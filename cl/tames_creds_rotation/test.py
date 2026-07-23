#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "boto3",
# ]
# ///
"""Test TAMES secret rotation against LocalStack.

Deploys the rotation lambda to LocalStack and triggers rotation
via the Secrets Manager API, just like production.

THIS WILL CREATE A NEW ACCOUNT ON TAMES!

Usage:
    docker compose up -d
    uv run test.py
"""

import io
import json
import time
import zipfile

import boto3

LOCALSTACK_URL = "http://localhost:4566"
SECRET_NAME = "TAMES_USER"
FUNCTION_NAME = "tames-rotation"
REGION = "us-west-2"

# These are some example old creds. They are used as a template for the next creds
INITIAL_SECRET = {
    "username": "CLTamesExample_01",
    "email": "casemailexample_01@texas.recap.email",
    "password": "CHANGEME1",
}


def _make_zip() -> bytes:
    """Zip the app package for deployment to LocalStack.

    We're just using standard library and boto3 which is automatically injected
    to keep this slim.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write("app/__init__.py")
        zf.write("app/app.py")
    return buf.getvalue()


def main():
    session = boto3.Session(
        region_name=REGION,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    sm = session.client("secretsmanager", endpoint_url=LOCALSTACK_URL)
    lam = session.client("lambda", endpoint_url=LOCALSTACK_URL)
    iam = session.client("iam", endpoint_url=LOCALSTACK_URL)

    # 1. Create a Lambda execution role (LocalStack doesn't enforce IAM,
    #    but the API requires a role ARN).
    role_name = "tames-rotation-role"
    try:
        role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        role_arn = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
        )["Role"]["Arn"]
    print(f"IAM role: {role_arn}")

    # 2. Deploy the Lambda function.
    zip_bytes = _make_zip()
    try:
        lam.delete_function(FunctionName=FUNCTION_NAME)
        print(f"Deleted existing Lambda {FUNCTION_NAME}")
    except lam.exceptions.ResourceNotFoundException:
        pass

    fn = lam.create_function(
        FunctionName=FUNCTION_NAME,
        Runtime="python3.11",
        Role=role_arn,
        Handler="app.app.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=60,
        Environment={
            "Variables": {
                # Lambda container reaches LocalStack via Docker host networking.
                "SECRETS_MANAGER_ENDPOINT": "http://host.docker.internal:4566",
            }
        },
    )
    fn_arn = fn["FunctionArn"]
    print(f"Created Lambda: {fn_arn}")

    # Wait for the Lambda to transition from Pending to Active.
    print("Waiting for Lambda to become Active...")
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=FUNCTION_NAME)
    print("Lambda is Active.")

    # 3. Create (or recreate) the initial secret.
    try:
        sm.delete_secret(SecretId=SECRET_NAME, ForceDeleteWithoutRecovery=True)
        print(f"Deleted existing secret {SECRET_NAME}")
    except sm.exceptions.ResourceNotFoundException:
        pass

    secret = sm.create_secret(
        Name=SECRET_NAME,
        SecretString=json.dumps(INITIAL_SECRET),
    )
    secret_arn = secret["ARN"]
    print(f"Created secret: {secret_arn}")
    print(f"  Initial value: {json.dumps(INITIAL_SECRET)}")

    # 4. Trigger rotation via the Secrets Manager API.
    print("\nTriggering rotation...")
    sm.rotate_secret(
        SecretId=SECRET_NAME,
        RotationLambdaARN=fn_arn,
        RotationRules={"AutomaticallyAfterDays": 30},
    )

    # 5. Wait for rotation to complete, then verify the secret.
    print("Waiting for rotation to complete...")
    for attempt in range(60):
        time.sleep(2)
        current = json.loads(
            sm.get_secret_value(
                SecretId=SECRET_NAME, VersionStage="AWSCURRENT"
            )["SecretString"]
        )
        if current["username"] != INITIAL_SECRET["username"]:
            break
        print(f"  Still rotating... (attempt {attempt + 1}/60)")
    else:
        print("ERROR: Rotation did not complete within 120 seconds.")
        print(f"  AWSCURRENT still: {json.dumps(current, indent=2)}")
        return

    print("\nRotation complete!")
    print(f"  New AWSCURRENT: {json.dumps(current, indent=2)}")

    assert current["username"] == "CLTames_02", (
        f"Expected CLTames_02, got {current['username']}"
    )
    assert current["email"] == "casemail_02@texas.recap.email", (
        f"Expected casemail_02@..., got {current['email']}"
    )
    assert len(current["password"]) >= 6, "Password too short"
    assert current["password"] != INITIAL_SECRET["password"], (
        "Password didn't change"
    )

    print("All assertions passed.")


if __name__ == "__main__":
    main()
