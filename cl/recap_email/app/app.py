from email.utils import parseaddr
import json
import os
import re
import sys

import requests
import sentry_sdk
from humps import decamelize
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import HTTPError, Timeout
from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

from .pacer import map_pacer_to_cl_id, sub_domains_to_ignore
from .utils import retry  # pylint: disable=import-error

# NOTE - This is necessary for the relative imports.
# See https://gist.github.com/gene1wood/06a64ba80cf3fe886053f0ca6d375bc0
sys.path.append(os.path.join(os.path.dirname(__file__)))

SENTRY_DSN = os.getenv("SENTRY_DSN", default="")

sentry_sdk.init(
    dsn=SENTRY_DSN,
    integrations=[
        AwsLambdaIntegration(),
    ],
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production,
    traces_sample_rate=1.0,
)


def get_ses_email_headers(email, header_name):
    return [header["value"] for header in email["headers"] if header["name"] == header_name]


def get_ses_record_from_event(event):
    for record in event.get("Records", []):
        if record.get("eventSource") == "aws:ses":
            return record.get("ses")
    return None


def get_spam_verdict(receipt):
    return receipt["spam_verdict"]["status"]


def get_virus_verdict(receipt):
    return receipt["virus_verdict"]["status"]


def get_spf_verdict(receipt):
    return receipt["spf_verdict"]["status"]


def get_dkim_verdict(receipt):
    return receipt["dkim_verdict"]["status"]


def get_dmarc_verdict(receipt):
    return receipt["dmarc_verdict"]["status"]


def get_combined_log_message(email):
    subject = None
    for header in email["headers"]:
        if header["name"] == "Subject":
            subject = header["value"]

    return (
        f"Email ID {email['message_id']} with {subject}, "
        f"from {email['source']} to {email['destination']}"
    )


def check_valid_domain(email_address):
    domain = parseaddr(email_address)[1].split("@")

    try:
        domain = domain[1]
    except IndexError:
        # Lack of @, invalid email address
        return False

    tld_domain = domain.split(".")

    valid_domains = [
        ["uscourts", "gov"],
        ["fedcourts", "us"],  # ACMS
        ["sc-us", "gov"], # SCOTUS
    ]
    return tld_domain[-2:] in valid_domains


def get_valid_domain_verdict(email):
    # Check all Return-Path headers comes from uscourts.gov
    for email_address in get_ses_email_headers(email, "Return-Path"):
        if not check_valid_domain(email_address):
            return "FAILED"
    return "PASS"


def validation_failure(email, receipt, verdict):
    print(
        f"{get_combined_log_message(email)} failed with spam verdict {verdict}"
    )
    return {
        "statusCode": 424,
        "body": json.dumps(receipt),
    }


def validation_domain_failure(email, receipt, verdict):
    print(
        f"{get_combined_log_message(email)}"
        f" failed with valid domain verdict {verdict}"
    )
    return {
        "statusCode": 424,
        "valid_domain": {"status": "FAILED"},
        "body": json.dumps(receipt),
    }


def get_cl_court_id(email):
    """
    Pull out and normalize the court ID from the email From header

    Take this:
      ecfnotices@areb.uscourts.gov
    And return:
      areb

    :param email: The email dict from AWS
    :return the CL court ID (not the PACER ID)
    """
    from_addr = email["common_headers"]["from"][0]
    # Get just the sub_domain from, "harold@areb.uscourts.gov"
    sub_domain = from_addr.split("@")[1].split(".")[0]
    return map_pacer_to_cl_id(sub_domain)


def log_invalid_court_error(response, message_id):
    """Checks if the response indicates an invalid court pk then send a report
    to Sentry.
    """
    if response.status_code != 400:
        return

    for msg in response.json().get("court", []):
        if "Invalid pk" not in msg:
            continue
        match = re.search(r'Invalid pk "([^"]+)"', msg)
        if not match:
            continue
        court_id = match.group(1)
        error_message = (
            f"Invalid court pk: {court_id} - message_id: {message_id}"
        )
        sentry_sdk.capture_message(
            error_message, level="error", fingerprint=["invalid-court-pk"]
        )
        break


def get_cl_endpoint(email):
    RECAP_EMAIL_ENDPOINT = os.getenv("RECAP_EMAIL_ENDPOINT")
    SCOTUS_EMAIL_ENDPOINT = os.getenv("SCOTUS_EMAIL_ENDPOINT")
    CL_ENDPOINT_MAP = {
        "sc-us.gov": SCOTUS_EMAIL_ENDPOINT,
        "fedcourts.us": RECAP_EMAIL_ENDPOINT,
        "uscourts.gov": RECAP_EMAIL_ENDPOINT,
    }

    for email_address in get_ses_email_headers(email, "Return-Path"):
        domain = ".".join(parseaddr(email_address)[1].split("@")[1].split(".")[-2:])

        if domain in CL_ENDPOINT_MAP:
            return CL_ENDPOINT_MAP[domain]
    return RECAP_EMAIL_ENDPOINT


@retry(
    (RequestsConnectionError, HTTPError, Timeout),
    tries=5,
    delay=10,
    backoff=3,
)
def send_to_court_listener(email, receipt):
    print(f"{get_combined_log_message(email)} sending to Court Listener API.")
    endpoint = get_cl_endpoint(email)

    # DEV DOMAIN: http://host.docker.internal:8000
    court_listener_response = requests.post(
        endpoint,
        json.dumps(
            {
                "mail": email,
                "receipt": receipt,
                "court": get_cl_court_id(email),
            }
        ),
        timeout=5,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Token {os.getenv('AUTH_TOKEN')}",
        },
    )

    if court_listener_response.status_code in [502, 503, 504]:
        # Raise an HTTPError for Bad Gateway, Service Unavailable or
        # Gateway Timeout status codes.
        court_listener_response.raise_for_status()

    message_id = email.get("message_id")
    log_invalid_court_error(court_listener_response, message_id)

    print(
        f"Got {court_listener_response.status_code=} and content "
        f"{court_listener_response.json()=}"
    )

    return {
        "statusCode": 200,
        "body": court_listener_response.json(),
    }


def handler(event, context):  # pylint: disable=unused-argument
    ses_record = get_ses_record_from_event(event)
    if ses_record is None:
        body = {"message": "PACER email receipt requires aws:ses eventSource."}
        return {
            "statusCode": 415,
            "body": json.dumps(body),
        }

    email = decamelize(ses_record.get("mail", {}))
    receipt = decamelize(ses_record.get("receipt", {}))

    tests = (
        # NOTE - SPAM verdict failed with some test emails.
        get_spam_verdict,
        get_virus_verdict,
    )
    for test in tests:
        verdict = test(receipt)
        if verdict != "PASS":
            return validation_failure(email, receipt, verdict)

    gray_or_pass_tests = (
        get_spf_verdict,
        get_dmarc_verdict,
        get_dkim_verdict,
    )
    for test in gray_or_pass_tests:
        verdict = test(receipt)
        if verdict not in {"PASS", "GRAY"}:
            return validation_failure(email, receipt, verdict)

    domain_verdict = get_valid_domain_verdict(email)
    court_id = get_cl_court_id(email)
    # Check domain is valid (comes from uscourts.gov)
    # Ignore messages that are not from courts, such as updates.uscourts.gov
    if domain_verdict != "PASS" or court_id in sub_domains_to_ignore:
        return validation_domain_failure(email, receipt, domain_verdict)
    return send_to_court_listener(email, receipt)
