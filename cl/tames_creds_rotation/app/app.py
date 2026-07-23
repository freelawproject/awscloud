"""AWS Secrets Manager rotation lambda for Texas CaseMail accounts.

Each rotation creates a new CaseMail account with an incremented numeric
suffix (CLTames_NN -> CLTames_NN+1).

Secret format: {"username": "CLTames_05", "email": "casemail_05@texas.recap.email", "password": "..."}
"""

import http.cookiejar
import json
import logging
import os
import re
import secrets
import string
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

import boto3

# sam build bundles sentry-sdk from requirements.txt; the LocalStack
# harness in test.py zips only this package, so run without it there.
try:
    import sentry_sdk
    from sentry_sdk.integrations.aws_lambda import AwsLambdaIntegration

    sentry_sdk.init(
        dsn=os.getenv("SENTRY_DSN", default=""),
        integrations=[
            AwsLambdaIntegration(),
        ],
        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        # We recommend adjusting this value in production,
        traces_sample_rate=1.0,
    )
except ImportError:
    pass

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CASEMAIL_BASE = "https://casemail.txcourts.gov"
CREATE_URL = f"{CASEMAIL_BASE}/MemberCreate.aspx"
LOGIN_URL = f"{CASEMAIL_BASE}/login.aspx"

# ASP.NET element-ID prefix shared by every field in both forms.
_PFX = "ctl00$ctl00$BaseContentPlaceHolder1$ContentPlaceHolder1$"

# The span that holds server-side error text on the create-account page.
_ERR_ID = (
    "ctl00_ctl00_BaseContentPlaceHolder1_ContentPlaceHolder1_lblErrorMessage"
)

# ---------------------------------------------------------------------------
# HTML parsers
# ---------------------------------------------------------------------------


class FormFieldParser(HTMLParser):
    """Extract hidden <input> fields from an ASP.NET form."""

    def __init__(self):
        super().__init__()
        self.fields: dict[str, str] = {}

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            a = dict(attrs)
            if a.get("type") == "hidden" and a.get("name"):
                self.fields[a["name"]] = a.get("value", "")


class ErrorSpanParser(HTMLParser):
    """Extract text content from a <span> with a specific id."""

    def __init__(self, target_id: str):
        super().__init__()
        self._target_id = target_id
        self._inside = False
        self.text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "span" and dict(attrs).get("id") == self._target_id:
            self._inside = True

    def handle_endtag(self, tag):
        if tag == "span" and self._inside:
            self._inside = False

    def handle_data(self, data):
        if self._inside:
            self.text += data


# ---------------------------------------------------------------------------
# HTTP helpers (urllib, no redirects)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Raise on redirects instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(newurl, code, msg, headers, fp)


_USER_AGENT = "Free Law Project"


def _headers_to_dict(headers) -> dict[str, str]:
    """Convert an HTTPMessage to a plain dict (case-preserved)."""
    return dict(headers.items())


class _Session:
    """Cookie-aware HTTP session (like httpx.Client).

    ASP.NET requires the session cookie from the initial GET to be
    present on the subsequent POST, or the __VIEWSTATE is rejected.
    """

    def __init__(self):
        cj = http.cookiejar.CookieJar()
        # Opener that keeps cookies but does NOT follow redirects.
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            _NoRedirect,
        )

    def get(self, url: str) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with self._opener.open(req) as resp:
                body: str = resp.read().decode("utf-8")
                return body
        except urllib.error.HTTPError as e:
            # Follow redirects on GET (ASP.NET may redirect on first visit).
            if e.code in (301, 302, 303, 307, 308):
                location = e.headers.get("Location", "")
                if location:
                    logger.info("GET %s redirected to %s", url, location)
                    return self.get(location)
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            logger.error(
                "GET %s failed: %s %s\n%s", url, e.code, e.reason, body[:500]
            )
            raise

    def post(self, url: str, data: dict) -> tuple[int, dict, str]:
        """POST form data. Does NOT follow redirects."""
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=encoded, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("User-Agent", _USER_AGENT)
        req.add_header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        req.add_header("Referer", url)
        req.add_header("Origin", "https://casemail.txcourts.gov")
        try:
            with self._opener.open(req) as resp:
                return (
                    resp.status,
                    _headers_to_dict(resp.headers),
                    resp.read().decode("utf-8"),
                )
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            return e.code, _headers_to_dict(e.headers), body


# ---------------------------------------------------------------------------
# Password generation
# ---------------------------------------------------------------------------


def generate_password(length: int = 16) -> str:
    """Generate a random password satisfying CaseMail rules.

    Rules:
      - At least 6 characters
      - At least 1 alphabetic character
      - At least 1 numeric character
      - Must not contain special characters
    """
    alphabet = string.ascii_letters + string.digits

    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw):
            return pw


# ---------------------------------------------------------------------------
# Credential incrementing
# ---------------------------------------------------------------------------


def next_credentials(current: dict) -> dict:
    """Derive the next username/email/password from the current secret.

    CLTames_05  -> CLTames_06
    casemail_05@... -> casemail_06@...
    """
    username = current["username"]
    m = re.search(r"(\d+)$", username)
    if not m:
        raise ValueError(
            f"Cannot extract numeric suffix from username: {username}"
        )
    nn = int(m.group(1))
    next_nn = f"{nn + 1:02d}"

    new_username = re.sub(r"\d+$", next_nn, username)
    new_email = re.sub(r"\d+(?=@)", next_nn, current["email"])

    return {
        "username": new_username,
        "email": new_email,
        "password": generate_password(),
    }


# ---------------------------------------------------------------------------
# CaseMail account creation
# ---------------------------------------------------------------------------


def create_account(username: str, email: str, password: str) -> None:
    """Create a new account on casemail.txcourts.gov.

    Raises RuntimeError on failure (unless the account already exists,
    which is treated as idempotent success for Lambda retries).
    """
    session = _Session()
    page_html = session.get(CREATE_URL)
    parser = FormFieldParser()
    parser.feed(page_html)

    data = dict(parser.fields)
    data.update(
        {
            f"{_PFX}txtUserName": username,
            f"{_PFX}txtEMail": email,
            f"{_PFX}txtPassword": password,
            f"{_PFX}txtPassword2": password,
            f"{_PFX}btnSubmit": "Create Account",
        }
    )

    status, headers, body = session.post(CREATE_URL, data)
    logger.info(
        "create_account POST response: status=%s, Location=%s, body_len=%d",
        status,
        headers.get("Location", "(none)"),
        len(body),
    )

    # Success → 302 redirect to login.aspx
    if status == 302 and "login.aspx" in headers.get("Location", ""):
        logger.info("Account %s created successfully.", username)
        return

    # Log a snippet of the response body for debugging.
    logger.info(
        "create_account response body (first 1000 chars):\n%s", body[:1000]
    )

    # Parse error span for details.
    err_parser = ErrorSpanParser(_ERR_ID)
    err_parser.feed(body)
    msg = err_parser.text.strip()

    # Treat "already exists" as success (idempotent retry).
    if msg and "already" in msg.lower():
        logger.info(
            "Account %s already exists (likely a retry). Treating as success.",
            username,
        )
        return

    raise RuntimeError(
        f"Account creation failed for {username}: "
        f"{msg or 'unknown error (no error span found)'}"
    )


# ---------------------------------------------------------------------------
# CaseMail login verification
# ---------------------------------------------------------------------------


def verify_login(username: str, password: str) -> None:
    """Verify that credentials work on casemail.txcourts.gov.

    Raises RuntimeError if login fails.
    """
    session = _Session()
    page_html = session.get(LOGIN_URL)
    parser = FormFieldParser()
    parser.feed(page_html)

    data = dict(parser.fields)
    data.update(
        {
            f"{_PFX}txtUserName": username,
            f"{_PFX}txtPassword": password,
            f"{_PFX}cmdLogon": "Logon",
        }
    )

    status, headers, body = session.post(LOGIN_URL, data)

    # Successful login → 302 redirect away from login.aspx
    if status == 302:
        logger.info("Login verified for %s (302 redirect).", username)
        return

    # If we got 200 but the login form is gone, that's also success.
    if status == 200 and "txtPassword" not in body:
        logger.info("Login verified for %s (200, no login form).", username)
        return

    raise RuntimeError(
        f"Login verification failed for {username}: "
        f"status={status}, still on login page"
    )


# ---------------------------------------------------------------------------
# Rotation steps
# ---------------------------------------------------------------------------


def create_secret(service_client, arn: str, token: str) -> None:
    """Step 1: Generate new credentials and store as AWSPENDING."""
    current = json.loads(
        service_client.get_secret_value(
            SecretId=arn, VersionStage="AWSCURRENT"
        )["SecretString"]
    )

    # Idempotent: skip if AWSPENDING already exists for this token.
    try:
        service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
        )
        logger.info(
            "createSecret: AWSPENDING already exists for %s, skipping.",
            token,
        )
        return
    except service_client.exceptions.ResourceNotFoundException:
        pass

    new_creds = next_credentials(current)
    logger.info(
        "createSecret: rotating %s -> %s",
        current["username"],
        new_creds["username"],
    )

    service_client.put_secret_value(
        SecretId=arn,
        ClientRequestToken=token,
        SecretString=json.dumps(new_creds),
        VersionStages=["AWSPENDING"],
    )


def set_secret(service_client, arn: str, token: str) -> None:
    """Step 2: Create the new account on casemail.txcourts.gov."""
    pending = json.loads(
        service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
        )["SecretString"]
    )
    logger.info(
        "setSecret: creating account %s (%s)",
        pending["username"],
        pending["email"],
    )
    create_account(pending["username"], pending["email"], pending["password"])
    logger.info(
        "setSecret: account %s created successfully.", pending["username"]
    )


def test_secret(service_client, arn: str, token: str) -> None:
    """Step 3: Verify the new account can log in."""
    pending = json.loads(
        service_client.get_secret_value(
            SecretId=arn, VersionId=token, VersionStage="AWSPENDING"
        )["SecretString"]
    )
    logger.info("testSecret: verifying login for %s", pending["username"])
    verify_login(pending["username"], pending["password"])
    logger.info("testSecret: login verified for %s.", pending["username"])


def finish_secret(service_client, arn: str, token: str) -> None:
    """Step 4: Promote AWSPENDING to AWSCURRENT."""
    metadata = service_client.describe_secret(SecretId=arn)

    current_version = None
    for version_id, stages in metadata["VersionIdsToStages"].items():
        if "AWSCURRENT" in stages:
            if version_id == token:
                logger.info("finishSecret: %s already AWSCURRENT.", token)
                return
            current_version = version_id
            break

    service_client.update_secret_version_stage(
        SecretId=arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logger.info(
        "finishSecret: promoted %s to AWSCURRENT (was %s).",
        token,
        current_version,
    )


# ---------------------------------------------------------------------------
# Lambda entry point
# ---------------------------------------------------------------------------


def handler(event, context):
    """Secrets Manager rotation handler."""
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    service_client = boto3.client(
        "secretsmanager",
        endpoint_url=os.environ.get("SECRETS_MANAGER_ENDPOINT"),
    )

    # Validate the secret is rotation-enabled and the token is staged.
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled"):
        raise ValueError(f"Secret {arn} does not have rotation enabled.")

    versions = metadata.get("VersionIdsToStages", {})
    if token not in versions:
        raise ValueError(
            f"Secret version {token} has no stage for secret {arn}."
        )
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT.", token)
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError(
            f"Secret version {token} not set as AWSPENDING for secret {arn}."
        )

    steps = {
        "createSecret": create_secret,
        "setSecret": set_secret,
        "testSecret": test_secret,
        "finishSecret": finish_secret,
    }

    if step not in steps:
        raise ValueError(f"Invalid step parameter: {step}")

    logger.info("Running step %s for secret %s (token %s)", step, arn, token)
    try:
        steps[step](service_client, arn, token)
    except Exception:
        logger.exception("Step %s failed for secret %s", step, arn)
        raise
