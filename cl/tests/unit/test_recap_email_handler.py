# pylint: disable=redefined-outer-name,unused-import
import json
import os
import re
from unittest import mock

import pytest
import requests  # noqa: F401
import requests_mock  # noqa: F401
from recap_email.app import app  # pylint: disable=import-error
from recap_email.app.pacer import (  # pylint: disable=import-error
    pacer_to_cl_ids,
)

from cl.tests.unit.utils import MockResponse


@pytest.fixture()
def spam_failure_ses_event():
    with open("./events/ses-spam-failure.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


def test_spam_failure(spam_failure_ses_event):
    response = app.handler(spam_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "spam_verdict" in data
    assert data["spam_verdict"]["status"] == "FAILED"


@pytest.fixture()
def virus_failure_ses_event():
    with open("./events/ses-virus-failure.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


def test_virus_failure(virus_failure_ses_event):
    response = app.handler(virus_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "virus_verdict" in data
    assert data["virus_verdict"]["status"] == "FAILED"


@pytest.fixture()
def spf_failure_ses_event():
    with open("./events/ses-spf-failure.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


def test_spf_failure(spf_failure_ses_event):
    response = app.handler(spf_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "spf_verdict" in data
    assert data["spf_verdict"]["status"] == "FAILED"


@pytest.fixture()
def dkim_failure_ses_event():
    with open("./events/ses-dkim-failure.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


def test_dkim_failure(dkim_failure_ses_event):
    response = app.handler(dkim_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "dkim_verdict" in data
    assert data["dkim_verdict"]["status"] == "FAILED"


@pytest.fixture()
def dmarc_failure_ses_event():
    with open("./events/ses-dmarc-failure.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


def test_dmarc_failure(dmarc_failure_ses_event):
    response = app.handler(dmarc_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "dmarc_verdict" in data
    assert data["dmarc_verdict"]["status"] == "FAILED"


def test_multiple_domains_failed():
    no_valid_emails = [
        "prvs=144d0cba7=sender@example.com",
        "prvs=144d0cba7=sender@.test.example.com",
        "prvs=144d0cba7=sender@cacd.uscourts.gov.uk",
        "prvs=144d0cba7=sender@uscourts.gov.uk",
    ]

    for email in no_valid_emails:
        assert app.check_valid_domain(email) == 0


def test_multiple_domains_success():
    valid_emails = [
        "cacd_ecfmail@uscourts.gov",
        "cacd_ecfmail@cacd.test.uscourts.gov",
        "cacd_ecfmail@cacd.uscourts.gov",
        "ACMS@ca9.fedcourts.us",
        "ACMS@ca2.fedcourts.us",
    ]

    for email in valid_emails:
        assert app.check_valid_domain(email) == 1


def test_get_cl_court_id_using_mapping():
    for pacer_id, expected_cl in pacer_to_cl_ids.items():
        email = {
            "common_headers": {"from": [f"ecfnotices@{pacer_id}.uscourts.gov"]}
        }
        result = app.get_cl_court_id(email)
        assert result == expected_cl, (
            f"For PACER id '{pacer_id}', expected CL id '{expected_cl}' but "
            f"got '{result}'."
        )


@pytest.fixture()
def valid_domain_failure_ses_event():
    with open(
        "./events/ses-valid-domain-failure.json", encoding="utf-8"
    ) as file:
        data = json.load(file)
    return data


def test_valid_domain_failed(valid_domain_failure_ses_event):
    response = app.handler(valid_domain_failure_ses_event, "")

    assert response["statusCode"] == 424
    assert response["valid_domain"]["status"] == "FAILED"


@pytest.fixture()
def invalid_return_path_ses_event():
    with open(
        "./events/ses-invalid-return-path.json", encoding="utf-8"
    ) as file:
        data = json.load(file)
    return data


def test_invalid_return_path(invalid_return_path_ses_event):
    response = app.handler(invalid_return_path_ses_event, "")

    assert response["statusCode"] == 424
    assert response["valid_domain"]["status"] == "FAILED"


@pytest.fixture()
def ses_event():
    with open("./events/ses.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def ses_gray_event():
    with open("./events/ses-dkim-gray.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_one():
    with open("./events/pacer-1.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_two():
    with open("./events/pacer-2.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_three():
    with open("./events/pacer-3.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def scotus_event():
    with open("./events/scotus-1.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def texas_event():
    with open("./events/texas-1.json", encoding="utf-8") as file:
        data = json.load(file)
    return data


@mock.patch.dict(
    os.environ,
    {
        "RECAP_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v3/recap-email/",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_success(  # pylint: disable=too-many-arguments
    ses_event,
    ses_gray_event,
    pacer_event_one,
    pacer_event_two,
    pacer_event_three,
    requests_mock,  # noqa: F811
):
    requests_mock.post(
        "http://host.docker.internal:8000/api/rest/v3/recap-email/",
        json=json.dumps({"mail": {}, "receipt": {}}),
    )

    for event in [
        ses_event,
        ses_gray_event,
        pacer_event_one,
        pacer_event_two,
        pacer_event_three,
    ]:
        response = app.handler(event, "")
        data = json.loads(response["body"])

        assert response["statusCode"] == 200
        assert "mail" in data
        assert "receipt" in data


@mock.patch.dict(
    os.environ,
    {
        "RECAP_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v3/recap-email/",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_request_court_field_actual_value(
    pacer_event_two,
    requests_mock,  # noqa: F811
):
    """Confirm that the court_id in the request uses the right value
    from map_pacer_to_cl_id"""
    requests_mock.post(
        "http://host.docker.internal:8000/api/rest/v3/recap-email/",
        json={"mail": {}, "receipt": {}},
    )

    response = app.handler(pacer_event_two, "")
    assert response["statusCode"] == 200

    # Retrieve the request that made by send_to_court_listener
    request = requests_mock.request_history[0]
    body = json.loads(request.body)
    assert body.get("court") == "mowd", (
        f"Expected 'mowd', but got '{body.get('court')}'"
    )


@mock.patch.dict(
    os.environ,
    {
        "SCOTUS_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v4/scrapers/scotus-email/",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_scotus_email_request(
    scotus_event,
    requests_mock,  # noqa: F811
):
    """Confirm a scotus email is properly routed to the SCOTUS_EMAIL_ENDPOINT"""
    requests_mock.register_uri(
        "POST",
        re.compile(r".*"),
        json={"mail": {}, "receipt": {}},
        status_code=200,
    )

    response = app.handler(scotus_event, "")
    assert response["statusCode"] == 200

    # Retrieve the request that made by send_to_court_listener
    request = requests_mock.request_history[0]
    assert (
        request.url
        == "http://host.docker.internal:8000/api/rest/v4/scrapers/scotus-email/"
    )

    body = json.loads(request.body)
    assert body.get("court") == "scotus", (
        f"Expected 'scotus', but got '{body.get('court')}'"
    )


@mock.patch.dict(
    os.environ,
    {
        "TEXAS_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v4/email/state/tx/tames/alert",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_texas_email_request(
    texas_event,
    requests_mock,  # noqa: F811
):
    """Confirm a Texas email is properly routed to the TEXAS_EMAIL_ENDPOINT"""
    requests_mock.register_uri(
        "POST",
        re.compile(r".*"),
        json={"mail": {}, "receipt": {}},
        status_code=200,
    )

    response = app.handler(texas_event, "")
    assert response["statusCode"] == 200

    # Retrieve the request that made by send_to_court_listener
    request = requests_mock.request_history[0]
    assert (
        request.url
        == "http://host.docker.internal:8000/api/rest/v4/email/state/tx/tames/alert"
    )

    body = json.loads(request.body)
    assert body.get("court") == "txctapp1", (
        f"Expected 'txctapp1', but got '{body.get('court')}'"
    )


@mock.patch.dict(
    os.environ,
    {
        "RECAP_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v3/recap-email/",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_report_request_for_invalid_court(
    pacer_event_one,
    requests_mock,  # noqa: F811
):
    """Confirm that if an invalid court_id is sent to CL, an error event is
    sent to Sentry."""

    mock_response = MockResponse(
        400, {"court": ['Invalid pk "whla" - object does not exist.']}
    )
    with (
        mock.patch(
            "recap_email.app.app.requests.post", return_value=mock_response
        ),
        mock.patch(
            "recap_email.app.app.sentry_sdk.capture_message"
        ) as mock_sentry_capture,
    ):
        requests_mock.post(
            "http://host.docker.internal:8000/api/rest/v3/recap-email/",
            json={"mail": {}, "receipt": {}},
        )
        app.handler(pacer_event_one, "")
    # The expected error message should be sent to Sentry.
    expected_error = (
        "Invalid court pk: whla - "
        "message_id: 171jjm4scn8vgcn5vrcv4su427obcred7bekus81"
    )
    mock_sentry_capture.assert_called_with(
        expected_error, level="error", fingerprint=["invalid-court-pk"]
    )


@mock.patch.dict(
    os.environ,
    {
        "RECAP_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v3/recap-email/",  # noqa: E501 pylint: disable=line-too-long
        "AUTH_TOKEN": "************************",
    },
)
def test_ignore_messages_from_invalid_court_ids(
    pacer_event_one,
    requests_mock,  # noqa: F811
):
    """Confirm that if an invalid court_id in sub_domains_to_ignore is sent, a
    validation_domain_failure is sent."""

    with mock.patch(
        "recap_email.app.app.get_cl_court_id", return_value="updates"
    ):
        requests_mock.post(
            "http://host.docker.internal:8000/api/rest/v3/recap-email/",
            json={"mail": {}, "receipt": {}},
        )
        response = app.handler(pacer_event_one, "")
        assert response["statusCode"] == 424
        assert response["valid_domain"]["status"] == "FAILED"
