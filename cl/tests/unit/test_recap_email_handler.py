# pylint: disable=redefined-outer-name,unused-import
import json
import os
from unittest import mock

import pytest
import requests  # noqa: F401
import requests_mock  # noqa: F401
from recap_email.app import app  # pylint: disable=import-error


@pytest.fixture()
def spam_failure_ses_event():
    with open("./events/ses-spam-failure.json") as file:
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
    with open("./events/ses-virus-failure.json") as file:
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
    with open("./events/ses-spf-failure.json") as file:
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
    with open("./events/ses-dkim-failure.json") as file:
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
    with open("./events/ses-dmarc-failure.json") as file:
        data = json.load(file)
    return data


def test_dmarc_failure(dmarc_failure_ses_event):
    response = app.handler(dmarc_failure_ses_event, "")
    data = json.loads(response["body"])

    assert response["statusCode"] == 424
    assert "dmarc_verdict" in data
    assert data["dmarc_verdict"]["status"] == "FAILED"


@pytest.fixture()
def ses_event():
    with open("./events/ses.json") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_one():
    with open("./events/pacer-1.json") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_two():
    with open("./events/pacer-2.json") as file:
        data = json.load(file)
    return data


@pytest.fixture()
def pacer_event_three():
    with open("./events/pacer-3.json") as file:
        data = json.load(file)
    return data


@mock.patch.dict(
    os.environ,
    {
        "RECAP_EMAIL_ENDPOINT": "http://host.docker.internal:8000/api/rest/v3/recap-email/"  # noqa: E501, pylint: disable=line-too-long
    },
)
def test_success(
    ses_event,
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
        pacer_event_one,
        pacer_event_two,
        pacer_event_three,
    ]:
        response = app.handler(event, "")
        data = json.loads(response["body"])

        assert response["statusCode"] == 200
        assert "mail" in data
        assert "receipt" in data
