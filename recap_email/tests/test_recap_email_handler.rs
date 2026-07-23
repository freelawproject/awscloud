use aws_lambda_events::ses::{SimpleEmailCommonHeaders, SimpleEmailEvent, SimpleEmailHeader, SimpleEmailMessage, SimpleEmailReceipt, SimpleEmailService};
use chrono::{DateTime, Local, Utc};
use lambda_runtime::{Context, LambdaEvent};
use recap_email::app;
use recap_email::app::{destination_matches_subscription, ValidationFailure};
use recap_email::pacer::{
    get_ecf_host_court,
    PACER_TO_CL_IDS,
};
use serde_json::{
    json,
    Value,
};
use std::future::Future;
use wiremock::matchers::method;
use wiremock::{
    Mock,
    MockServer,
    ResponseTemplate,
};

fn load_event(name: &str) -> LambdaEvent<SimpleEmailEvent> {
    let path = format!("{}/../cl/events/{}", env!("CARGO_MANIFEST_DIR"), name);
    LambdaEvent::new(serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap(), Context::default())
}

async fn with_env<T>(vars: &[(&str, &str)], f: impl Future<Output = T>) -> T {
    let mut all_vars: Vec<(&str, Option<&str>)> = [
        "RECAP_EMAIL_ENDPOINT",
        "SCOTUS_EMAIL_ENDPOINT",
        "TEXAS_EMAIL_ENDPOINT",
        "AUTH_TOKEN",
    ]
    .iter()
    .map(|key| (*key, None))
    .collect();
    for (key, value) in vars {
        if let Some(entry) = all_vars.iter_mut().find(|(k, _)| k == key) {
            entry.1 = Some(*value);
        }
    }
    temp_env::async_with_vars(all_vars, f).await
}

fn spam_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-spam-failure.json")
}

#[tokio::test]
async fn test_spam_failure() {
    let event = spam_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();
    let data = &response.body;

    assert_eq!(response.status_code, 424);
    assert!(data.get("spamVerdict").is_some());
    assert_eq!(data["spamVerdict"]["status"], "FAILED");
}

fn virus_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-virus-failure.json")
}

#[tokio::test]
async fn test_virus_failure() {
    let event = virus_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();
    let data = &response.body;

    assert_eq!(response.status_code, 424);
    assert!(data.get("virusVerdict").is_some());
    assert_eq!(data["virusVerdict"]["status"], "FAILED");
}

fn spf_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-spf-failure.json")
}

#[tokio::test]
async fn test_spf_failure() {
    let event = spf_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();
    let data = &response.body;

    assert_eq!(response.status_code, 424);
    assert!(data.get("spfVerdict").is_some());
    assert_eq!(data["spfVerdict"]["status"], "FAILED");
}

fn dkim_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-dkim-failure.json")
}

#[tokio::test]
async fn test_dkim_failure() {
    let event = dkim_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();
    let data = &response.body;

    assert_eq!(response.status_code, 424);
    assert!(data.get("dkimVerdict").is_some());
    assert_eq!(data["dkimVerdict"]["status"], "FAILED");
}

fn dmarc_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-dmarc-failure.json")
}

#[tokio::test]
async fn test_dmarc_failure() {
    let event = dmarc_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();
    let data = &response.body;

    assert_eq!(response.status_code, 424);
    assert!(data.get("dmarcVerdict").is_some());
    assert_eq!(data["dmarcVerdict"]["status"], "FAILED");
}

#[tokio::test]
async fn test_multiple_domains_failed() {
    let no_valid_emails = [
        "prvs=144d0cba7=sender@example.com",
        "prvs=144d0cba7=sender@.test.example.com",
        "prvs=144d0cba7=sender@cacd.uscourts.gov.uk",
        "prvs=144d0cba7=sender@uscourts.gov.uk",
    ];

    for email in no_valid_emails {
        assert!(!app::check_valid_domain(email));
    }
}

#[tokio::test]
async fn test_multiple_domains_success() {
    let event = spam_failure_ses_event();
    with_env(&[], async {
        app::handler(event).await.unwrap();
    })
    .await;

    let valid_emails = [
        "cacd_ecfmail@uscourts.gov",
        "cacd_ecfmail@cacd.test.uscourts.gov",
        "cacd_ecfmail@cacd.uscourts.gov",
        "ACMS@ca9.fedcourts.us",
        "ACMS@ca2.fedcourts.us",
    ];

    for email in valid_emails {
        assert!(app::check_valid_domain(email));
    }
}

#[test]
fn test_get_cl_court_id_using_mapping() {
    for (pacer_id, expected_cl) in PACER_TO_CL_IDS {
        let email = make_court_email(
            &format!("ecfnotices@{pacer_id}.uscourts.gov"), &vec![][..],
        );
        let result = app::map_email_to_cl_id(&email).unwrap();
        assert_eq!(
            result, expected_cl,
            "For PACER id '{pacer_id}', expected CL id '{expected_cl}' but got '{result}'."
        );
    }
}

/// Build a minimal email object with Received headers listed from the
/// latest relay down to the originating server, as in a real message.
fn make_court_email(from_addr: &str, received_hosts: &[&str]) -> SimpleEmailMessage {
    let now = Local::now();
    SimpleEmailMessage::builder()
        .message_id("test-ecf-host-message-id".to_string())
        .common_headers(SimpleEmailCommonHeaders::builder()
            .from(vec![from_addr.to_string()])
            .to(vec![])
            .build()
        )
        .headers(received_hosts
            .iter()
            .map(|host| {
                SimpleEmailHeader::builder()
                    .name("Received".to_string())
                    .value(format!(
                        "from unknown (HELO {host}) ([156.119.56.176]) by \
                         icmecf202.gtwy.uscourts.gov with ESMTP; 28 Jun 2021 18:51:10 +0000"
                    ))
                    .build()
            })
            .collect()
        )
        .timestamp(DateTime::from_naive_utc_and_offset(now.naive_utc(), Utc))
        .destination(vec![])
        .headers_truncated(false)
        .build()
}

/// A txsb NEF arrives from the shared txs.uscourts.gov domain; the ECF
/// database host in the Received headers must reassign it to txsb.
#[test]
fn test_ecf_host_overrides_shared_domain_bankruptcy() {
    let email = make_court_email(
        "BKECF_LiveDB@txs.uscourts.gov",
        &["relay1.uscourts.gov", "txsbdb.txsb.gtwy.dcn"],
    );
    assert_eq!(app::map_email_to_cl_id(&email).unwrap(), "txsb");
}

/// A txsd NEF from the shared txs.uscourts.gov domain must still map to
/// txsd (the majority case for the shared domain).
#[test]
fn test_ecf_host_confirms_shared_domain_district() {
    let email = make_court_email(
        "ecf_txsd@txs.uscourts.gov",
        &["relay1.uscourts.gov", "txsddb.txsd.gtwy.dcn"],
    );
    assert_eq!(app::map_email_to_cl_id(&email).unwrap(), "txsd");
}

/// When the From domain and the ECF host agree, behavior is unchanged.
#[test]
fn test_ecf_host_agreement_keeps_court() {
    let email = make_court_email(
        "cacd_ecfmail@cacd.uscourts.gov",
        &["relay1.uscourts.gov", "cacddb.cacd.gtwy.dcn"],
    );
    assert_eq!(app::map_email_to_cl_id(&email).unwrap(), "cacd");
}

/// Courts like gas or mow use a From subdomain that differs from their
/// ECF host court (gasddb.gasd.gtwy.dcn), and courts like neb use an ECF
/// host that differs from their CL id (nebdb.neb.gtwy.dcn vs nebraskab),
/// but both sides resolve to the same CL court via pacer_to_cl_ids, so no
/// mismatch may be reported to Sentry.
#[test]
fn test_ecf_host_agreement_via_pacer_mapping_is_not_a_mismatch() {
    let emails = [
        (
            "efile_support@gas.uscourts.gov",
            "gasddb.gasd.gtwy.dcn",
            "gasd",
        ),
        (
            "ecfMOW.notification@mow.uscourts.gov",
            "mowddb.mowd.gtwy.dcn",
            "mowd",
        ),
        (
            "neb_bkecf@neb.uscourts.gov",
            "nebdb.neb.gtwy.dcn",
            "nebraskab",
        ),
    ];
    for (from_addr, ecf_host, expected_court) in emails {
        let email = make_court_email(from_addr, &["relay1.uscourts.gov", ecf_host]);
        let events = sentry::test::with_captured_events(|| {
            assert_eq!(app::map_email_to_cl_id(&email).unwrap(), expected_court);
        });
        assert!(events.is_empty());
    }
}

/// A disagreement on a domain outside the shared-domain set keeps the
/// From-derived court and reports the mismatch to Sentry.
#[test]
fn test_ecf_host_mismatch_on_non_shared_domain_logs_error() {
    let email = make_court_email(
        "cacd_ecfmail@cacd.uscourts.gov",
        &["relay1.uscourts.gov", "nysbdb.nysb.gtwy.dcn"],
    );
    let events = sentry::test::with_captured_events(|| {
        assert_eq!(app::map_email_to_cl_id(&email).unwrap(), "cacd");
    });
    let expected_error = "ECF host court mismatch: From-derived court 'cacd' vs ECF host court \
                          'nysb' - message_id: test-ecf-host-message-id";
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message.as_deref(), Some(expected_error));
    assert_eq!(events[0].level, sentry::Level::Error);
    assert_eq!(
        events[0]
            .fingerprint
            .iter()
            .map(|f| f.as_ref())
            .collect::<Vec<_>>(),
        vec!["ecf-host-court-mismatch"]
    );
}

/// Generic court mail relays under gtwy.dcn are not ECF database hosts
/// and must not match, so behavior stays unchanged without an ECF host.
#[test]
fn test_ecf_host_ignores_generic_gtwy_relays() {
    let email = make_court_email(
        "BKECF_LiveDB@txs.uscourts.gov",
        &["relay1.uscourts.gov", "smtp2-i.asbn.gtwy.dcn"],
    );
    assert!(get_ecf_host_court(&email).is_none());
    assert_eq!(app::map_email_to_cl_id(&email).unwrap(), "txsd");
}

/// The last match across the Received headers (closest to the
/// originating server) wins over hosts stamped by later relays.
#[test]
fn test_ecf_host_uses_earliest_received_header() {
    let email = make_court_email(
        "BKECF_LiveDB@txs.uscourts.gov",
        &["otherdb.other.gtwy.dcn", "txsbdb.txsb.gtwy.dcn"],
    );
    assert_eq!(get_ecf_host_court(&email).as_deref(), Some("txsb"));
}

fn valid_domain_failure_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-valid-domain-failure.json")
}

#[tokio::test]
async fn test_valid_domain_failed() {
    let event = valid_domain_failure_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();

    assert_eq!(response.status_code, 424);
    assert_eq!(response.failure, Err(ValidationFailure::Domain));
}

fn invalid_return_path_ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-invalid-return-path.json")
}

#[tokio::test]
async fn test_invalid_return_path() {
    let event = invalid_return_path_ses_event();
    let response = with_env(&[], app::handler(event)).await.unwrap();

    assert_eq!(response.status_code, 424);
    assert_eq!(response.failure, Err(ValidationFailure::Domain));
}

fn ses_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses.json")
}

fn ses_gray_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("ses-dkim-gray.json")
}

fn pacer_event_one() -> LambdaEvent<SimpleEmailEvent> {
    load_event("pacer-1.json")
}

fn pacer_event_two() -> LambdaEvent<SimpleEmailEvent> {
    load_event("pacer-2.json")
}

fn pacer_event_three() -> LambdaEvent<SimpleEmailEvent> {
    load_event("pacer-3.json")
}

fn scotus_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("scotus-1.json")
}

fn texas_event() -> LambdaEvent<SimpleEmailEvent> {
    load_event("texas-1.json")
}

#[tokio::test(flavor = "multi_thread")]
async fn test_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(SimpleEmailService::builder()
                    .mail(make_court_email("aaaa@bbb.com", &[][..]))
                    .receipt(SimpleEmailReceipt::default())
                    .build()),
        )
        .mount(&server)
        .await;

    with_env(
        &[
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        async {
            for event in [
                ses_event(),
                ses_gray_event(),
                pacer_event_one(),
                pacer_event_two(),
                pacer_event_three(),
            ] {
                let response = app::handler(event).await.unwrap();
                let data = &response.body;

                assert_eq!(response.status_code, 200);
                eprintln!("{data:#?}");
                assert!(data.get("mail").is_some());
                assert!(data.get("receipt").is_some());
            }
        },
    )
    .await;
}

/// Confirm that the court_id in the request uses the right value
/// from map_email_to_cl_id
#[tokio::test(flavor = "multi_thread")]
async fn test_request_court_field_actual_value() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let event = pacer_event_two();
    let response = with_env(
        &[
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();
    assert_eq!(response.status_code, 200);

    // Retrieve the request that made by send_to_court_listener
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body.get("court"),
        Some(&json!("mowd")),
        "Expected 'mowd', but got '{:?}'",
        body.get("court")
    );
}

/// A bankruptcy NEF from the shared txs.uscourts.gov domain must be
/// posted with the ECF-host court (txsb), not the district default.
#[tokio::test(flavor = "multi_thread")]
async fn test_request_court_field_uses_ecf_host_for_shared_domain() {
    let mut event = pacer_event_two();
    let mail = &mut event.payload.records[0].ses.mail;
    mail.common_headers.from = vec!["<BKECF_LiveDB@txs.uscourts.gov>".to_string()];
    mail.headers.push(SimpleEmailHeader::builder()
        .name("Received".to_string())
        .value("from txsbdb.txsb.gtwy.dcn (localhost.localdomain [127.0.0.1]) by txsbdb.txsb.gtwy.dcn with ESMTP; Mon, 28 Jun 2021 13:51:08 -0500".to_string())
        .build());

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let response = with_env(
        &[
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();
    assert_eq!(response.status_code, 200);

    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body.get("court"),
        Some(&json!("txsb")),
        "Expected 'txsb', but got '{:?}'",
        body.get("court")
    );
}

/// Confirm a scotus email is properly routed to the SCOTUS_EMAIL_ENDPOINT
#[tokio::test(flavor = "multi_thread")]
async fn test_scotus_email_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let event = scotus_event();
    let response = with_env(
        &[
            (
                "SCOTUS_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v4/scrapers/scotus-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();
    assert_eq!(response.status_code, 200);

    // Retrieve the request that made by send_to_court_listener
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].url.path(),
        "/api/rest/v4/scrapers/scotus-email/"
    );

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body.get("court"),
        Some(&json!("scotus")),
        "Expected 'scotus', but got '{:?}'",
        body.get("court")
    );
}

/// Confirm a Texas email is properly routed to the TEXAS_EMAIL_ENDPOINT
#[tokio::test(flavor = "multi_thread")]
async fn test_texas_email_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let event = texas_event();
    let response = with_env(
        &[
            (
                "TEXAS_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v4/email/state/tx/tames/alert", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();
    assert_eq!(response.status_code, 200);

    // Retrieve the request that made by send_to_court_listener
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests[0].url.path(),
        "/api/rest/v4/email/state/tx/tames/alert"
    );

    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(
        body.get("court"),
        Some(&json!("txctapp1")),
        "Expected 'txctapp1', but got '{:?}'",
        body.get("court")
    );
}

/// Confirm that if an invalid court_id is sent to CL, an error event is
/// sent to Sentry.
#[tokio::test(flavor = "multi_thread")]
async fn test_report_request_for_invalid_court() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"court": ["Invalid pk \"whla\" - object does not exist."]})),
        )
        .mount(&server)
        .await;

    let event = pacer_event_one();
    let events = with_env(
        &[
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        async {
            sentry::test::with_captured_events(|| {
                futures::executor::block_on(app::handler(event)).unwrap();
            })
        },
    )
    .await;
    // The expected error message should be sent to Sentry.
    let expected_error =
        "Invalid court pk: whla - message_id: 171jjm4scn8vgcn5vrcv4su427obcred7bekus81";
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].message.as_deref(), Some(expected_error));
    assert_eq!(events[0].level, sentry::Level::Error);
    assert_eq!(
        events[0]
            .fingerprint
            .iter()
            .map(|f| f.as_ref())
            .collect::<Vec<_>>(),
        vec!["invalid-court-pk"]
    );
}

/// A SCOTUS email delivered to a plain @recap.email address is ignored to
/// avoid double processing via the generic recap.email SES rule.
#[tokio::test(flavor = "multi_thread")]
async fn test_scotus_email_ignored_for_wrong_subscription() {
    let mut event = scotus_event();
    event.payload.records[0].ses.mail.destination = vec!["user@recap.email".to_string()];

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let response = with_env(
        &[
            (
                "SCOTUS_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v4/scrapers/scotus-email/", server.uri()),
            ),
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.failure, Err(ValidationFailure::Subscription));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

/// A Texas email delivered to a plain @recap.email address is ignored to
/// avoid double processing via the generic recap.email SES rule.
#[tokio::test(flavor = "multi_thread")]
async fn test_texas_email_ignored_for_wrong_subscription() {
    let mut event = texas_event();
    event.payload.records[0].ses.mail.destination = vec!["user@recap.email".to_string()];

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let response = with_env(
        &[
            (
                "TEXAS_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v4/email/state/tx/tames/alert", server.uri()),
            ),
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();

    assert_eq!(response.status_code, 200);
    assert_eq!(response.failure, Err(ValidationFailure::Subscription));
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[test]
fn test_destination_list_matches_subscription() {
    let mut email = make_court_email("meow@meow.gov", &vec![][..]);
    email.headers.push(SimpleEmailHeader::builder()
        .name("Return-Path".to_string())
        .value("no-reply@sc-us.gov".to_string())
        .build());
    email.destination = vec!["bob@test.email".to_string(), "notifications@scotus.recap.email".to_string()];

    let m = destination_matches_subscription(&email);

    assert!(m);
}

/// Confirm that if an invalid court_id in sub_domains_to_ignore is sent, a
/// validation_domain_failure is sent.
#[tokio::test(flavor = "multi_thread")]
async fn test_ignore_messages_from_invalid_court_ids() {
    let mut event = pacer_event_one();
    event.payload.records[0].ses.mail.common_headers.from =
        vec!["ecfnotices@updates.uscourts.gov".to_string()];

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"mail": {}, "receipt": {}})))
        .mount(&server)
        .await;

    let response = with_env(
        &[
            (
                "RECAP_EMAIL_ENDPOINT",
                &format!("{}/api/rest/v3/recap-email/", server.uri()),
            ),
            ("AUTH_TOKEN", "************************"),
        ],
        app::handler(event),
    )
    .await
    .unwrap();
    assert_eq!(response.status_code, 424);
    assert_eq!(response.failure, Err(ValidationFailure::Domain));
}
