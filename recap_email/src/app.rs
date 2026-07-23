use crate::pacer::DOMAIN_TO_SUBSCRIPTION_SUBDOMAIN;
pub use crate::pacer::{
    map_email_to_cl_id,
    SUB_DOMAINS_TO_IGNORE,
};
use crate::utils;
use crate::utils::{extract_address, extract_tld};
use aws_lambda_events::ses::{SimpleEmailEvent, SimpleEmailMessage, SimpleEmailReceipt, SimpleEmailVerdict};
use lambda_runtime::tracing::{error, warn};
use lambda_runtime::{Error, LambdaEvent};
use regex::Regex;
use serde::Serialize;
use serde_json::{
    json,
    Value,
};
use std::collections::HashMap;
use std::env;
use std::sync::{
    LazyLock,
    RwLock,
};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ValidationFailure {
    Spam,
    Virus,
    Spf,
    Dkim,
    Dmarc,
    Domain,
    EventSourceMissing,
    Subscription,
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ValidationFailure {}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub status_code: u16,
    pub failure: Result<(), ValidationFailure>,
    pub body: Value,
}

impl Response {
    pub fn success(body: Value) -> Response {
        Self {
            status_code: 200,
            failure: Ok(()),
            body,
        }
    }

    pub fn source_missing_failure(body: Value) -> Response {
        Self {
            status_code: 415,
            failure: Err(ValidationFailure::EventSourceMissing),
            body,
        }
    }

    pub fn dependency_failure(body: Value, failure: ValidationFailure) -> Response {
        Self {
            status_code: 424,
            failure: Err(failure),
            body,
        }
    }
}

pub static RECAP_EMAIL_ENDPOINT: LazyLock<RwLock<Option<String>>> =
    LazyLock::new(|| RwLock::new(None));
pub static CL_ENDPOINT_MAP: LazyLock<RwLock<HashMap<String, Option<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Extract values for a specific header from an SES email payload.
///
/// :param email: The SES email object.
/// :param header_name: The name of the email header to extract.
/// :return: A list of header values matching the requested header name.
pub fn get_ses_email_headers<'a>(email: &'a SimpleEmailMessage, header_name: &str) -> Vec<Option<&'a str>> {
    email.headers.iter()
        .filter(|header| header.name.as_ref().is_some_and(|s| s.eq_ignore_ascii_case(header_name)))
        .map(|header| header.value.as_ref().map(|s| s.as_str()))
        .collect()
}

pub fn get_combined_log_message(email: &SimpleEmailMessage) -> String {
    let subjects = get_ses_email_headers(email, "Subject");
    let subject = subjects
        .last().and_then(|subject| subject.as_deref());

    format!(
        "Email ID {:?} with {subject:?}, from {:?} to {:?}",
        email.message_id,
        email.source,
        email.destination
    )
}

pub fn check_valid_domain(email_address: &str) -> bool {
    let domain = match extract_address(email_address).split('@').nth(1) {
        Some(domain) => domain,
        // Lack of @, invalid email address
        None => return false,
    };

    let labels: Vec<&str> = domain.split('.').collect();
    let tld = labels[labels.len().saturating_sub(2)..].join(".");

    CL_ENDPOINT_MAP.read().unwrap().contains_key(&tld)
}

pub fn is_valid_domain(email: &SimpleEmailMessage) -> bool {
    // Check all Return-Path headers comes from uscourts.gov
    for email_address in get_ses_email_headers(email, "Return-Path") {
        let Some(email_address) = email_address.as_deref() else {
            continue;
        };
        if !check_valid_domain(email_address) {
            return false;
        }
    }
    true
}

pub fn validation_failure(email: &SimpleEmailMessage, receipt: &SimpleEmailReceipt, failure: ValidationFailure) -> Response {
    error!(
        "{} failed with spam verdict {failure:?}",
        get_combined_log_message(email)
    );
    Response {
        status_code: 424,
        failure: Err(failure),
        body: serde_json::to_value(receipt).unwrap(),
    }
}

pub fn validation_domain_failure(email: &SimpleEmailMessage, receipt: &SimpleEmailReceipt) -> Response {
    error!(
        "{} failed domain validation.",
        get_combined_log_message(email)
    );
    Response::dependency_failure(serde_json::to_value(receipt).unwrap(), ValidationFailure::Domain)
}

/// Return the registrable domain from the email's Return-Path header,
/// or None if no Return-Path is present or parseable.
pub fn get_source_domain(email: &SimpleEmailMessage) -> Option<&str> {
    for email_address in get_ses_email_headers(email, "Return-Path") {
        let Some(email_address) = email_address else {
            continue;
        };
        return extract_tld(email_address);
    }
    None
}

/// Return True if the email should be processed, False if it should be
/// ignored because its source domain requires a specific subscription
/// subdomain (e.g., scotus.recap.email) but the destination does not use it.
///
/// Specifically, if any address in the email's destination list matches the
/// expected destination for the given source domain, return True. Otherwise,
/// return False. This lets us handle potential emails with multiple destinations
/// correctly.
pub fn destination_matches_subscription(email: &SimpleEmailMessage) -> bool {
    let source_domain = match get_source_domain(email) {
        Some(source_domain) => source_domain,
        None => return true,
    };
    let required = match DOMAIN_TO_SUBSCRIPTION_SUBDOMAIN
        .iter()
        .find(|(domain, _)| *domain == source_domain)
    {
        Some((_, required)) => *required,
        None => return true,
    };
    for destination in &email.destination {
        let dest_parts: Vec<&str> = extract_address(&destination).split('@').collect();
        if dest_parts.len() != 2 {
            continue;
        }
        let dest_domain = dest_parts[1].to_lowercase();
        if dest_domain == required || dest_domain.ends_with(&format!(".{required}")) {
            return true;
        }
    }
    false
}

pub fn ignore_wrong_subscription(email: &SimpleEmailMessage, receipt: &SimpleEmailReceipt) -> Response {
    warn!(
        "{} ignored — destination does not match the required subscription subdomain for its \
         source domain.",
        get_combined_log_message(email)
    );
    Response {
        status_code: 200,
        failure: Err(ValidationFailure::Subscription),
        body: serde_json::to_value(receipt).unwrap(),
    }
}

static INVALID_PK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"Invalid pk "([^"]+)""#).unwrap());

/// Checks if the response indicates an invalid court pk then send a report
/// to Sentry.
pub fn log_invalid_court_error(status_code: u16, response_json: &Value, message_id: &Option<String>) {
    if status_code != 400 {
        return;
    }

    let empty = Vec::new();
    let msgs = response_json["court"].as_array().unwrap_or(&empty);
    for msg in msgs {
        let msg = match msg.as_str() {
            Some(msg) => msg,
            None => continue,
        };
        let court_id = match INVALID_PK_RE.captures(msg) {
            Some(captures) => captures[1].to_string(),
            None => continue,
        };
        let error_message = format!("Invalid court pk: {court_id} - message_id: {}", message_id.clone().unwrap_or_default());
        sentry::with_scope(
            |scope| scope.set_fingerprint(Some(&["invalid-court-pk"])),
            || sentry::capture_message(&error_message, sentry::Level::Error),
        );
        break;
    }
}

/// Determine the appropriate CourtListener API endpoint to route an SES
/// email.
///
/// If no known domain match is found, the function defaults to the
/// `RECAP_EMAIL_ENDPOINT`.
///
/// :param email: The SES email object.
/// :return: A string containing the CourtListener API endpoint URL to which
/// the email request should be sent.
pub fn get_cl_endpoint(email: &SimpleEmailMessage) -> Option<String> {
    for email_address in get_ses_email_headers(email, "Return-Path") {
        let Some(email_address) = email_address else {
            continue;
        };

        let Some(tld) = extract_tld(email_address) else {
            continue;
        };

        if let Some(endpoint) = CL_ENDPOINT_MAP.read().unwrap().get(tld) {
            return endpoint.clone();
        }
    }
    RECAP_EMAIL_ENDPOINT.read().unwrap().clone()
}

fn is_retryable(e: &Error) -> bool {
    e.downcast_ref::<reqwest::Error>()
        .is_some_and(|e| e.is_connect() || e.is_timeout() || e.is_status())
}

pub async fn send_to_court_listener(
    email: &SimpleEmailMessage,
    receipt: &SimpleEmailReceipt,
    court_id: &str,
) -> Result<Response, Error> {
    utils::retry(is_retryable, 5, 10, 3, || async {
        println!(
            "{} sending to Court Listener API.",
            get_combined_log_message(email)
        );
        let endpoint = get_cl_endpoint(email).ok_or("no CourtListener endpoint configured")?;

        // DEV DOMAIN: http://host.docker.internal:8000
        let court_listener_response = reqwest::Client::new()
            .post(&endpoint)
            .json(&json!({
                "mail": email,
                "receipt": receipt,
                "court": court_id,
            }))
            .timeout(Duration::from_secs(5))
            .header(
                "Authorization",
                format!(
                    "Token {}",
                    env::var("AUTH_TOKEN").unwrap_or_else(|_| "None".to_string())
                ),
            )
            .send()
            .await?;

        let status_code = court_listener_response.status().as_u16();
        if [502, 503, 504].contains(&status_code) {
            // Raise an HTTPError for Bad Gateway, Service Unavailable or
            // Gateway Timeout status codes.
            court_listener_response.error_for_status_ref()?;
        }

        let response_json = court_listener_response.json().await?;

        log_invalid_court_error(status_code, &response_json, &email.message_id);

        println!("Got status_code={status_code} and content {response_json}");

        Ok(Response {
            status_code: 200,
            failure: Ok(()),
            body: response_json,
        })
    })
    .await
}

fn verdict_pass(verdict: &SimpleEmailVerdict) -> bool {
    match &verdict.status {
        Some(status) => status == "PASS",
        None => true,
    }
}

fn verdict_pass_or_gray(verdict: &SimpleEmailVerdict) -> bool {
    match &verdict.status {
        Some(status) => status == "PASS" || status == "GRAY",
        None => true,
    }
}

pub async fn handler(event: LambdaEvent<SimpleEmailEvent>) -> Result<Response, Error> {
    let recap_email_endpoint = env::var("RECAP_EMAIL_ENDPOINT").ok();
    *RECAP_EMAIL_ENDPOINT.write().unwrap() = recap_email_endpoint.clone();
    let scotus_email_endpoint = env::var("SCOTUS_EMAIL_ENDPOINT").ok();
    let texas_email_endpoint = env::var("TEXAS_EMAIL_ENDPOINT").ok();
    *CL_ENDPOINT_MAP.write().unwrap() = HashMap::from([
        ("sc-us.gov".to_string(), scotus_email_endpoint),
        ("fedcourts.us".to_string(), recap_email_endpoint.clone()),
        ("uscourts.gov".to_string(), recap_email_endpoint),
        ("txcourts.gov".to_string(), texas_email_endpoint),
    ]);

    let Some(ses_record) = event.payload.records.first().map(|r| &r.ses) else {
        let body = json!({"message": "PACER email receipt requires aws:ses eventSource."});

        return Ok(Response::source_missing_failure(body));
    };

    if !verdict_pass(&ses_record.receipt.spam_verdict) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Spam));
    }

    if !verdict_pass(&ses_record.receipt.virus_verdict) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Virus));
    }

    if !verdict_pass_or_gray(&ses_record.receipt.spf_verdict) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Spf));
    }

    if !verdict_pass_or_gray(&ses_record.receipt.dmarc_verdict) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Dmarc));
    }

    if !verdict_pass_or_gray(&ses_record.receipt.dkim_verdict) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Dkim));
    }

    if !is_valid_domain(&ses_record.mail) {
        return Ok(validation_failure(&ses_record.mail, &ses_record.receipt, ValidationFailure::Domain));
    }

    if !destination_matches_subscription(&ses_record.mail) {
        return Ok(ignore_wrong_subscription(&ses_record.mail, &ses_record.receipt));
    }

    let court_id = map_email_to_cl_id(&ses_record.mail)?;
    if SUB_DOMAINS_TO_IGNORE.contains(&court_id.as_str()) {
        return Ok(validation_domain_failure(&ses_record.mail, &ses_record.receipt));
    }

    send_to_court_listener(&ses_record.mail, &ses_record.receipt, &court_id).await
}
