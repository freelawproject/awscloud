use std::collections::HashMap;
use std::env;
use std::sync::{
    LazyLock,
    RwLock,
};
use std::time::Duration;

use lambda_runtime::Error;
use regex::Regex;
use serde_json::{
    Value,
    json,
};

use crate::pacer::DOMAIN_TO_SUBSCRIPTION_SUBDOMAIN;
pub use crate::pacer::{
    SUB_DOMAINS_TO_IGNORE,
    map_email_to_cl_id,
};
use crate::utils;
use crate::utils::{
    decamelize,
    extract_address,
};

pub static RECAP_EMAIL_ENDPOINT: LazyLock<RwLock<Option<String>>> =
    LazyLock::new(|| RwLock::new(None));
pub static CL_ENDPOINT_MAP: LazyLock<RwLock<HashMap<String, Option<String>>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Extract values for a specific header from an SES email payload.
///
/// :param email: The SES email object.
/// :param header_name: The name of the email header to extract.
/// :return: A list of header values matching the requested header name.
pub fn get_ses_email_headers<'a>(email: &'a Value, header_name: &str) -> Vec<&'a str> {
    email["headers"]
        .as_array()
        .map(|headers| {
            headers
                .iter()
                .filter(|header| header["name"] == header_name)
                .filter_map(|header| header["value"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

pub fn get_ses_record_from_event(event: &Value) -> Option<&Value> {
    for record in event["Records"].as_array()? {
        if record["eventSource"] == "aws:ses" {
            return record.get("ses").filter(|ses| !ses.is_null());
        }
    }
    None
}

pub fn get_spam_verdict(receipt: &Value) -> Result<&str, Error> {
    receipt["spam_verdict"]["status"]
        .as_str()
        .ok_or_else(|| "receipt is missing spam_verdict.status".into())
}

pub fn get_virus_verdict(receipt: &Value) -> Result<&str, Error> {
    receipt["virus_verdict"]["status"]
        .as_str()
        .ok_or_else(|| "receipt is missing virus_verdict.status".into())
}

pub fn get_spf_verdict(receipt: &Value) -> Result<&str, Error> {
    receipt["spf_verdict"]["status"]
        .as_str()
        .ok_or_else(|| "receipt is missing spf_verdict.status".into())
}

pub fn get_dkim_verdict(receipt: &Value) -> Result<&str, Error> {
    receipt["dkim_verdict"]["status"]
        .as_str()
        .ok_or_else(|| "receipt is missing dkim_verdict.status".into())
}

pub fn get_dmarc_verdict(receipt: &Value) -> Result<&str, Error> {
    receipt["dmarc_verdict"]["status"]
        .as_str()
        .ok_or_else(|| "receipt is missing dmarc_verdict.status".into())
}

pub fn get_combined_log_message(email: &Value) -> String {
    let subject = get_ses_email_headers(email, "Subject")
        .last()
        .copied()
        .unwrap_or("None");

    format!(
        "Email ID {} with {subject}, from {} to {}",
        email["message_id"].as_str().unwrap_or("None"),
        email["source"].as_str().unwrap_or("None"),
        email["destination"]
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

pub fn get_valid_domain_verdict(email: &Value) -> &'static str {
    // Check all Return-Path headers comes from uscourts.gov
    for email_address in get_ses_email_headers(email, "Return-Path") {
        if !check_valid_domain(email_address) {
            return "FAILED";
        }
    }
    "PASS"
}

pub fn validation_failure(email: &Value, receipt: &Value, verdict: &str) -> Value {
    println!(
        "{} failed with spam verdict {verdict}",
        get_combined_log_message(email)
    );
    json!({
        "statusCode": 424,
        "body": receipt.to_string(),
    })
}

pub fn validation_domain_failure(email: &Value, receipt: &Value, verdict: &str) -> Value {
    println!(
        "{} failed with valid domain verdict {verdict}",
        get_combined_log_message(email)
    );
    json!({
        "statusCode": 424,
        "valid_domain": {"status": "FAILED"},
        "body": receipt.to_string(),
    })
}

/// Return the registrable domain from the email's Return-Path header,
/// or None if no Return-Path is present or parseable.
pub fn get_source_domain(email: &Value) -> Option<String> {
    for email_address in get_ses_email_headers(email, "Return-Path") {
        let parts: Vec<&str> = extract_address(email_address).split('@').collect();
        if parts.len() != 2 {
            continue;
        }
        let labels: Vec<&str> = parts[1].split('.').collect();
        return Some(
            labels[labels.len().saturating_sub(2)..]
                .join(".")
                .to_lowercase(),
        );
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
pub fn destination_matches_subscription(email: &Value) -> bool {
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
    let destinations = email["destination"].as_array().cloned().unwrap_or_default();
    for destination in &destinations {
        let destination = match destination.as_str() {
            Some(destination) => destination,
            None => continue,
        };
        let dest_parts: Vec<&str> = extract_address(destination).split('@').collect();
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

pub fn ignore_wrong_subscription(email: &Value, receipt: &Value) -> Value {
    println!(
        "{} ignored — destination does not match the required subscription subdomain for its \
         source domain.",
        get_combined_log_message(email)
    );
    json!({
        "statusCode": 200,
        "subscription": {"status": "IGNORED"},
        "body": receipt.to_string(),
    })
}

static INVALID_PK_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"Invalid pk "([^"]+)""#).unwrap());

/// Checks if the response indicates an invalid court pk then send a report
/// to Sentry.
pub fn log_invalid_court_error(status_code: u16, response_json: &Value, message_id: &str) {
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
        let error_message = format!("Invalid court pk: {court_id} - message_id: {message_id}");
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
pub fn get_cl_endpoint(email: &Value) -> Option<String> {
    for email_address in get_ses_email_headers(email, "Return-Path") {
        let domain = match extract_address(email_address).split('@').nth(1) {
            Some(domain) => domain,
            None => continue,
        };
        let labels: Vec<&str> = domain.split('.').collect();
        let tld = labels[labels.len().saturating_sub(2)..].join(".");

        if let Some(endpoint) = CL_ENDPOINT_MAP.read().unwrap().get(&tld) {
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
    email: &Value,
    receipt: &Value,
    court_id: &str,
) -> Result<Value, Error> {
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

        let response_json: Value = court_listener_response.json().await?;

        let message_id = email["message_id"].as_str().unwrap_or("None");
        log_invalid_court_error(status_code, &response_json, message_id);

        println!("Got status_code={status_code} and content {response_json}");

        Ok(json!({
            "statusCode": 200,
            "body": response_json,
        }))
    })
    .await
}

pub async fn handler(event: &Value) -> Result<Value, Error> {
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

    let ses_record = match get_ses_record_from_event(event) {
        Some(ses_record) => ses_record,
        None => {
            let body = json!({"message": "PACER email receipt requires aws:ses eventSource."});
            return Ok(json!({
                "statusCode": 415,
                "body": body.to_string(),
            }));
        }
    };

    let email = decamelize(&ses_record["mail"]);
    let receipt = decamelize(&ses_record["receipt"]);

    type VerdictFn = for<'a> fn(&'a Value) -> Result<&'a str, Error>;
    let tests: [VerdictFn; 2] = [
        // NOTE - SPAM verdict failed with some test emails.
        get_spam_verdict,
        get_virus_verdict,
    ];
    for test in tests {
        let verdict = test(&receipt)?;
        if verdict != "PASS" {
            return Ok(validation_failure(&email, &receipt, verdict));
        }
    }

    let gray_or_pass_tests: [VerdictFn; 3] = [get_spf_verdict, get_dmarc_verdict, get_dkim_verdict];
    for test in gray_or_pass_tests {
        let verdict = test(&receipt)?;
        if verdict != "PASS" && verdict != "GRAY" {
            return Ok(validation_failure(&email, &receipt, verdict));
        }
    }

    let domain_verdict = get_valid_domain_verdict(&email);
    // Check domain is valid (comes from uscourts.gov)
    // Ignore messages that are not from courts, such as updates.uscourts.gov
    if domain_verdict != "PASS" {
        return Ok(validation_domain_failure(&email, &receipt, domain_verdict));
    }
    if !destination_matches_subscription(&email) {
        return Ok(ignore_wrong_subscription(&email, &receipt));
    }
    let court_id = map_email_to_cl_id(&email)?;
    if SUB_DOMAINS_TO_IGNORE.contains(&court_id.as_str()) {
        return Ok(validation_domain_failure(&email, &receipt, domain_verdict));
    }
    send_to_court_listener(&email, &receipt, &court_id).await
}
