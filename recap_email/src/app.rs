use crate::pacer::EmailMap;
use crate::utils;
use crate::utils::EmailAddress;
use aws_lambda_events::ses::{SimpleEmailEvent, SimpleEmailMessage, SimpleEmailReceipt, SimpleEmailService, SimpleEmailVerdict};
use lambda_runtime::tracing::{error, warn};
use lambda_runtime::{Error, LambdaEvent};
use regex::regex;
use serde::Serialize;
use serde_json::{
    Value,
    json,
};
use std::collections::HashMap;
use std::env;
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
        write!(f, "{self:?}")
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
    #[must_use]
    pub fn success(body: Value) -> Response {
        Self {
            status_code: 200,
            failure: Ok(()),
            body,
        }
    }

    #[must_use]
    pub fn source_missing_failure(body: Value) -> Response {
        Self {
            status_code: 415,
            failure: Err(ValidationFailure::EventSourceMissing),
            body,
        }
    }

    #[must_use]
    pub fn dependency_failure(body: Value, failure: ValidationFailure) -> Response {
        Self {
            status_code: 424,
            failure: Err(failure),
            body,
        }
    }
}

pub struct EndpointMap {
    recap_endpoint: Option<String>,
    cl_endpoints: HashMap<String, Option<String>>,
}

impl Default for EndpointMap {
    fn default() -> Self {
        let recap_endpoint = env::var("RECAP_EMAIL_ENDPOINT").ok();
        let scotus_email_endpoint = env::var("SCOTUS_EMAIL_ENDPOINT").ok();
        let texas_email_endpoint = env::var("TEXAS_EMAIL_ENDPOINT").ok();
        Self {
            cl_endpoints: HashMap::from([
                ("sc-us.gov".to_string(), scotus_email_endpoint),
                ("fedcourts.us".to_string(), recap_endpoint.clone()),
                ("uscourts.gov".to_string(), recap_endpoint.clone()),
                ("txcourts.gov".to_string(), texas_email_endpoint),
            ]),
            recap_endpoint,
        }
    }
}

impl EndpointMap {
    /// Determine the appropriate CourtListener API endpoint to route an SES
    /// email.
    ///
    /// If no known domain match is found, the function defaults to the
    /// [`self.recap_endpoint`].
    #[must_use]
    pub fn get_cl_endpoint(&self, event: &SESEvent) -> Option<String> {
        for email_address in event.get_header("Return-Path") {
            let Some(email_address) = email_address.and_then(EmailAddress::parse_str) else {
                continue;
            };

            if let Some(endpoint) = self.cl_endpoints.get(email_address.domain()) {
                return endpoint.clone();
            }
        }
        self.recap_endpoint.clone()
    }

    /// Check whether an email address is one we accept updates from.
    #[must_use]
    pub fn check_valid_domain(&self, email_address: &str) -> bool {
        let Some(email) = EmailAddress::parse_str(email_address) else {
            return false;
        };

        self.cl_endpoints.contains_key(email.domain())
    }

    #[must_use]
    pub fn is_valid_domain(&self, email: &SESEvent) -> bool {
        // Check all Return-Path headers comes from uscourts.gov
        email.get_header("Return-Path").iter()
            .filter_map(|v| *v)
            .all(|email_address| self.check_valid_domain(email_address))
    }
}

/// Shorthand to log a given validation failure and construct a [`Response`] object.
///
/// # Panics
/// Will panic if the [`receipt`] parameter fails JSON serialization.
pub fn validation_failure(email: &SESEvent, failure: ValidationFailure) -> Response {
    error!(
        "{} failed because {failure:?}",
        email.get_combined_log_message()
    );
    Response {
        status_code: 424,
        failure: Err(failure),
        body: serde_json::to_value(email.receipt()).unwrap(),
    }
}

/// Shorthand to log a domain validation failure and construct a [`Response`] object.
///
/// # Panics
/// Will panic if the [`receipt`] parameter fails JSON serialization.
pub fn validation_domain_failure(email: &SESEvent) -> Response {
    error!(
        "{} failed domain validation.",
        email.get_combined_log_message()
    );
    Response::dependency_failure(serde_json::to_value(email.receipt()).unwrap(), ValidationFailure::Domain)
}

/// Ensure that the destination of an email matches the subscription subdomain for its source
/// domain.
///
/// # Panics
/// Will panic if the [`receipt`] parameter fails to serialize to JSON.
#[must_use]
pub fn ignore_wrong_subscription(email: &SESEvent) -> Response {
    warn!(
        "{} ignored — destination does not match the required subscription subdomain for its \
         source domain.",
        email.get_combined_log_message()
    );
    Response {
        status_code: 200,
        failure: Err(ValidationFailure::Subscription),
        body: serde_json::to_value(email.receipt()).unwrap(),
    }
}

/// Checks if the response indicates an invalid court pk then send a report
/// to Sentry.
pub fn log_invalid_court_error(status_code: u16, response_json: &Value, message_id: &Option<String>) {
    let invalid_pk_re = regex!(r#"Invalid pk "([^"]+)"#);

    if status_code != 400 {
        return;
    }

    let empty = Vec::new();
    let msgs = response_json["court"].as_array().unwrap_or(&empty);
    for msg in msgs {
        let Some(msg) = msg.as_str() else { continue };
        let court_id = match invalid_pk_re.captures(msg) {
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

pub struct SESEvent<'a>(&'a SimpleEmailService);

impl<'a> From<&'a SimpleEmailService> for SESEvent<'a> {
    fn from(event: &'a SimpleEmailService) -> Self {
        Self(event)
    }
}

impl<'a> From<SESEvent<'a>> for &'a SimpleEmailService {
    fn from(event: SESEvent<'a>) -> Self {
        event.0
    }
}

impl<'a> SESEvent<'a> {
    pub fn email(&self) -> &SimpleEmailMessage {
        &self.0.mail
    }

    pub fn receipt(&self) -> &SimpleEmailReceipt {
        &self.0.receipt
    }

    /// Extract values for the header with name [`header_name`] from an SES email payload.
    #[must_use]
    pub fn get_header(&self, key: &'a str) -> Vec<Option<&'a str>> {
        self.0.mail.headers.iter()
            .filter(|header| header.name.as_ref().is_some_and(|s| s.eq_ignore_ascii_case(key)))
            .map(|header| header.value.as_deref())
            .collect()
    }

    #[must_use]
    pub fn get_combined_log_message(&self) -> String {
        let subjects = self.get_header("Subject");
        let subject = subjects
            .last().and_then(|subject| subject.as_deref());

        format!(
            "Email ID {:?} with {subject:?}, from {:?} to {:?}",
            self.0.mail.message_id,
            self.0.mail.source,
            self.0.mail.destination
        )
    }

    /// Return the registrable domain from the email's `"Return-Path"` header,
    /// or None if no `"Return-Path"` is present or parseable.
    #[must_use]
    pub fn get_source_domain(&self) -> Option<&'a str> {
        self.get_header("Return-Path").iter()
            .filter_map(|v| v.and_then(EmailAddress::parse_str))
            .map(|email_address| email_address.domain())
            .next()
    }
}


fn is_retryable(e: &Error) -> bool {
    e.downcast_ref::<reqwest::Error>()
        .is_some_and(|e| e.is_connect() || e.is_timeout() || e.is_status())
}

/// Send an event which has passed validation to the CourtListener endpoint for the given court.
///
/// # Errors
/// Will return an error if the send attempt fails all retries.
pub async fn send_to_court_listener(
    endpoint_map: &EndpointMap,
    event: &SESEvent<'_>,
    court_id: &str,
) -> Result<Response, Error> {
    utils::retry(is_retryable, 5, 10, 3, || async {
        println!(
            "{} sending to Court Listener API.",
            event.get_combined_log_message()
        );
        let endpoint = endpoint_map.get_cl_endpoint(event).ok_or("no CourtListener endpoint configured")?;

        // DEV DOMAIN: http://host.docker.internal:8000
        let court_listener_response = reqwest::Client::new()
            .post(&endpoint)
            .json(&json!({
                "mail": event.email(),
                "receipt": event.receipt(),
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

        log_invalid_court_error(status_code, &response_json, &event.email().message_id);

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

/// Forward an SES email event to the appropriate CourtListener endpoint if it is valid.
///
/// # Errors
/// Will return an error if the email event fails validation for any reason.
pub async fn handler(event: LambdaEvent<SimpleEmailEvent>) -> Result<Response, Error> {
    let endpoint_map = EndpointMap::default();
    let email_map = EmailMap::default();

    let Some(ses_event) = event.payload.records.first().map(|r| SESEvent::from(&r.ses)) else {
        let body = json!({"message": "PACER email receipt requires aws:ses eventSource."});

        return Ok(Response::source_missing_failure(body));
    };

    if !verdict_pass(&ses_event.receipt().spam_verdict) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Spam));
    }

    if !verdict_pass(&ses_event.receipt().virus_verdict) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Virus));
    }

    if !verdict_pass_or_gray(&ses_event.receipt().spf_verdict) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Spf));
    }

    if !verdict_pass_or_gray(&ses_event.receipt().dmarc_verdict) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Dmarc));
    }

    if !verdict_pass_or_gray(&ses_event.receipt().dkim_verdict) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Dkim));
    }

    if !endpoint_map.is_valid_domain(&ses_event) {
        return Ok(validation_failure(&ses_event, ValidationFailure::Domain));
    }

    if !email_map.destination_matches_subscription(&ses_event) {
        return Ok(ignore_wrong_subscription(&ses_event));
    }

    let court_id = email_map.email_to_cl_id(&ses_event)?;
    if email_map.ignored_subdomains.contains(&court_id.as_str()) {
        return Ok(validation_domain_failure(&ses_event));
    }

    send_to_court_listener(&endpoint_map, &ses_event, &court_id).await
}
