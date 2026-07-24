use std::collections::HashMap;
use std::env;
use std::time::Duration;

use aws_lambda_events::ses::{
    SimpleEmailEvent,
    SimpleEmailMessage,
    SimpleEmailReceipt,
    SimpleEmailService,
    SimpleEmailVerdict,
};
use lambda_runtime::tracing::{
    error,
    warn,
};
use lambda_runtime::{
    Error,
    LambdaEvent,
};
use regex::regex;
use serde::Serialize;
use serde_json::{
    Value,
    json,
};

use crate::pacer::EmailMap;
use crate::utils;
use crate::utils::EmailAddress;

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
    Email,
    UnrecognizedSubject,
    UnrecognizedCourt,
    MissingCommonFrom,
    MissingCommonSubject,
    AddressParsingFailed,
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
    pub fn source_missing_failure() -> Response {
        Self {
            status_code: 415,
            failure: Err(ValidationFailure::EventSourceMissing),
            body: json!({"message": "PACER email receipt requires aws:ses eventSource."}),
        }
    }

    #[must_use]
    pub fn dependency_failure(
        event: &SESEvent<Unvalidated>,
        failure: ValidationFailure,
    ) -> Response {
        error!(
            "{} failed because {failure:?}",
            event.get_combined_log_message()
        );
        Self {
            status_code: 424,
            failure: Err(failure),
            body: serde_json::to_value(event.receipt())
                .unwrap_or(json!({"error": "Failed to serialize message receipt"})),
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
    /// email to based on its `"Return-Path"` headers.
    ///
    /// If no known domain match is found, the function defaults to the
    /// [`self.recap_endpoint`].
    #[must_use]
    pub fn get_cl_endpoint(&self, addrs: &[Option<&str>]) -> Option<String> {
        addrs
            .iter()
            .filter_map(|addr| addr.and_then(EmailAddress::parse_str))
            .find_map(|addr| {
                self.cl_endpoints
                    .get(addr.domain())
                    .and_then(ToOwned::to_owned)
            })
            .or(self.recap_endpoint.clone())
    }

    /// Check whether an email address is one we accept updates from.
    #[must_use]
    pub fn check_valid_domain(&self, email_address: &str) -> bool {
        EmailAddress::parse_str(email_address)
            .is_some_and(|email| self.cl_endpoints.contains_key(email.domain()))
    }

    #[must_use]
    pub fn is_valid_domain(&self, addrs: &[Option<&str>]) -> bool {
        // Check all Return-Path headers comes from uscourts.gov
        addrs
            .iter()
            .filter_map(|v| *v)
            .all(|email_address| self.check_valid_domain(email_address))
    }
}

/// Checks if the response indicates an invalid court pk then send a report
/// to Sentry.
pub fn log_invalid_court_error(
    status_code: u16,
    response_json: &Value,
    message_id: &Option<String>,
) {
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
        let error_message = format!(
            "Invalid court pk: {court_id} - message_id: {}",
            message_id.clone().unwrap_or_default()
        );
        sentry::with_scope(
            |scope| scope.set_fingerprint(Some(&["invalid-court-pk"])),
            || sentry::capture_message(&error_message, sentry::Level::Error),
        );
        break;
    }
}

pub struct Unvalidated;
pub struct Validated {
    court_id: String,
    endpoint: Option<String>,
}

pub struct SESEvent<'a, ValidationState>(&'a SimpleEmailService, ValidationState);

impl<'a> From<&'a SimpleEmailService> for SESEvent<'a, Unvalidated> {
    fn from(event: &'a SimpleEmailService) -> Self {
        Self(event, Unvalidated)
    }
}

impl<'a, VS> From<SESEvent<'a, VS>> for &'a SimpleEmailService {
    fn from(event: SESEvent<'a, VS>) -> Self {
        event.0
    }
}

impl<'a, VS> SESEvent<'a, VS> {
    pub fn email(&self) -> &SimpleEmailMessage {
        &self.0.mail
    }

    pub fn receipt(&self) -> &SimpleEmailReceipt {
        &self.0.receipt
    }

    /// Extract values for the header with name [`header_name`] from an SES email payload.
    #[must_use]
    pub fn get_header(&self, key: &'a str) -> Vec<Option<&'a str>> {
        self.0
            .mail
            .headers
            .iter()
            .filter(|header| {
                header
                    .name
                    .as_ref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(key))
            })
            .map(|header| header.value.as_deref())
            .collect()
    }

    #[must_use]
    pub fn get_combined_log_message(&self) -> String {
        let subjects = self.get_header("Subject");
        let subject = subjects.last().and_then(|subject| subject.as_deref());

        format!(
            "Email ID {:?} with {subject:?}, from {:?} to {:?}",
            self.0.mail.message_id, self.0.mail.source, self.0.mail.destination
        )
    }

    /// Return the registrable domain from the email's `"Return-Path"` header,
    /// or None if no `"Return-Path"` is present or parseable.
    #[must_use]
    pub fn get_source_domain(&self) -> Option<&'a str> {
        self.get_header("Return-Path")
            .iter()
            .filter_map(|v| v.and_then(EmailAddress::parse_str))
            .map(|email_address| email_address.domain())
            .next()
    }
}

impl<'a> SESEvent<'a, Unvalidated> {
    fn verdict_require_pass(
        &self,
        verdict: &SimpleEmailVerdict,
        failure: ValidationFailure,
    ) -> Result<(), Response> {
        match &verdict.status {
            Some(status) => {
                if status == "PASS" {
                    Ok(())
                } else {
                    Err(Response::dependency_failure(self, failure))
                }
            }
            None => Ok(()),
        }
    }

    fn verdict_require_pass_or_gray(
        &self,
        verdict: &SimpleEmailVerdict,
        failure: ValidationFailure,
    ) -> Result<(), Response> {
        match &verdict.status {
            Some(status) => {
                if status == "PASS" || status == "GRAY" {
                    Ok(())
                } else {
                    Err(Response::dependency_failure(self, failure))
                }
            }
            None => Ok(()),
        }
    }

    /// Consume and validate this SES event. Performs all necessary validation before the event can
    /// be sent to CourtListener.
    ///
    /// # Errors
    /// Will return an error if any validation step fails.
    pub fn validate(self) -> Result<SESEvent<'a, Validated>, Response> {
        self.verdict_require_pass(&self.0.receipt.spam_verdict, ValidationFailure::Spam)?;
        self.verdict_require_pass(&self.0.receipt.virus_verdict, ValidationFailure::Virus)?;
        self.verdict_require_pass_or_gray(&self.0.receipt.spf_verdict, ValidationFailure::Spf)?;
        self.verdict_require_pass_or_gray(&self.0.receipt.dmarc_verdict, ValidationFailure::Dmarc)?;
        self.verdict_require_pass_or_gray(&self.0.receipt.dkim_verdict, ValidationFailure::Dkim)?;

        let endpoint_map = EndpointMap::default();
        let email_map = EmailMap::default();

        if !endpoint_map.is_valid_domain(&self.get_header("Return-Path")) {
            return Err(Response::dependency_failure(
                &self,
                ValidationFailure::Domain,
            ));
        }

        if !email_map.destination_matches_subscription(&self) {
            warn!(
                "{} ignored — destination does not match the required subscription subdomain for \
                 its source domain.",
                self.get_combined_log_message()
            );
            return Err(Response {
                status_code: 200,
                failure: Err(ValidationFailure::Subscription),
                body: serde_json::to_value(&self.0.receipt)
                    .unwrap_or(json!({"error": "Failed to serialize message receipt"})),
            });
        }

        let court_id = match email_map.email_to_cl_id(&self) {
            Ok(id) => id,
            Err(e) => return Err(Response::dependency_failure(&self, e)),
        };
        if email_map.ignored_subdomains.contains(&court_id.as_str()) {
            return Err(Response::dependency_failure(
                &self,
                ValidationFailure::Email,
            ));
        }


        Ok(SESEvent(
            self.0,
            Validated {
                court_id,
                endpoint: endpoint_map.get_cl_endpoint(&self.get_header("Return-Path")),
            },
        ))
    }
}

impl SESEvent<'_, Validated> {
    /// Send an event which has passed validation to the CourtListener endpoint for the given court.
    ///
    /// # Errors
    /// Will return an error if the send attempt fails all retries or if no CourtListener endpoint
    /// is configured for this event.
    pub async fn send_to_court_listener(&self) -> Result<Response, Error> {
        let endpoint = self
            .1
            .endpoint
            .clone()
            .ok_or("no CourtListener endpoint configured")?;
        utils::retry(is_retryable, 5, 10, 3, || async {
            println!(
                "{} sending to Court Listener API.",
                self.get_combined_log_message()
            );

            // DEV DOMAIN: http://host.docker.internal:8000
            let court_listener_response = reqwest::Client::new()
                .post(&endpoint)
                .json(&CLPayload::from(self))
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

            log_invalid_court_error(status_code, &response_json, &self.email().message_id);

            println!("Got status_code={status_code} and content {response_json}");

            Ok(Response {
                status_code: 200,
                failure: Ok(()),
                body: response_json,
            })
        })
        .await
    }
}

#[derive(Serialize)]
pub struct CLPayload<'a> {
    mail: &'a SimpleEmailMessage,
    receipt: &'a SimpleEmailReceipt,
    court: &'a str,
}

impl<'a> From<&'a SESEvent<'a, Validated>> for CLPayload<'a> {
    fn from(event: &'a SESEvent<'a, Validated>) -> Self {
        Self {
            mail: &event.0.mail,
            receipt: &event.0.receipt,
            court: &event.1.court_id,
        }
    }
}


fn is_retryable(e: &Error) -> bool {
    e.downcast_ref::<reqwest::Error>()
        .is_some_and(|e| e.is_connect() || e.is_timeout() || e.is_status())
}

/// Forward an SES email event to the appropriate CourtListener endpoint if it is valid.
///
/// # Errors
/// Will return an error if the event is valid, but fails to successfully send to CourtListener.
pub async fn handler(event: LambdaEvent<SimpleEmailEvent>) -> Result<Response, Error> {
    let Some(ses_event) = event
        .payload
        .records
        .first()
        .map(|r| SESEvent::from(&r.ses))
    else {
        return Ok(Response::source_missing_failure());
    };

    let ses_event = match ses_event.validate() {
        Ok(ses_event) => ses_event,
        Err(response) => return Ok(response),
    };

    ses_event.send_to_court_listener().await
}
