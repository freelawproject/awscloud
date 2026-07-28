//! The Lambda request handler and the SES event validation/forwarding
//! pipeline.
//!
//! [`handler`] is the Lambda entry point. It wraps an incoming SES record in a
//! typestate [`SESEvent`], validates it, and forwards the validated event to
//! the appropriate CourtListener endpoint.

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
    info,
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
use tower::{
    Service,
    ServiceBuilder,
    ServiceExt,
    retry,
};

use crate::pacer::EmailMap;
use crate::utils::EmailAddress;

/// A reason an SES event was rejected during validation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ValidationFailure {
    /// The SES spam verdict did not pass.
    Spam,
    /// The SES virus verdict did not pass.
    Virus,
    /// The SES SPF verdict was neither `PASS` nor `GRAY`.
    Spf,
    /// The SES DKIM verdict was neither `PASS` nor `GRAY`.
    Dkim,
    /// The SES DMARC verdict was neither `PASS` nor `GRAY`.
    Dmarc,
    /// The `Return-Path` domain is not one we accept updates from.
    Domain,
    /// The record's event source was not `aws:ses`.
    EventSourceMissing,
    /// The destination did not match the subscription subdomain required for
    /// the source domain, so the email was ignored to avoid double processing.
    Subscription,
    /// The resolved court is an ignored subdomain (not a real NEF source).
    Email,
    /// A Texas subject line did not have the expected prefix.
    UnrecognizedSubject,
    /// A Texas subject line named a court we could not map to a CL id.
    UnrecognizedCourt,
    /// The email had no `From` address in its common headers.
    MissingCommonFrom,
    /// A Texas email had no `Subject` in its common headers.
    MissingCommonSubject,
    /// The `From` address could not be parsed.
    AddressParsingFailed,
    /// No CourtListener endpoint was configured
    NoCourtListenerEndpoint,
}

impl std::fmt::Display for ValidationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ValidationFailure {}

/// The result of handling an SES event, returned to the Lambda runtime.
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// HTTP-style status code describing the outcome.
    pub status_code: u16,
    /// `None` when the event was accepted, otherwise the reason it was rejected.
    pub failure: Option<ValidationFailure>,
    /// The response body: the CourtListener response, or the SES receipt when
    /// the event was rejected before being forwarded.
    pub body: Value,
}

impl Response {
    /// Build a `200 OK` response wrapping the given body.
    #[must_use]
    pub fn success(body: Value) -> Response {
        Self {
            status_code: 200,
            failure: None,
            body,
        }
    }

    /// Build a `415` response for records that are not `aws:ses` events.
    #[must_use]
    pub fn source_missing_failure() -> Response {
        Self {
            status_code: 415,
            failure: Some(ValidationFailure::EventSourceMissing),
            body: json!({"message": "PACER email receipt requires aws:ses eventSource."}),
        }
    }

    /// Build a `424` response for an event that failed a validation check,
    /// logging the failure and echoing back the SES receipt.
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
            failure: Some(failure),
            body: serde_json::to_value(event.receipt())
                .unwrap_or(json!({"error": "Failed to serialize message receipt"})),
        }
    }
}

/// Maps court source domains to their CourtListener API endpoints, read from
/// the `RECAP_EMAIL_ENDPOINT`, `SCOTUS_EMAIL_ENDPOINT`, and
/// `TEXAS_EMAIL_ENDPOINT` environment variables.
pub struct EndpointMap {
    recap_endpoint: Option<String>,
    cl_endpoints: HashMap<&'static str, Option<String>>,
}

impl EndpointMap {
    /// Initialize based on the `RECAP_EMAIL_ENDPOINT`, `SCOTUS_EMAIL_ENDPOINT`, and
    /// `TEXAS_EMAIL_ENDPOINT` environment variables
    #[must_use]
    pub fn from_env() -> EndpointMap {
        let recap_endpoint = env::var("RECAP_EMAIL_ENDPOINT").ok();
        let scotus_email_endpoint = env::var("SCOTUS_EMAIL_ENDPOINT").ok();
        let texas_email_endpoint = env::var("TEXAS_EMAIL_ENDPOINT").ok();
        Self {
            cl_endpoints: HashMap::from([
                ("sc-us.gov", scotus_email_endpoint),
                ("fedcourts.us", recap_endpoint.clone()),
                ("uscourts.gov", recap_endpoint.clone()),
                ("txcourts.gov", texas_email_endpoint),
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
    /// `recap_endpoint`.
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
            .or_else(|| self.recap_endpoint.clone())
    }

    /// Check whether an email address is one we accept updates from.
    #[must_use]
    pub fn check_valid_domain(&self, email_address: &str) -> bool {
        EmailAddress::parse_str(email_address)
            .is_some_and(|email| self.cl_endpoints.contains_key(email.domain()))
    }

    /// Check whether every supplied `Return-Path` address comes from a domain
    /// we accept updates from.
    #[must_use]
    pub fn is_valid_domain(&self, addrs: &[Option<&str>]) -> bool {
        addrs
            .iter()
            .filter_map(|v| *v)
            .all(|email_address| self.check_valid_domain(email_address))
    }
}

/// Checks if the response indicates an invalid court pk then send a report
/// to Sentry.
pub fn log_invalid_court_error(status_code: u16, response_json: &Value, message_id: &Option<&str>) {
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
            message_id.as_deref().unwrap_or_default()
        );
        sentry::with_scope(
            |scope| scope.set_fingerprint(Some(&["invalid-court-pk"])),
            || sentry::capture_message(&error_message, sentry::Level::Error),
        );
        break;
    }
}

/// Typestate marker for an [`SESEvent`] that has not yet been validated.
pub struct Unvalidated;

/// Typestate marker for an [`SESEvent`] that has passed validation, carrying
/// the resolved court id and its CourtListener endpoint.
pub struct Validated {
    court_id: String,
    endpoint: String,
}

/// A borrowed SES email paired with a typestate marker (`Unvalidated` or
/// `Validated`) that tracks whether it has passed validation.
pub struct SESEvent<'a, ValidationState>(&'a SimpleEmailService, ValidationState);

impl<'a> From<&'a SimpleEmailService> for SESEvent<'a, Unvalidated> {
    fn from(event: &'a SimpleEmailService) -> Self {
        Self(event, Unvalidated)
    }
}

impl<'a, VS> SESEvent<'a, VS> {
    /// Borrow the underlying SES message.
    pub fn email(&self) -> &SimpleEmailMessage {
        &self.0.mail
    }

    /// Borrow the SES receipt (spam/virus/SPF/DKIM/DMARC verdicts).
    pub fn receipt(&self) -> &SimpleEmailReceipt {
        &self.0.receipt
    }

    /// Extract values for the header with name `key` from an SES email payload.
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

    /// Build a human-readable one-line summary of the email (id, subject,
    /// source, and destination) for logging.
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
    pub fn get_source_domain(&self) -> Option<String> {
        self.get_header("Return-Path")
            .iter()
            .filter_map(|v| v.and_then(EmailAddress::parse_str))
            .map(|email_address| email_address.domain().to_lowercase())
            .next()
    }
}

impl<'a> SESEvent<'a, Unvalidated> {
    fn require_verdict(
        &self,
        verdict: &SimpleEmailVerdict,
        verdicts: &[&str],
        failure: ValidationFailure,
    ) -> Result<(), Response> {
        match &verdict.status {
            Some(status) => {
                if verdicts.contains(&status.as_str()) {
                    Ok(())
                } else {
                    Err(Response::dependency_failure(self, failure))
                }
            }
            None => Err(Response::dependency_failure(self, failure)),
        }
    }

    /// Consume and validate this SES event. Performs all necessary validation before the event can
    /// be sent to CourtListener.
    ///
    /// # Errors
    /// Will return an error if any validation step fails.
    pub fn validate(self) -> Result<SESEvent<'a, Validated>, Response> {
        self.require_verdict(
            &self.0.receipt.spam_verdict,
            &["PASS"],
            ValidationFailure::Spam,
        )?;
        self.require_verdict(
            &self.0.receipt.virus_verdict,
            &["PASS"],
            ValidationFailure::Virus,
        )?;
        self.require_verdict(
            &self.0.receipt.spf_verdict,
            &["PASS", "GRAY"],
            ValidationFailure::Spf,
        )?;
        self.require_verdict(
            &self.0.receipt.dmarc_verdict,
            &["PASS", "GRAY"],
            ValidationFailure::Dmarc,
        )?;
        self.require_verdict(
            &self.0.receipt.dkim_verdict,
            &["PASS", "GRAY"],
            ValidationFailure::Dkim,
        )?;

        let endpoint_map = EndpointMap::from_env();
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
                failure: Some(ValidationFailure::Subscription),
                body: serde_json::to_value(&self.0.receipt)
                    .unwrap_or(json!({"error": "Failed to serialize message receipt"})),
            });
        }

        let court_id = match email_map.email_to_cl_id(&self) {
            Ok(id) => id.to_string(),
            Err(e) => return Err(Response::dependency_failure(&self, e)),
        };
        if email_map.ignored_subdomains.contains(&&*court_id) {
            return Err(Response::dependency_failure(
                &self,
                ValidationFailure::Email,
            ));
        }

        let Some(endpoint) = endpoint_map.get_cl_endpoint(&self.get_header("Return-Path")) else {
            return Err(Response::dependency_failure(
                &self,
                ValidationFailure::NoCourtListenerEndpoint,
            ));
        };

        Ok(SESEvent(self.0, Validated { court_id, endpoint }))
    }
}

/// Defines an exponential backoff retry policy for sending `POST` requests to CourtListener.
#[derive(Debug, Clone)]
struct CLSendRetryPolicy {
    delay: Duration,
    backoff: f32,
    max_tries: u32,
    current_try: u32,
}

impl CLSendRetryPolicy {
    /// Create an exponential backoff retry policy with a base wait time of `delay`, which is
    /// increased after each failed attempt by a factor of `backoff` with at most `max_tries`
    /// attempts.
    pub fn new(delay: Duration, backoff: f32, max_tries: u32) -> Self {
        // Divide `delay` by backoff to start so we don't have to branch in `retry`.
        Self {
            delay: delay.div_f32(backoff),
            backoff,
            max_tries,
            current_try: 0,
        }
    }
}

impl retry::Policy<reqwest::Request, reqwest::Response, reqwest::Error> for CLSendRetryPolicy {
    type Future = tokio::time::Sleep;

    fn retry(
        &mut self,
        _: &mut reqwest::Request,
        result: &mut Result<reqwest::Response, reqwest::Error>,
    ) -> Option<Self::Future> {
        self.current_try += 1;
        self.delay = self.delay.mul_f32(self.backoff);
        if self.current_try >= self.max_tries {
            return None;
        }

        match result {
            Err(e) if e.is_connect() || e.is_timeout() || e.is_status() => {
                Some(tokio::time::sleep(self.delay))
            }
            Ok(_) | Err(_) => None,
        }
    }

    fn clone_request(&mut self, req: &reqwest::Request) -> Option<reqwest::Request> {
        req.try_clone()
    }
}

impl SESEvent<'_, Validated> {
    /// Send an event which has passed validation to the CourtListener endpoint for the given court.
    ///
    /// # Errors
    /// Will return an error if:
    /// - The send attempt fails all retries;
    /// - the response status is one of 502, 503, or 504;
    /// - or we fail to parse the response as JSON.
    pub async fn send_to_court_listener(&self) -> Result<Response, Error> {
        let client = reqwest::Client::new();
        // DEV DOMAIN: http://host.docker.internal:8000
        let endpoint = self.1.endpoint.as_str();
        let request = client
            .post(endpoint)
            .json(&CLPayload::from(self))
            .timeout(Duration::from_secs(5))
            .header(
                "Authorization",
                format!(
                    "Token {}",
                    env::var("AUTH_TOKEN").unwrap_or_else(|_| "None".to_string())
                ),
            )
            .build()?;

        let service = ServiceBuilder::new()
            .retry(CLSendRetryPolicy::new(Duration::from_secs(10), 3.0, 5))
            .map_result(
                |result: Result<reqwest::Response, reqwest::Error>| match result {
                    Ok(response) => {
                        Ok(if [502, 503, 504].contains(&response.status().as_u16()) {
                            // Raise an HTTPError for Bad Gateway, Service Unavailable or
                            // Gateway Timeout status codes.
                            response.error_for_status()?
                        } else {
                            response
                        })
                    }
                    Err(e) => Err(e),
                },
            )
            .service(client)
            .and_then(async |response: reqwest::Response| {
                let status = response.status().as_u16();
                let json = response.json().await?;

                log_invalid_court_error(status, &json, &self.email().message_id.as_deref());

                println!("Got status_code={status} and content {json}");

                Ok(Response {
                    status_code: 200,
                    failure: None,
                    body: json,
                })
            });

        info!(
            "{} sending to Court Listener API.",
            self.get_combined_log_message()
        );

        service.oneshot(request).await
    }
}

/// The JSON body posted to the CourtListener endpoint: the SES message and
/// receipt plus the resolved CourtListener court id.
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
