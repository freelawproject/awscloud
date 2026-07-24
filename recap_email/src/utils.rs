use std::fmt::Formatter;
use std::future::Future;
use std::time::Duration;

use lambda_runtime::Error;
use serde::{
    Serialize,
    Serializer,
};

/// Retry calling the decorated function using an exponential backoff.
///
/// - [`exception_to_check`] Returns true if the given error value should be retried.
/// - [`tries`] The maximum number of times to attempt the function.
/// - [`delay`] The amount of time (in seconds) to wait between tries.
/// - [`backoff`] The factor to multiply [`delay`] by after each try.
/// - [`f`] The future to retry.
///
/// # Errors
/// After all retries are exhausted, will return the final output of [`f`], which may be an error.
pub async fn retry<T, F, Fut>(
    exception_to_check: fn(&Error) -> bool,
    tries: u32,
    delay: u64,
    backoff: u64,
    f: F,
) -> Result<T, Error>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, Error>>,
{
    let mut mtries = tries;
    let mut mdelay = delay;
    while mtries > 1 {
        match f().await {
            Ok(value) => return Ok(value),
            Err(e) if exception_to_check(&e) => {
                println!("{e}, Retrying in {mdelay} seconds...");
                tokio::time::sleep(Duration::from_secs(mdelay)).await;
                mtries -= 1;
                mdelay *= backoff;
            }
            Err(e) => return Err(e),
        }
    }
    f().await
}

/// Structure for zero-copy email parsing.
#[derive(Clone)]
pub struct EmailAddress<'a> {
    value: &'a str,
    at_index: usize,
    dot_indices: Vec<usize>,
}

impl std::fmt::Debug for EmailAddress<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "EmailAddress({:?})", self.value)
    }
}

impl Serialize for EmailAddress<'_> {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(self.value)
    }
}

impl<'a> EmailAddress<'a> {
    /// Parse a given string into an email of the form
    ///
    /// ```
    /// [<]<name>@[subdomain.]<domain>[>]
    /// ```
    #[must_use]
    pub fn parse_str(email: &'a str) -> Option<Self> {
        let value = email.trim();
        let email_clean = match value.rfind('<') {
            Some(start) => {
                let rest = &value[start + 1..];
                rest.strip_suffix('>').unwrap_or(rest).trim()
            }
            None => value,
        };
        let at_index = email_clean.find('@')?;
        Some(Self {
            value: email_clean,
            at_index,
            dot_indices: email_clean[at_index..]
                .char_indices()
                .filter(|(_, c)| *c == '.')
                .map(|(i, _)| at_index + i)
                .collect(),
        })
    }

    /// Get the name component of this email (the part before "@").
    #[must_use]
    pub fn name(&self) -> &'a str {
        &self.value[..self.at_index]
    }

    /// Get the address component of this email (the part after "@").
    #[must_use]
    pub fn address(&self) -> &'a str {
        &self.value[self.at_index + 1..]
    }

    #[must_use]
    #[inline]
    fn subdomain_index(&self) -> usize {
        if self.dot_indices.len() < 2 {
            self.at_index
        } else {
            *self.dot_indices.iter().nth_back(1).unwrap()
        }
    }

    /// Get the subdomain of the address component (i.e. "tx" in "tx.uscourts.gov").
    #[must_use]
    pub fn subdomain(&self) -> &'a str {
        let end = self.subdomain_index();
        &self.value[(self.at_index + 1)..end]
    }

    /// Get the domain of the address component (i.e. "uscourts.gov" in "tx.uscourts.gov").
    #[must_use]
    pub fn domain(&self) -> &'a str {
        let start = self.subdomain_index();
        &self.value[(start + 1)..]
    }
}
