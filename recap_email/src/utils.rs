use std::future::Future;
use std::time::Duration;

use lambda_runtime::Error;
use serde_json::Value;

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
    mut f: F,
) -> Result<T, Error>
where
    F: FnMut() -> Fut,
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

#[must_use]
pub fn extract_address(email: &str) -> &str {
    let value = email.trim();
    match value.rfind('<') {
        Some(start) => {
            let rest = &value[start + 1..];
            rest.strip_suffix('>').unwrap_or(rest).trim()
        }
        None => value,
    }
}

#[must_use]
pub fn extract_tld(email: &str) -> Option<&str> {
    let address = extract_address(email);
    let i = address.find('@')?;

    let domain = &address[i + 1..];

    let i = domain.char_indices()
        .filter(|(_, c)| *c == '.')
        .nth_back(1)
        .map_or(0, |(i, _)| i + 1);
    Some(&domain[i..])
}

fn decamelize_key(key: &str) -> String {
    let mut out = String::new();
    for c in key.chars() {
        if c.is_ascii_uppercase() {
            if !out.is_empty() {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub fn decamelize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(decamelize).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (decamelize_key(k), decamelize(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}
