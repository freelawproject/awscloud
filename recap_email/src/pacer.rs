use std::sync::LazyLock;

use lambda_runtime::Error;
use regex::Regex;
use serde_json::Value;

use crate::utils::extract_address;

// Maps PACER ids to their CL equivalents
pub const PACER_TO_CL_IDS: [(&str, &str); 9] = [
    ("azb", "arb"),        // Arizona Bankruptcy Court
    ("cofc", "uscfc"),     // Court of Federal Claims
    ("neb", "nebraskab"),  // Nebraska Bankruptcy
    ("nysb-mega", "nysb"), // Remove the mega thing
    ("txs", "txsd"),       // Southern District Of Texas
    ("mow", "mowd"),       // Western District of Missouri
    ("gas", "gasd"),       // Southern District of Georgia
    ("cfc", "uscfc"),      // Court of Federal Claims
    ("id", "idd"),         // District Court, D. Idaho
];

// Notice that MIWD (uppercase) was found not to be a NEF. This differentiates it
// from miwd (lowercase), which is related to actual NEFs.
pub const SUB_DOMAINS_TO_IGNORE: [&str; 5] = ["usdoj", "law", "psc", "updates", "MIWD"];

pub fn map_pacer_to_cl_id(pacer_id: &str) -> &str {
    PACER_TO_CL_IDS
        .iter()
        .find(|(pacer, _)| *pacer == pacer_id)
        .map(|(_, cl)| *cl)
        .unwrap_or(pacer_id)
}

pub fn map_cl_to_pacer_id(cl_id: &str) -> &str {
    if cl_id == "nysb" {
        return cl_id;
    }
    PACER_TO_CL_IDS
        .iter()
        .rfind(|(_, cl)| *cl == cl_id)
        .map(|(pacer, _)| *pacer)
        .unwrap_or(cl_id)
}

/// Map an email subject line to a Texas CL Court ID. Raises an exception if
/// the subject or the court name extracted from it is not recognized.
///
/// :param subject: The email subject line.
///
/// :return: CL Court ID.
pub fn get_tx_court_id_from_subject(subject: &str) -> Result<&'static str, Error> {
    let prefix = "Automated Case Update from ";
    if !subject.starts_with(prefix) {
        return Err(format!("Texas: Invalid subject {subject}").into());
    }
    let court_name = subject[prefix.len()..].to_lowercase();
    match court_name.as_str() {
        "first court of appeals" => Ok("txctapp1"),
        "second court of appeals" => Ok("txctapp2"),
        "third court of appeals" => Ok("txctapp3"),
        "fourth court of appeals" => Ok("txctapp4"),
        "fifth court of appeals" => Ok("txctapp5"),
        "sixth court of appeals" => Ok("txctapp6"),
        "seventh court of appeals" => Ok("txctapp7"),
        "eighth court of appeals" => Ok("txctapp8"),
        "ninth court of appeals" => Ok("txctapp9"),
        "tenth court of appeals" => Ok("txctapp10"),
        "eleventh court of appeals" => Ok("txctapp11"),
        "twelfth court of appeals" => Ok("txctapp12"),
        "thirteenth court of appeals" => Ok("txctapp13"),
        "fourteenth court of appeals" => Ok("txctapp14"),
        "fifteenth court of appeals" => Ok("txctapp15"),
        "court of criminal appeals" => Ok("texcrimapp"),
        "supreme court" => Ok("tex"),
        _ => Err(format!("Texas: unknown court name {court_name}").into()),
    }
}

// Matches the originating ECF database hostname that courts stamp into the
// earliest Received headers of every NEF, e.g. "txsbdb.txsb.gtwy.dcn". The
// "<name>db." prefix is required so generic court mail relays under gtwy.dcn
// (e.g. "smtp2-i.asbn.gtwy.dcn") don't match.
static ECF_HOST_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9]+db\.([a-z0-9]+)\.gtwy\.dcn").unwrap());

// PACER email subdomains shared by more than one court, mapped to the PACER
// court ids whose NEFs legitimately originate from that domain. Only these
// domains may have their From court overridden by the ECF host found
// in the Received headers.
pub const SHARED_DOMAIN_COURTS: [(&str, &[&str]); 1] = [
    ("txs", &["txsd", "txsb"]), // S.D. Tex. district and bankruptcy
];

/// Extract the PACER court id from the originating ECF database hostname
/// in the email's Received headers.
///
/// The last regex match across the concatenated Received headers is the one
/// closest to the originating server, since each relay prepends its header.
///
/// :param email: Object containing email content and metadata.
///
/// :return: The lowercase PACER court id, or None if no ECF database host is
/// present (e.g. non-NEF mail from court staff or mailing lists).
pub fn get_ecf_host_court(email: &Value) -> Option<String> {
    let received = crate::app::get_ses_email_headers(email, "Received").join(" ");
    ECF_HOST_RE
        .captures_iter(&received)
        .last()
        .map(|captures| captures[1].to_lowercase())
}

pub const DOMAIN_TO_CL_ID: [(&str, &str); 2] = [
    ("sc-us.gov", "scotus"),   // Supreme Court of the United States
    ("txcourts.gov", "texas"), // All Texas courts
];

// Maps a court source domain to the subscription subdomain that must receive
// its emails. Emails from these domains that arrive via a different SES rule
// (e.g., the generic recap.email rule) are ignored to avoid double processing.
pub const DOMAIN_TO_SUBSCRIPTION_SUBDOMAIN: [(&str, &str); 2] = [
    ("sc-us.gov", "scotus.recap.email"),
    ("txcourts.gov", "texas.recap.email"),
];

/// Attempts to map a case update email address to a CL Court ID. Will raise an
/// exception if the email domain is not recognized.
///
/// :param email: Object containing email content and metadata.
///
/// :return: CL Court ID.
pub fn map_email_to_cl_id(email: &Value) -> Result<String, Error> {
    let from_addr = email["common_headers"]["from"][0]
        .as_str()
        .ok_or("email is missing common_headers.from")?;
    let full_domain = extract_address(from_addr)
        .split('@')
        .nth(1)
        .ok_or("From address has no domain")?;
    let parts: Vec<&str> = full_domain.split('.').collect();
    let domain = parts[parts.len().saturating_sub(2)..].join(".");
    if domain == "fedcourts.us" || domain == "uscourts.gov" {
        let pacer_id = parts[0];
        let pacer_id_lower = pacer_id.to_lowercase();
        let from_court = map_pacer_to_cl_id(pacer_id);
        let from_court_lower = map_pacer_to_cl_id(&pacer_id_lower);
        let ecf_court = get_ecf_host_court(email);
        let ecf_cl_court = ecf_court.as_deref().map(map_pacer_to_cl_id);
        // Compare mapped CL courts, not raw subdomains: courts like gas or
        // mow use a From subdomain that differs from their ECF host court
        // (gasddb.gasd.gtwy.dcn) but both resolve to the same CL court in
        // map_pacer_to_cl_id.
        if let (Some(ecf_court), Some(ecf_cl_court)) = (ecf_court.as_deref(), ecf_cl_court)
            && ecf_cl_court != from_court_lower
        {
            let shared_courts = SHARED_DOMAIN_COURTS
                .iter()
                .find(|(pacer, _)| *pacer == pacer_id_lower)
                .map(|(_, courts)| *courts)
                .unwrap_or(&[]);
            if shared_courts.contains(&ecf_court) {
                return Ok(ecf_cl_court.to_string());
            }
            let message_id = email["message_id"].as_str().unwrap_or("None");
            let error_message = format!(
                "ECF host court mismatch: From-derived court '{pacer_id}' vs ECF host court \
                 '{ecf_court}' - message_id: {message_id}"
            );
            sentry::with_scope(
                |scope| scope.set_fingerprint(Some(&["ecf-host-court-mismatch"])),
                || sentry::capture_message(&error_message, sentry::Level::Error),
            );
        }
        return Ok(from_court.to_string());
    }
    let maybe_cl_id = DOMAIN_TO_CL_ID
        .iter()
        .find(|(known_domain, _)| *known_domain == full_domain)
        .map(|(_, cl_id)| *cl_id)
        .unwrap_or(full_domain);
    if maybe_cl_id == "texas" {
        let subject = email["common_headers"]["subject"]
            .as_str()
            .ok_or("email is missing common_headers.subject")?;
        return Ok(get_tx_court_id_from_subject(subject)?.to_string());
    }
    Ok(maybe_cl_id.to_string())
}
