//! Mapping between PACER/court email identifiers and CourtListener court ids,
//! including the special handling for shared domains and Texas courts.

use std::borrow::Cow;
use std::collections::HashMap;

use regex::regex;

use crate::app::{
    SESEvent,
    Unvalidated,
    ValidationFailure,
};
use crate::utils::EmailAddress;

/// Lookup tables for translating a court's email identifiers into a
/// CourtListener court id, plus the metadata needed to disambiguate shared
/// and mismatched domains.
pub struct EmailMap {
    /// Source subdomains that are not real NEF origins and should be ignored.
    pub ignored_subdomains: Vec<&'static str>,
    /// Direct map from a full source domain to its CourtListener court id.
    pub domain_to_cl_id: HashMap<&'static str, &'static str>,
    /// Map from a PACER court id to its (differing) CourtListener court id.
    pub pacer_to_cl_id: HashMap<&'static str, &'static str>,
    /// Maps a court source domain to the subscription subdomain that must receive
    /// its emails. Emails from these domains that arrive via a different SES rule
    /// (e.g., the generic recap.email rule) are ignored to avoid double processing.
    pub domain_to_subscription: HashMap<&'static str, &'static str>,
    /// PACER email subdomains shared by more than one court, mapped to the PACER
    /// court ids whose NEFs legitimately originate from that domain. Only these
    /// domains may have their From court overridden by the ECF host found
    /// in the Received headers.
    pub shared_domain_courts: HashMap<&'static str, Vec<&'static str>>,
}

impl Default for EmailMap {
    fn default() -> Self {
        Self {
            // Notice that MIWD (uppercase) was found not to be a NEF. This differentiates it
            // from miwd (lowercase), which is related to actual NEFs.
            ignored_subdomains: vec!["usdoj", "law", "psc", "updates", "MIWD"],
            domain_to_cl_id: HashMap::from([
                ("sc-us.gov", "scotus"),   // Supreme Court of the United States
                ("txcourts.gov", "texas"), // All Texas courts
            ]),
            pacer_to_cl_id: HashMap::from([
                ("azb", "arb"),        // Arizona Bankruptcy Court
                ("cofc", "uscfc"),     // Court of Federal Claims
                ("neb", "nebraskab"),  // Nebraska Bankruptcy
                ("nysb-mega", "nysb"), // Remove the mega thing
                ("txs", "txsd"),       // Southern District Of Texas
                ("mow", "mowd"),       // Western District of Missouri
                ("gas", "gasd"),       // Southern District of Georgia
                ("cfc", "uscfc"),      // Court of Federal Claims
                ("id", "idd"),         // District Court, D. Idaho
            ]),
            domain_to_subscription: HashMap::from([
                ("sc-us.gov", "scotus.recap.email"),
                ("txcourts.gov", "texas.recap.email"),
            ]),
            shared_domain_courts: HashMap::from([
                ("txs", vec!["txsd", "txsb"]), // S.D. Tex. district and bankruptcy
            ]),
        }
    }
}

impl EmailMap {
    /// Translate a PACER court id to its CourtListener court id, returning the
    /// input unchanged when there is no override.
    #[must_use]
    pub fn pacer_to_cl_id<'a>(&self, pacer_id: &'a str) -> &'a str {
        self.pacer_to_cl_id
            .get(pacer_id)
            .copied()
            .unwrap_or(pacer_id)
    }

    /// Translate a CourtListener court id back to its PACER court id, returning
    /// the input unchanged when there is no override.
    #[must_use]
    pub fn cl_to_pacer_id<'a>(&self, cl_id: &'a str) -> &'a str {
        if cl_id == "nysb" {
            return cl_id;
        }
        self.pacer_to_cl_id
            .iter()
            .find(|(_, cl)| **cl == cl_id)
            .map_or(cl_id, |(pacer, _)| *pacer)
    }

    /// Map an email address's domain to a CourtListener court id via
    /// [`Self::domain_to_cl_id`], returning the domain unchanged when unknown.
    #[must_use]
    pub fn email_address_to_cl_id<'a>(&self, email: &EmailAddress<'a>) -> &'a str {
        self.domain_to_cl_id
            .get(email.domain())
            .copied()
            .unwrap_or(email.domain())
    }

    /// Extract the PACER court id from the originating ECF database hostname
    /// in the email's Received headers.
    ///
    /// The last regex match across the concatenated Received headers is the one
    /// closest to the originating server, since each relay prepends its header.
    ///
    /// Returns the lowercase PACER court id, or None if no ECF database host is
    /// present (e.g. non-NEF mail from court staff or mailing lists).
    #[must_use]
    pub fn get_ecf_host_court<VS>(event: &SESEvent<VS>) -> Option<String> {
        // Matches the originating ECF database hostname that courts stamp into the
        // earliest Received headers of every NEF, e.g. "txsbdb.txsb.gtwy.dcn". The
        // "<name>db." prefix is required so generic court mail relays under gtwy.dcn
        // (e.g. "smtp2-i.asbn.gtwy.dcn") don't match.
        let ecf_host_re = regex!(r"(?i)\b[a-z0-9]+db\.([a-z0-9]+)\.gtwy\.dcn");
        event
            .get_header("Received")
            .iter()
            .rev()
            .filter_map(Clone::clone)
            .find_map(|v| ecf_host_re.captures(v))
            .and_then(|captures| captures.get(1).map(|m| m.as_str().to_lowercase()))
    }

    /// Attempts to map a case update email address to a CL Court ID.
    ///
    /// # Errors
    /// Will return an error message if:
    /// - The common `"From"` header is missing.
    /// - The first `"From"` email address failed to parse.
    /// - The email is from Texas, but wasn't a recognized format.
    pub fn email_to_cl_id<'a, VS>(
        &self,
        event: &'a SESEvent<'a, VS>,
    ) -> Result<Cow<'a, str>, ValidationFailure> {
        let from_addr = EmailAddress::parse_str(
            event
                .email()
                .common_headers
                .from
                .first()
                .ok_or(ValidationFailure::MissingCommonFrom)?,
        )
        .ok_or(ValidationFailure::AddressParsingFailed)?;
        let domain = from_addr.domain();
        if domain == "fedcourts.us" || domain == "uscourts.gov" {
            let pacer_id = from_addr.subdomain();
            let pacer_id_lower = pacer_id.to_lowercase();
            let from_court = self.pacer_to_cl_id(pacer_id);
            let from_court_lower = self.pacer_to_cl_id(&pacer_id_lower);
            let Some(ecf_court) = Self::get_ecf_host_court(event) else {
                return Ok(Cow::from(from_court));
            };
            let ecf_cl_court = self.pacer_to_cl_id(&ecf_court);
            // Compare mapped CL courts, not raw subdomains: courts like gas or
            // mow use a From subdomain that differs from their ECF host court
            // (gasddb.gasd.gtwy.dcn) but both resolve to the same CL court in
            // pacer_to_cl_id.
            if ecf_cl_court != from_court_lower {
                if let Some(shared_courts) = self.shared_domain_courts.get(pacer_id_lower.as_str())
                    && shared_courts.contains(&ecf_court.as_str())
                {
                    return Ok(Cow::from(ecf_cl_court.to_string()));
                }
                sentry::with_scope(
                    |scope| scope.set_fingerprint(Some(&["ecf-host-court-mismatch"])),
                    || {
                        sentry::capture_message(
                            &format!(
                                "ECF host court mismatch: From-derived court '{pacer_id}' vs ECF \
                                 host court '{ecf_court}' - message_id: {}",
                                event.email().message_id.clone().unwrap_or_default(),
                            ),
                            sentry::Level::Error,
                        )
                    },
                );
            }
            return Ok(Cow::from(from_court));
        }
        let cl_id = self.email_address_to_cl_id(&from_addr);
        if cl_id == "texas" {
            let subject = event
                .email()
                .common_headers
                .subject
                .clone()
                .ok_or(ValidationFailure::MissingCommonSubject)?;
            return Ok(Cow::from(get_tx_court_id_from_subject(&subject)?));
        }
        Ok(Cow::from(cl_id))
    }

    /// Return `true` if the email should be processed, `false` if it should be
    /// ignored because its source domain requires a specific subscription
    /// subdomain (e.g., scotus.recap.email) but the destination does not use it.
    ///
    /// Specifically, if any address in the email's destination list matches the
    /// expected destination for the given source domain, return True. Otherwise,
    /// return `false`. This lets us handle potential emails with multiple destinations
    /// correctly.
    #[must_use]
    pub fn destination_matches_subscription(&self, event: &SESEvent<Unvalidated>) -> bool {
        let Some(source_domain) = event.get_source_domain() else {
            return true;
        };
        let Some(required) = self.domain_to_subscription.get(source_domain) else {
            return true;
        };

        for destination in &event.email().destination {
            let Some(address) = EmailAddress::parse_str(destination) else {
                continue;
            };
            let dest_domain = &address.address().to_lowercase();

            if dest_domain == required || dest_domain.ends_with(&format!(".{required}")) {
                return true;
            }
        }
        false
    }
}


/// Map an email subject line to a Texas CL Court ID.
///
/// # Errors
/// Returns an error message the subject line format or the court name extracted from it is
/// unrecognized.
pub fn get_tx_court_id_from_subject(subject: &str) -> Result<&'static str, ValidationFailure> {
    let prefix = "Automated Case Update from ";
    if !subject.starts_with(prefix) {
        return Err(ValidationFailure::UnrecognizedSubject);
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
        _ => Err(ValidationFailure::UnrecognizedCourt),
    }
}
