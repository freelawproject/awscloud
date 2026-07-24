//! AWS Lambda that routes incoming PACER/court notification emails delivered
//! via Amazon SES to the appropriate CourtListener API endpoint.
//!
//! An SES event is validated (spam/virus/SPF/DKIM/DMARC verdicts, source
//! domain, and subscription), mapped to a CourtListener court id, and then
//! forwarded to the matching CourtListener endpoint.
#![warn(missing_docs)]

pub mod app;
pub mod pacer;
pub mod utils;
