import re
from email.utils import parseaddr

import sentry_sdk

pacer_to_cl_ids = {
    # Maps PACER ids to their CL equivalents
    "azb": "arb",  # Arizona Bankruptcy Court
    "cofc": "uscfc",  # Court of Federal Claims
    "neb": "nebraskab",  # Nebraska Bankruptcy
    "nysb-mega": "nysb",  # Remove the mega thing
    "txs": "txsd",  # Southern District Of Texas
    "mow": "mowd",  # Western District of Missouri
    "gas": "gasd",  # Southern District of Georgia
    "cfc": "uscfc",  # Court of Federal Claims
    "id": "idd",  # District Court, D. Idaho
}

sub_domains_to_ignore = ["usdoj", "law", "psc", "updates", "MIWD"]

# Reverse dict of pacer_to_cl_ids
cl_to_pacer_ids = {v: k for k, v in pacer_to_cl_ids.items()}


def map_pacer_to_cl_id(pacer_id):
    return pacer_to_cl_ids.get(pacer_id, pacer_id)


def map_cl_to_pacer_id(cl_id):
    if cl_id == "nysb":
        return cl_id
    return cl_to_pacer_ids.get(cl_id, cl_id)


def get_tx_court_id_from_subject(subject: str) -> str:
    """
    Map an email subject line to a Texas CL Court ID. Raises an exception if
    the subject or the court name extracted from it is not recognized.

    :param subject: The email subject line.

    :return: CL Court ID.
    """
    court_map = {
        "first court of appeals": "txctapp1",
        "second court of appeals": "txctapp2",
        "third court of appeals": "txctapp3",
        "fourth court of appeals": "txctapp4",
        "fifth court of appeals": "txctapp5",
        "sixth court of appeals": "txctapp6",
        "seventh court of appeals": "txctapp7",
        "eighth court of appeals": "txctapp8",
        "ninth court of appeals": "txctapp9",
        "tenth court of appeals": "txctapp10",
        "eleventh court of appeals": "txctapp11",
        "twelfth court of appeals": "txctapp12",
        "thirteenth court of appeals": "txctapp13",
        "fourteenth court of appeals": "txctapp14",
        "fifteenth court of appeals": "txctapp15",
        "court of criminal appeals": "texcrimapp",
        "supreme court": "tex",
    }
    prefix = "Automated Case Update from "
    if not subject.startswith(prefix):
        raise KeyError(f"Texas: Invalid subject {subject}")
    court_name = subject.removeprefix(prefix).lower()
    return court_map[court_name]


# Matches the originating ECF database hostname that courts stamp into the
# earliest Received headers of every NEF, e.g. "txsbdb.txsb.gtwy.dcn". The
# "<name>db." prefix is required so generic court mail relays under gtwy.dcn
# (e.g. "smtp2-i.asbn.gtwy.dcn") don't match.
ecf_host_re = re.compile(
    r"\b[a-z0-9]+db\.([a-z0-9]+)\.gtwy\.dcn", re.IGNORECASE
)

# PACER email subdomains shared by more than one court, mapped to the PACER
# court ids whose NEFs legitimately originate from that domain. Only these
# domains may have their From court overridden by the ECF host found
# in the Received headers.
shared_domain_courts = {
    "txs": {"txsd", "txsb"},  # S.D. Tex. district and bankruptcy
}


def get_ecf_host_court(email):
    """Extract the PACER court id from the originating ECF database hostname
    in the email's Received headers.

    The last regex match across the concatenated Received headers is the one
    closest to the originating server, since each relay prepends its header.

    :param email: Object containing email content and metadata.

    :return: The lowercase PACER court id, or None if no ECF database host is
    present (e.g. non-NEF mail from court staff or mailing lists).
    """
    received = " ".join(
        header["value"]
        for header in email.get("headers", [])
        if header["name"] == "Received"
    )
    matches = ecf_host_re.findall(received)
    if not matches:
        return None
    return matches[-1].lower()


domain_to_cl_id = {
    "sc-us.gov": "scotus",  # Supreme Court of the United States
    "txcourts.gov": "texas",  # All Texas courts
}

# Maps a court source domain to the subscription subdomain that must receive
# its emails. Emails from these domains that arrive via a different SES rule
# (e.g., the generic recap.email rule) are ignored to avoid double processing.
domain_to_subscription_subdomain = {
    "sc-us.gov": "scotus.recap.email",
    "txcourts.gov": "texas.recap.email",
}


def map_email_to_cl_id(email):
    """
    Attempts to map a case update email address to a CL Court ID. Will raise an
    exception if the email domain is not recognized.

    :param email: Object containing email content and metadata.

    :return: CL Court ID.
    """
    from_addr = email["common_headers"]["from"][0]
    full_domain = parseaddr(from_addr)[1].split("@")[1]
    parts = full_domain.split(".")
    domain = ".".join(parts[-2:])
    if domain in {"fedcourts.us", "uscourts.gov"}:
        pacer_id = parts[0]
        pacer_id_lower = pacer_id.lower()
        ecf_court = get_ecf_host_court(email)
        # Compare mapped CL courts, not raw subdomains: courts like gas or
        # mow use a From subdomain that differs from their ECF host court
        # (gasddb.gasd.gtwy.dcn) but both resolve to the same CL court in
        # map_pacer_to_cl_id.
        if ecf_court is not None and map_pacer_to_cl_id(
            ecf_court
        ) != map_pacer_to_cl_id(pacer_id_lower):
            if ecf_court in shared_domain_courts.get(pacer_id_lower, set()):
                return map_pacer_to_cl_id(ecf_court)
            message_id = email.get("message_id")
            error_message = (
                f"ECF host court mismatch: From-derived court "
                f"{pacer_id!r} vs ECF host court {ecf_court!r} - "
                f"message_id: {message_id}"
            )
            sentry_sdk.capture_message(
                error_message,
                level="error",
                fingerprint=["ecf-host-court-mismatch"],
            )
        return map_pacer_to_cl_id(pacer_id)
    maybe_cl_id = domain_to_cl_id.get(full_domain, full_domain)
    if maybe_cl_id == "texas":
        return get_tx_court_id_from_subject(email["common_headers"]["subject"])
    return maybe_cl_id
