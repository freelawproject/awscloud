from email.utils import parseaddr

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


domain_to_cl_id = {
    "sc-us.gov": "scotus",  # Supreme Court of the United States
    "txcourts.gov": "texas",  # All Texas courts
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
        return map_pacer_to_cl_id(parts[0])
    maybe_cl_id = domain_to_cl_id.get(full_domain, full_domain)
    if maybe_cl_id == "texas":
        return get_tx_court_id_from_subject(email["common_headers"]["subject"])
    return maybe_cl_id
