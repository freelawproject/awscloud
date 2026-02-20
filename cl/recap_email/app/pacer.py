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


def get_tx_court_id_from_subject(subject: str) -> str | None:
    if not subject.startswith("Automated Case Update from"):
        return None
    return {
        "First Court of Appeals": "txctapp1",
        "Second Court of Appeals": "txctapp2",
        "Third Court of Appeals": "txctapp3",
        "Fourth Court of Appeals": "txctapp4",
        "Fifth Court of Appeals": "txctapp5",
        "Sixth Court of Appeals": "txctapp6",
        "Seventh Court of Appeals": "txctapp7",
        "Eighth Court of Appeals": "txctapp8",
        "Ninth Court of Appeals": "txctapp9",
        "Tenth Court of Appeals": "txctapp10",
        "Eleventh Court of Appeals": "txctapp11",
        "Twelfth Court of Appeals": "txctapp12",
        "Thirteenth Court of Appeals": "txctapp13",
        "Fourteenth Court of Appeals": "txctapp14",
        "Fifteenth Court of Appeals": "txctapp15",
        "Court of Criminal Appeals": "texcrimapp",
        "Supreme Court": "tex",
    }.get(subject[27:])


domain_to_cl_id = {
    "sc-us.gov": "scotus",  # Supreme Court of the United States
    "txcourts.gov": "texas",  # All Texas courts
}


def map_email_to_cl_id(email):
    from_addr = email["common_headers"]["from"][0]
    full_domain = parseaddr(from_addr)[1].split("@")[1]
    parts = full_domain.split(".")
    domain = ".".join(parts[-2:])
    if domain in {"fedcourts.us", "uscourts.gov"}:
        return map_pacer_to_cl_id(parts[0])
    maybe_cl_id = domain_to_cl_id.get(full_domain, full_domain)
    if maybe_cl_id == "texas":
        cl_id = get_tx_court_id_from_subject(email["commonHeaders"]["subject"])
    else:
        cl_id = maybe_cl_id
    return cl_id
