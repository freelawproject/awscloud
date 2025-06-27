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
