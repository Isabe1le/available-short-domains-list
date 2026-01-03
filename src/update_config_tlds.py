from typing import Final
import json

import requests


ICANN_TLD_LIST_URL: Final[str] = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


def _fetch_active_tlds(len_req: int) -> list[str]:
    with requests.get(ICANN_TLD_LIST_URL) as resp:
        resp.raise_for_status()
    tlds: list[str] = resp.text.split("\n")[1::]
    return [tld.lower() for tld in tlds if len(tld) == len_req]


if __name__ == "__main__":
    tld_lengths_to_track: dict[str, list[int]] = {}
    active_tlds = _fetch_active_tlds(2)
    if active_tlds:
        tld_lengths_to_track.update({tld: [2] for tld in active_tlds})

    with open("_data/config/tracked_tlds.json", "w+") as f:
        json.dump(tld_lengths_to_track, f, indent=4, sort_keys=True)