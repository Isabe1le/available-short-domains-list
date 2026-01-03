import datetime
import json
import threading
import time
from functools import lru_cache
from typing import Final, Optional

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.resolver
import dns.rdatatype

from utils import LAST_UPDATED_KEY, DomainStatus, generate_strings_to_check


ROOT_SERVERS: Final[tuple[str, ...]] = (
    "198.41.0.4",     # a.root-servers.net
    "199.9.14.201",   # b.root-servers.net
    "192.33.4.12",    # c.root-servers.net
    "199.7.91.13",    # d.root-servers.net
)

DNS_TIMEOUT: Final[float] = 2.5


def _normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _make_query(qname: str, rdtype: dns.rdatatype.RdataType) -> dns.message.Message:
    msg = dns.message.make_query(qname, rdtype, want_dnssec=False)
    msg.use_edns(edns=True, payload=1232)
    return msg


def _udp(msg: dns.message.Message, server_ip: str, timeout: float) -> dns.message.Message:
    return dns.query.udp(msg, server_ip, timeout=timeout)


def _dedupe_preserve_order(items: list[str]) -> tuple[str, ...]:
    seen = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return tuple(out)


@lru_cache(maxsize=2048)
def _get_tld_nameservers(tld: str, timeout: float = DNS_TIMEOUT) -> tuple[str, ...]:
    tld = tld.strip().lstrip(".").lower()
    qname = f"{tld}."

    q = _make_query(qname, dns.rdatatype.NS)

    last_err: Optional[Exception] = None
    for root_ip in ROOT_SERVERS:
        try:
            resp = _udp(q, root_ip, timeout)
            rcode = resp.rcode()

            if rcode == dns.rcode.NXDOMAIN:
                return tuple()  # TLD not in root?

            if rcode != dns.rcode.NOERROR:
                continue

            ns_names: list[str] = []

            # root maybe returns NS in authority
            for rrset in list(resp.answer) + list(resp.authority):
                if rrset.rdtype == dns.rdatatype.NS:
                    ns_names.extend([r.to_text().rstrip(".") for r in rrset])

            if ns_names:
                return _dedupe_preserve_order(ns_names)

        except Exception as e:
            last_err = e

    if last_err:
        raise last_err
    return tuple()


@lru_cache(maxsize=8192)
def _resolve_ips(hostname: str, timeout: float = DNS_TIMEOUT) -> tuple[str, ...]:
    res = dns.resolver.Resolver(configure=True)
    res.timeout = timeout
    res.lifetime = timeout

    ips: list[str] = []

    try:
        ans = res.resolve(hostname, "A")
        ips.extend([r.to_text() for r in ans])
    except Exception:
        pass

    try:
        ans = res.resolve(hostname, "AAAA")
        ips.extend([r.to_text() for r in ans])
    except Exception:
        pass

    return _dedupe_preserve_order(ips)


def _authoritative_tld_query(domain: str, tld_ns_ips: list[str], timeout: float) -> dns.message.Message:
    qname = f"{domain}."
    q = _make_query(qname, dns.rdatatype.SOA)

    last: Optional[Exception] = None
    for ip in tld_ns_ips:
        try:
            return _udp(q, ip, timeout)
        except Exception as e:
            last = e

    if last:
        raise last
    raise RuntimeError("No authoritative NS IPs available")


def check_domain_registration(domain: str, tld: str, *, depth: int = 1) -> DomainStatus:
    if depth > 30:
        return DomainStatus.FAILED

    domain = _normalize_domain(domain)
    tld = tld.strip().lstrip(".").lower()

    try:
        tld_ns = _get_tld_nameservers(tld)
        if not tld_ns:
            return DomainStatus.FAILED

        ips: list[str] = []
        for ns in tld_ns:
            ips.extend(list(_resolve_ips(ns)))

        if not ips:
            return DomainStatus.FAILED

        resp = _authoritative_tld_query(domain, ips, DNS_TIMEOUT)
        rcode = resp.rcode()

        if rcode == dns.rcode.NXDOMAIN:
            return DomainStatus.UNREGISTERED
        elif rcode == dns.rcode.NOERROR:
            return DomainStatus.REGISTERED
        elif rcode in (dns.rcode.SERVFAIL, dns.rcode.REFUSED):
            time.sleep(min(3, depth))  # backoff
            return check_domain_registration(domain, tld, depth=depth + 2)

        return DomainStatus.FAILED

    except dns.exception.Timeout:
        print(f"> [{tld}] [ !!! ] DNS timed out, retrying.")
        return check_domain_registration(domain, tld, depth=depth + 3)
    except Exception:
        return DomainStatus.FAILED


def load_tld_registration_information(tld: str, size: int) -> None:
    time_start = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()
    domains_to_check: list[str] = generate_strings_to_check(size)
    number_of_domains_to_check: int = len(domains_to_check)
    checked_domains: dict[str, int] = {}

    for index, host_name in enumerate(domains_to_check):
        domain = f"{host_name}.{tld}"
        status = check_domain_registration(domain, tld)

        print(f"> [{tld}] [{index + 1}/{number_of_domains_to_check}] \t{domain} is {status.name}")
        checked_domains[host_name] = status.value

        if index % 10 == 0:
            print(f"> [{tld}] Saving progress...")
            checked_domains[LAST_UPDATED_KEY] = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
            with open(f"_data/json/{tld}-{size}.json", "w+") as f:
                json.dump(
                    obj=checked_domains,
                    fp=f,
                    indent=2,
                    ensure_ascii=True,
                    sort_keys=True,
                )

    time_end = datetime.datetime.now(tz=datetime.timezone.utc).timestamp()

    checked_domains[LAST_UPDATED_KEY] = int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())
    with open(f"_data/json/{tld}-{size}.json", "w+") as f:
        json.dump(
            obj=checked_domains,
            fp=f,
            indent=2,
            ensure_ascii=True,
            sort_keys=True,
        )

    registered_count = sum(1 for k, v in checked_domains.items() if k != LAST_UPDATED_KEY and v == DomainStatus.REGISTERED.value)
    unregistered_count = sum(1 for k, v in checked_domains.items() if k != LAST_UPDATED_KEY and v == DomainStatus.UNREGISTERED.value)
    failed_lookup_count = sum(1 for k, v in checked_domains.items() if k != LAST_UPDATED_KEY and v == DomainStatus.FAILED.value)

    successful_lookup_count = registered_count + unregistered_count
    total_count = successful_lookup_count + failed_lookup_count

    success_rate = round((successful_lookup_count / total_count) * 100, 2) if total_count else 0.0
    if success_rate > 99.99:
        success_rate = 100

    print(
        f"Fetched registration information for {total_count} domains."
        + f"\n  - Attempted: {number_of_domains_to_check}"
        + f"\n  - Failed: {failed_lookup_count}"
        + f"\n  - Lookup success rate: {success_rate}%"
        + f"\n  - {registered_count} registered"
        + f"\n  - {unregistered_count} unregistered"
        + f"\nTime taken: {round(time_end-time_start)} seconds."
    )


def main() -> None:
    with open("_data/config/tracked_tlds.json", "r") as f:
        config = json.load(f)

    for domain, lengths in config.items():
        for length in lengths:
            thread = threading.Thread(target=load_tld_registration_information, args=(domain, length))
            thread.start()


if __name__ == "__main__":
    main()
