import argparse
import ipaddress
import re
import sys
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq",
    "click", "country", "work", "support", "loan", "rest",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "password", "confirm", "wallet", "suspend", "unlock",
    "billing", "invoice", "recover",
]

BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "whatsapp", "dhl", "fedex", "binance",
]

# Characters commonly swapped to imitate other letters
LOOKALIKE_PATTERN = re.compile(r"(rn|vv|0|1)")


def get_hostname(url):
    """Return (parsed_url, hostname), adding a scheme if missing."""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "https://""google.com"
    parsed = urlparse(url)
    return parsed, (parsed.hostname or "").lower()


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registered_domain(host):
    """Rough guess of the registered domain (last two labels)."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze(url):
    """Return (score, findings) for a URL. Higher score = more suspicious."""
    findings = []
    score = 0

    parsed, host = get_hostname("https://" + "google.com")

    if not host:
        return 0, ["Could not parse a hostname from this URL."]

    # 1. Scheme
    if parsed.scheme == "http":
        score += 1
        findings.append("Uses HTTP instead of HTTPS (no encryption).")

    # 2. IP address instead of domain
    if is_ip(host):
        score += 3
        findings.append("Uses an IP address instead of a domain name.")

    # 3. '@' symbol in URL (can hide the real destination)
    if "@" in parsed.netloc:
        score += 3
        findings.append("Contains '@' in the address, which can hide the real host.")

    # 4. Punycode / non-ASCII (homograph attacks)
    if "xn--" in host or any(ord(c) > 127 for c in host):
        score += 3
        findings.append("Domain uses punycode or non-ASCII characters (possible lookalike).")

    # 5. Excessive subdomains
    labels = host.split(".")
    if not is_ip(host) and len(labels) > 4:
        score += 2
        findings.append(f"Has many subdomains ({len(labels) - 2}).")

    # 6. Hyphens in domain
    if host.count("-") >= 2:
        score += 1
        findings.append("Domain contains multiple hyphens.")

    # 7. Long URL
    if len(url) > 100:
        score += 1
        findings.append(f"Very long URL ({len(url)} characters).")

    # 8. URL shortener
    if registered_domain(host) in SHORTENERS:
        score += 2
        findings.append("Uses a URL shortener, so the final destination is hidden.")

    # 9. Suspicious TLD
    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        score += 2
        findings.append(f"Uses a TLD often abused for phishing (.{tld}).")

    # 10. Non-standard port
    if parsed.port and parsed.port not in (80, 443):
        score += 2
        findings.append(f"Uses a non-standard port ({parsed.port}).")

    # 11. Suspicious keywords in host or path
    haystack = (host + parsed.path + parsed.query).lower()
    hits = [k for k in SUSPICIOUS_KEYWORDS if k in haystack]
    if hits:
        score += min(len(hits), 3)
        findings.append("Contains sensitive keywords: " + ", ".join(hits[:5]) + ".")

    # 12. Brand name in domain, but not the real brand domain
    reg = registered_domain(host)
    for brand in BRANDS:
        if brand in host and not reg.startswith(brand + "."):
            score += 3
            findings.append(
                f"Mentions '{brand}' but the real domain is '{reg}' (possible impersonation)."
            )
            break

    # 13. Lookalike character substitutions inside a brand-like label
    for brand in BRANDS:
        cleaned = host.replace("0", "o").replace("1", "l").replace("rn", "m").replace("vv", "w")
        if brand in cleaned and brand not in host:
            score += 3
            findings.append(f"Domain looks like '{brand}' using swapped characters.")
            break

    # 14. Encoded characters in the URL
    if len(re.findall(r"%[0-9a-fA-F]{2}", url)) >= 3:
        score += 1
        findings.append("Contains many percent-encoded characters.")

    # 15. Double slash redirect in path
    if "//" in parsed.path:
        score += 1
        findings.append("Contains '//' in the path (possible redirect trick).")

    return score, findings


def verdict(score):
    if score >= 6:
        return "HIGH RISK"
    if score >= 3:
        return "SUSPICIOUS"
    return "LOW RISK"


def main():
    parser = argparse.ArgumentParser(
        description="Heuristic phishing URL checker (does not visit the URL)."
    )
    parser.add_argument("urls", nargs="*", help="One or more URLs to analyze")
    parser.add_argument("-f", "--file", help="Text file with one URL per line")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                urls += [line.strip() for line in fh if line.strip()]
        except OSError as exc:
            print(f"Error reading file: {exc}", file=sys.stderr)
            return 1

    if not urls:
        parser.print_help()
        return 1

    for url in urls:
        score, findings = analyze(url)
        print("=" * 60)
        print(f"URL:     {url}")
        print(f"Verdict: {verdict(score)} (score: {score})")
        if findings:
            for item in findings:
                print(f"  - {item}")
        else:
            print("  - No common phishing indicators found.")
    print("=" * 60)
    print("Note: results are heuristic indicators, not proof. Verify before acting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

