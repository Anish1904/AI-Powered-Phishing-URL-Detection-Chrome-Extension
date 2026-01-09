import re
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_WORDS = [
    "login", "secure", "account", "update", "verify",
    "bank", "free", "confirm", "signin", "payment"
]

def has_ip_address(url):
    return 1 if re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", url) else 0

def extract_features(url):
    features = {}

    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    # URL-based features
    features["url_length"] = len(url)
    features["count_dots"] = url.count(".")
    features["count_hyphens"] = url.count("-")
    features["count_slashes"] = url.count("/")
    features["count_digits"] = sum(c.isdigit() for c in url)
    features["has_ip"] = has_ip_address(url)
    features["has_https"] = 1 if parsed.scheme == "https" else 0

    features["suspicious_word_count"] = sum(
        word in url.lower() for word in SUSPICIOUS_WORDS
    )

    # Domain-based (string only)
    domain = extracted.domain + "." + extracted.suffix
    features["domain_length"] = len(domain)

    features["subdomain_count"] = (
        extracted.subdomain.count(".") + (1 if extracted.subdomain else 0)
    )

    return features
