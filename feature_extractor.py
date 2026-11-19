"""
feature_extractor.py
Extracts URL-based features used by the phishing detection model.
All features align with the PhiUSIIL dataset columns.
"""

import re
import math
import urllib.parse
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".win", ".stream", ".download", ".gdn", ".racing", ".loan",
    ".accountant", ".science", ".work", ".date", ".faith", ".review",
}

BRAND_KEYWORDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "facebook",
    "instagram", "twitter", "linkedin", "netflix", "bank", "secure",
    "login", "signin", "account", "verify", "update", "confirm",
]

IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)


def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _count_digits(s: str) -> int:
    return sum(c.isdigit() for c in s)


def _count_special(s: str) -> int:
    return sum(not c.isalnum() for c in s)


# ---------------------------------------------------------------------------
# Main extractor
# ---------------------------------------------------------------------------

def extract_features(url: str) -> Dict[str, Any]:
    """
    Extract all features from a URL.
    Returns a dict whose keys match the ML model's expected feature columns.
    """
    # Ensure the URL has a scheme so urlparse works properly
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    scheme   = parsed.scheme or ""
    hostname = parsed.netloc or ""
    path     = parsed.path or ""
    query    = parsed.query or ""
    fragment = parsed.fragment or ""

    # Strip port from hostname
    if ":" in hostname:
        hostname = hostname.rsplit(":", 1)[0]

    full_url = url

    # --- URL-level -----------------------------------------------------------
    url_len        = len(full_url)
    hostname_len   = len(hostname)
    path_len       = len(path)
    query_len      = len(query)
    fragment_len   = len(fragment)

    num_dots        = full_url.count(".")
    num_hyphens     = full_url.count("-")
    num_underscores = full_url.count("_")
    num_slashes     = full_url.count("/")
    num_at          = full_url.count("@")
    num_question    = full_url.count("?")
    num_ampersand   = full_url.count("&")
    num_equal       = full_url.count("=")
    num_percent     = full_url.count("%")
    num_hash        = full_url.count("#")
    num_tilde       = full_url.count("~")
    num_colon       = full_url.count(":")
    num_comma       = full_url.count(",")
    num_semicolon   = full_url.count(";")
    num_digits_url  = _count_digits(full_url)
    num_special_url = _count_special(full_url)

    # --- Hostname features ---------------------------------------------------
    num_dots_host     = hostname.count(".")
    num_hyphens_host  = hostname.count("-")
    num_digits_host   = _count_digits(hostname)
    num_subdirs       = path.count("/")

    is_ip             = 1 if IP_RE.match(hostname) else 0
    has_https         = 1 if scheme == "https" else 0
    has_www           = 1 if hostname.startswith("www.") else 0

    # Suspicious TLD
    tld = ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1].lower()
    has_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

    # Subdomain count (dots beyond the base domain)
    subdomain_count = max(0, num_dots_host - 1)

    # Brand in URL (typosquatting signal)
    url_lower = full_url.lower()
    has_brand_keyword = int(any(b in url_lower for b in BRAND_KEYWORDS))

    # Entropy
    url_entropy      = _entropy(full_url)
    hostname_entropy = _entropy(hostname)
    path_entropy     = _entropy(path)

    # Shortening services
    shorteners = [
        "bit.ly", "tinyurl", "goo.gl", "ow.ly", "t.co", "is.gd",
        "buff.ly", "adf.ly", "tr.im", "tiny.cc",
    ]
    is_shortened = int(any(s in hostname.lower() for s in shorteners))

    # Redirection in path / query
    has_redirect = int("redirect" in url_lower or "url=" in url_lower or "goto=" in url_lower)

    # Port in URL
    port = parsed.port
    has_port          = 1 if port else 0
    is_non_std_port   = 1 if (port and port not in (80, 443)) else 0

    # --- Query / Path features -----------------------------------------------
    num_params     = len(query.split("&")) if query else 0
    longest_param  = max((len(p) for p in query.split("&")), default=0) if query else 0
    has_exe        = int(any(path.lower().endswith(e) for e in [".exe", ".zip", ".rar", ".js", ".bat"]))
    num_path_tokens = len([t for t in path.split("/") if t])

    # Ratio features
    digit_ratio_url  = num_digits_url / max(url_len, 1)
    special_ratio_url = num_special_url / max(url_len, 1)

    return {
        # Length-based
        "URLLength":          url_len,
        "DomainLength":       hostname_len,
        "PathLength":         path_len,
        "QueryLength":        query_len,
        "FragmentLength":     fragment_len,

        # Count-based
        "NumDots":            num_dots,
        "NumHyphens":         num_hyphens,
        "NumUnderscores":     num_underscores,
        "NumSlashes":         num_slashes,
        "NumAt":              num_at,
        "NumQuestion":        num_question,
        "NumAmpersand":       num_ampersand,
        "NumEqual":           num_equal,
        "NumPercent":         num_percent,
        "NumHash":            num_hash,
        "NumTilde":           num_tilde,
        "NumColon":           num_colon,
        "NumComma":           num_comma,
        "NumSemicolon":       num_semicolon,
        "NumDigitsURL":       num_digits_url,
        "NumSpecialURL":      num_special_url,

        # Hostname-level
        "NumDotsHost":        num_dots_host,
        "NumHyphensHost":     num_hyphens_host,
        "NumDigitsHost":      num_digits_host,
        "NumSubdirs":         num_subdirs,
        "SubdomainCount":     subdomain_count,

        # Binary flags
        "IsIP":               is_ip,
        "HasHTTPS":           has_https,
        "HasWWW":             has_www,
        "HasSuspiciousTLD":   has_suspicious_tld,
        "HasBrandKeyword":    has_brand_keyword,
        "IsShortened":        is_shortened,
        "HasRedirect":        has_redirect,
        "HasPort":            has_port,
        "IsNonStdPort":       is_non_std_port,
        "HasExeExtension":    has_exe,

        # Entropy
        "URLEntropy":         round(url_entropy,  4),
        "HostnameEntropy":    round(hostname_entropy, 4),
        "PathEntropy":        round(path_entropy, 4),

        # Ratio
        "DigitRatioURL":      round(digit_ratio_url,  4),
        "SpecialRatioURL":    round(special_ratio_url, 4),

        # Query / Path
        "NumParams":          num_params,
        "LongestParam":       longest_param,
        "NumPathTokens":      num_path_tokens,
    }
