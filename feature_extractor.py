"""Extract the 25 dataset features required for phishing URL prediction."""

import math
import re
import urllib.parse


def _entropy(value):
    if not value:
        return 0.0
    frequencies = {}
    for character in value:
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(value)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in frequencies.values()
    )


def _count_digits(value):
    return sum(character.isdigit() for character in value)


def _count_special(value):
    return sum(not character.isalnum() for character in value)


def _has_repeated_digits(value):
    return int(bool(re.search(r"(\d)\1+", value)))


def extract_features(url):
    url = (url or "").strip()
    if not url:
        raise ValueError("No URL provided")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # Remove a leading www. label from subdomain calculations.
    labels = [label for label in hostname.split(".") if label]
    subdomain_labels = labels[:-2] if len(labels) > 2 else []

    subdomain_text = ".".join(subdomain_labels)
    subdomain_lengths = [len(label) for label in subdomain_labels]
    average_subdomain_length = (
        sum(subdomain_lengths) / len(subdomain_lengths)
        if subdomain_lengths
        else 0.0
    )

    return {
        "url_length": len(url),
        "average_subdomain_length": round(average_subdomain_length, 4),
        "entropy_of_url": round(_entropy(url), 9),
        "entropy_of_domain": round(_entropy(hostname), 9),
        "domain_length": len(hostname),
        "number_of_subdomains": len(subdomain_labels),
        "number_of_special_char_in_url": _count_special(url),
        "number_of_digits_in_domain": _count_digits(hostname),
        "number_of_dots_in_domain": hostname.count("."),
        "number_of_digits_in_url": _count_digits(url),
        "number_of_slash_in_url": url.count("/"),
        "number_of_dots_in_url": url.count("."),
        "path_length": len(path),
        "number_of_hyphens_in_domain": hostname.count("-"),
        "number_of_hyphens_in_url": url.count("-"),
        "having_digits_in_domain": int(_count_digits(hostname) > 0),
        "number_of_equal_in_url": url.count("="),
        "number_of_digits_in_subdomain": _count_digits(subdomain_text),
        "having_repeated_digits_in_domain": _has_repeated_digits(hostname),
        "having_digits_in_subdomain": int(_count_digits(subdomain_text) > 0),
        "number_of_questionmark_in_url": url.count("?"),
        "number_of_special_characters_in_domain": _count_special(hostname),
        "number_of_underline_in_url": url.count("_"),
        "having_query": int(bool(query)),
        "having_repeated_digits_in_url": _has_repeated_digits(url),
    }
