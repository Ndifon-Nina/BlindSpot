from http.cookies import SimpleCookie

import requests

GOOD_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "X-Frame-Options",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/backup.zip",
    "/backup/",
    "/test/",
    "/debug/",
]

LEAK_WORDS = [
    "traceback",
    "mysql",
    "postgresql",
    "sqlstate",
    "stack trace",
    "filenotfoundexception",
    "internal error details",
]

TIMEOUT = 10


def scan_website(url):
    try:
        response = requests.get(url, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return None, []

    homepage_text = response.text.lower()

    findings = []
    findings += check_https(url)
    findings += check_headers(response)
    findings += check_error_leakage(url)
    findings += check_cookies(response)
    exposed_paths, listing_dirs = check_paths(url, homepage_text)
    findings += exposed_paths
    findings += check_directory_listing(url, listing_dirs)

    return response, findings


def check_https(url):
    if url.startswith("https://"):
        return []
    return [{
        "check_type": "https",
        "severity": "HIGH",
        "title": "Website does not use HTTPS",
        "description": (
            "The website is served over plain HTTP. Data sent between visitors "
            "and the site is not encrypted and could be read by others."
        ),
        "recommendation": "Enable HTTPS with a valid certificate and redirect all HTTP traffic to HTTPS.",
    }]


def check_headers(response):
    missing = []
    response_headers = {key.lower() for key in response.headers.keys()}

    for header in GOOD_HEADERS:
        if header.lower() not in response_headers:
            missing.append(header)

    if not missing:
        return []
    names = ", ".join(missing)
    return [{
        "check_type": "headers",
        "severity": "MEDIUM",
        "title": "Missing security headers",
        "description": (
            f"These security headers are missing: {names}. "
            "They help the browser protect visitors from common attacks."
        ),
        "recommendation": "Add the missing headers to your server configuration.",
    }]


def check_directory_listing(url, listing_dirs):
    if not listing_dirs:
        return []
    names = ", ".join(listing_dirs)
    return [{
        "check_type": "directory",
        "severity": "MEDIUM",
        "title": "Directory listing may be enabled",
        "description": (
            f"Folders like {names} may be showing a list of their files. "
            "This can expose files that should stay private."
        ),
        "recommendation": "Disable directory listing in your web server configuration.",
    }]


def check_error_leakage(url):
    probe_url = url.rstrip("/") + "/doesnotexist_bs_probe_123456"
    try:
        response = requests.get(probe_url, timeout=TIMEOUT)
    except requests.exceptions.RequestException:
        return []

    text = response.text.lower()
    found = [word for word in LEAK_WORDS if word in text]
    if not found:
        return []
    return [{
        "check_type": "leakage",
        "severity": "LOW",
        "title": "Error pages may reveal technical details",
        "description": (
            "An error response contained technical terms ("
            + ", ".join(found)
            + "). This can give attackers clues about the site's internals."
        ),
        "recommendation": "Use friendly, generic error pages that do not show stack traces or database details.",
    }]


def check_cookies(response):
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie")
    if not set_cookie_headers:
        return []

    insecure = []
    for header in set_cookie_headers:
        cookie = SimpleCookie()
        cookie.load(header)
        for morsel in cookie.values():
            has_secure = bool(morsel["secure"])
            has_httponly = bool(morsel["httponly"])
            has_samesite = bool(morsel["samesite"])
            if not (has_secure and has_httponly and has_samesite):
                insecure.append(morsel.key)

    if not insecure:
        return []
    names = ", ".join(insecure)
    return [{
        "check_type": "cookies",
        "severity": "LOW",
        "title": "Cookies missing security attributes",
        "description": (
            f"Cookies ({names}) may be missing Secure, HttpOnly, or SameSite. "
            "Such cookies are easier to steal or misuse."
        ),
        "recommendation": "Set Secure, HttpOnly, and SameSite attributes on all cookies.",
    }]


def check_paths(url, homepage_text):
    """Probe sensitive paths once, and return (exposure_findings, listing_dirs)."""
    finding_list = []
    listing_dirs = []
    base = url.rstrip("/")

    for path in SENSITIVE_PATHS:
        try:
            probe = requests.get(base + path, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            continue

        if probe.status_code != 200:
            continue

        page_text = probe.text.lower()

        # Some sites return their normal homepage for every path we try.
        # That's not a real exposure, so ignore identical pages.
        is_directory_listing = "index of" in page_text or "directory listing" in page_text
        if is_directory_listing:
            listing_dirs.append(path)
            continue

        if page_text == homepage_text:
            continue

        finding_list.append({
            "check_type": "exposure",
            "severity": "HIGH",
            "title": "Possible exposed resource",
            "description": (
                f"{base}{path} is publicly accessible. "
                "It may contain secrets or files that should stay private."
            ),
            "recommendation": f"Block public access to {path}.",
        })

    return finding_list, listing_dirs