import re


def normalize_url(url: str) -> str:
    """Normalize user-provided URLs to a valid requests-compatible format.

    - Convert backslashes to forward slashes
    - Ensure proper scheme separator (://) for http/https
    - Prepend http:// if scheme is missing
    - Collapse duplicate slashes immediately after the scheme
    """
    url = (url or "").strip()
    url = url.replace("\\", "/")
    url = re.sub(r'^(https?):/*', r'\1://', url, flags=re.IGNORECASE)
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = f"http://{url}"
    url = re.sub(r'^(https?://)/+', r'\1', url, flags=re.IGNORECASE)
    return url


NOISE_PATTERNS = [
    "[ERROR]",
    "Command error:",
    "Traceback",
    "Exception",
    " failed:",
    "Error running",
    "Make sure",
    "not found",
    "timeout",
    "timed out",
    "Timeout",
]


def is_noise_line(line: str) -> bool:
    """Return True if a line is likely an operational/tool error rather than a security finding."""
    if not line:
        return True
    lower_line = line.lower()
    # Skip explicit error tags fast
    if "[error]" in lower_line:
        return True
    # Generic noise patterns
    for pat in NOISE_PATTERNS:
        if pat.lower() in lower_line:
            return True
    return False


