import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(
    r"https?://[^\s]+",
    re.IGNORECASE,
)


ARCHIVE_EXTENSIONS = (
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".7z",
    ".rar",
)


def get_valid_url(value: str) -> str | None:
    """
    Находит первый HTTP/HTTPS URL внутри значения.
    """

    value = (value or "").strip()

    if not value:
        return None

    match = URL_PATTERN.search(value)

    if not match:
        return None

    url = match.group(0).rstrip(
        ".,;:)]}>\"'"
    )

    parsed = urlparse(url)

    if parsed.scheme not in (
        "http",
        "https",
    ):
        return None

    if not parsed.netloc:
        return None

    return url


def is_archive_url(url: str) -> bool:
    """
    Определяет, указывает ли URL на архив.
    """

    if not url:
        return False

    path = urlparse(url).path.lower()

    return path.endswith(
        ARCHIVE_EXTENSIONS
    )