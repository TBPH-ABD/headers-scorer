#!/usr/bin/env python3
"""headers-scorer - grade a website's HTTP security headers.

Makes one request to a URL, inspects the response headers, and grades the site
on the security headers that matter: HSTS, Content-Security-Policy,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy,
and the absence of version-leaking headers. Each check explains what is missing
or weak and why it matters, and the run ends with a letter grade.

It is read-only reconnaissance: it sends a single GET (or HEAD) to a URL you
provide and reports what came back. Point it at sites you own or are authorized
to assess.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

GOOD, WARN, BAD = "GOOD", "WARN", "BAD"
_POINTS = {GOOD: 2, WARN: 1, BAD: 0}

# Headers whose presence leaks implementation detail an attacker can use.
_LEAKY_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version",
                  "X-AspNetMvc-Version", "X-Generator")


class FetchError(RuntimeError):
    """Raised when the target URL cannot be fetched."""


def fetch_headers(url: str, timeout: float = 15.0, method: str = "GET",
                  opener=None) -> dict:
    """Fetch a URL and return its response headers as a lowercased dict.

    ``opener`` is injectable so tests drive this against a local fake server.
    Both success and HTTP error responses carry headers, so a 4xx/5xx is still
    inspected rather than discarded.
    """
    opener = opener or urllib.request.urlopen
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    request = urllib.request.Request(
        url, method=method, headers={"User-Agent": "headers-scorer"})
    try:
        with opener(request, timeout=timeout) as response:
            headers = {k.lower(): v for k, v in response.headers.items()}
            headers["__status__"] = str(response.status)
            headers["__url__"] = response.url
            return headers
    except urllib.error.HTTPError as exc:
        # An error response still has headers worth grading.
        headers = {k.lower(): v for k, v in exc.headers.items()}
        headers["__status__"] = str(exc.code)
        headers["__url__"] = url
        exc.close()
        return headers
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise FetchError(f"could not fetch {url}: {exc}") from exc


# ----------------------------------------------------------------------------
# Individual header checks
# ----------------------------------------------------------------------------

def _check_hsts(headers: dict, is_https: bool) -> dict:
    value = headers.get("strict-transport-security")
    if not is_https:
        return _result("Strict-Transport-Security", WARN,
                       "target is HTTP, so HSTS does not apply; serve the site "
                       "over HTTPS.")
    if not value:
        return _result("Strict-Transport-Security", BAD,
                       "missing: a downgrade or SSL-strip attack can force the "
                       "browser back to HTTP.")
    max_age = _directive_int(value, "max-age")
    if max_age is None or max_age < 15_552_000:  # 180 days
        return _result("Strict-Transport-Security", WARN,
                       f"present but weak ({value!r}); use a max-age of at "
                       "least 15552000 (180 days).")
    return _result("Strict-Transport-Security", GOOD, f"present ({value}).")


def _check_csp(headers: dict) -> dict:
    value = headers.get("content-security-policy")
    if not value:
        return _result("Content-Security-Policy", BAD,
                       "missing: the strongest defence against XSS and data "
                       "injection is not in place.")
    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return _result("Content-Security-Policy", WARN,
                       "present but allows 'unsafe-inline'/'unsafe-eval', "
                       "which weakens its XSS protection.")
    if "default-src" not in lowered and "script-src" not in lowered:
        return _result("Content-Security-Policy", WARN,
                       "present but defines neither default-src nor script-src; "
                       "script execution may be unrestricted.")
    return _result("Content-Security-Policy", GOOD, "present and restrictive.")


def _check_x_content_type(headers: dict) -> dict:
    value = (headers.get("x-content-type-options") or "").strip().lower()
    if value == "nosniff":
        return _result("X-Content-Type-Options", GOOD, "nosniff.")
    return _result("X-Content-Type-Options", BAD,
                   "missing 'nosniff': the browser may MIME-sniff a response "
                   "into an executable type.")


def _check_frame_options(headers: dict) -> dict:
    xfo = (headers.get("x-frame-options") or "").strip().upper()
    csp = (headers.get("content-security-policy") or "").lower()
    if "frame-ancestors" in csp:
        return _result("X-Frame-Options", GOOD,
                       "framing controlled via CSP frame-ancestors.")
    if xfo in ("DENY", "SAMEORIGIN"):
        return _result("X-Frame-Options", GOOD, f"{xfo}.")
    return _result("X-Frame-Options", BAD,
                   "missing: the page can be framed, enabling clickjacking. "
                   "Set DENY/SAMEORIGIN or a CSP frame-ancestors directive.")


def _check_referrer(headers: dict) -> dict:
    value = (headers.get("referrer-policy") or "").strip().lower()
    strong = {"no-referrer", "same-origin", "strict-origin",
              "strict-origin-when-cross-origin"}
    if value in strong:
        return _result("Referrer-Policy", GOOD, f"{value}.")
    if value:
        return _result("Referrer-Policy", WARN,
                       f"set to {value!r}, which may leak full URLs "
                       "cross-origin; prefer strict-origin-when-cross-origin.")
    return _result("Referrer-Policy", WARN,
                   "missing: full referrer URLs may leak to other origins.")


def _check_permissions(headers: dict) -> dict:
    value = headers.get("permissions-policy") or headers.get("feature-policy")
    if value:
        return _result("Permissions-Policy", GOOD, "present.")
    return _result("Permissions-Policy", WARN,
                   "missing: powerful features (camera, geolocation, etc.) are "
                   "not explicitly restricted.")


def _check_leaky(headers: dict) -> dict:
    leaks = []
    for name in _LEAKY_HEADERS:
        value = headers.get(name.lower())
        # A bare product name with no version is low-risk; a version string is
        # what helps an attacker. Flag any value for Server/X-Powered-By.
        if value:
            leaks.append(f"{name}: {value}")
    if not leaks:
        return _result("Information disclosure", GOOD,
                       "no version-leaking headers.")
    return _result("Information disclosure", WARN,
                   "leaks implementation detail via " + "; ".join(leaks))


def _result(name: str, status: str, detail: str) -> dict:
    return {"header": name, "status": status, "detail": detail}


def _directive_int(header_value: str, directive: str):
    """Pull an integer directive (e.g. max-age=31536000) from a header."""
    for part in header_value.split(";"):
        part = part.strip()
        if part.lower().startswith(directive.lower() + "="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


# ----------------------------------------------------------------------------
# Scoring
# ----------------------------------------------------------------------------

def grade(headers: dict) -> dict:
    """Run all checks and compute a letter grade from the results."""
    url = headers.get("__url__", "")
    is_https = url.startswith("https://")
    checks = [
        _check_hsts(headers, is_https),
        _check_csp(headers),
        _check_x_content_type(headers),
        _check_frame_options(headers),
        _check_referrer(headers),
        _check_permissions(headers),
        _check_leaky(headers),
    ]
    earned = sum(_POINTS[c["status"]] for c in checks)
    possible = 2 * len(checks)
    pct = earned / possible * 100 if possible else 0
    return {
        "url": url,
        "status": headers.get("__status__"),
        "score": round(pct),
        "grade": _letter(pct),
        "checks": checks,
    }


def _letter(pct: float) -> str:
    if pct >= 90:
        return "A"
    if pct >= 75:
        return "B"
    if pct >= 60:
        return "C"
    if pct >= 40:
        return "D"
    return "F"


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def _print_report(report: dict) -> None:
    print(f"headers-scorer  {report['url']}  (HTTP {report['status']})")
    print(f"grade: {report['grade']}  ({report['score']}/100)\n")
    for check in report["checks"]:
        print(f"  [{check['status']:<4}] {check['header']}: {check['detail']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="headers-scorer",
        description="Grade a website's HTTP security headers (read-only; "
                    "authorized targets only).")
    parser.add_argument("url", help="target URL (https:// assumed if omitted)")
    parser.add_argument("--head", action="store_true",
                        help="use a HEAD request instead of GET")
    parser.add_argument("--json", action="store_true",
                        help="emit the report as JSON")
    parser.add_argument("--fail-under", type=int, metavar="SCORE",
                        help="exit non-zero if the score is below this (0-100)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        headers = fetch_headers(args.url,
                                method="HEAD" if args.head else "GET")
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = grade(headers)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_report(report)

    if args.fail_under is not None and report["score"] < args.fail_under:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
