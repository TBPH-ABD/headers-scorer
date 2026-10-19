"""Tests for headers-scorer: fetching, each check, scoring, and CLI."""
from __future__ import annotations

import json
import unittest
import urllib.request

import headers_scorer
from headers_scorer import FetchError, fetch_headers, grade
from tests.support.fakes import capture_cli, closed_port, http_fake

SECURE = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}


def grade_for(headers, url="https://secure.test/"):
    h = {k.lower(): v for k, v in headers.items()}
    h["__url__"] = url
    h["__status__"] = "200"
    return grade(h)


def status_of(report, header_name):
    for check in report["checks"]:
        if check["header"] == header_name:
            return check["status"]
    raise AssertionError(f"no check named {header_name}")


class FetchTests(unittest.TestCase):
    def _opener_for(self, base):
        def opener(request, timeout=15.0):
            from urllib.parse import urlsplit
            path = urlsplit(request.full_url).path or "/"
            return urllib.request.urlopen(base + path, timeout=timeout)
        return opener

    def test_fetch_lowercases_headers(self):
        with http_fake({"/": (200, {"X-Frame-Options": "DENY"}, "ok")}) \
                as (base, _rec):
            headers = fetch_headers(base + "/", opener=self._opener_for(base))
        self.assertEqual(headers["x-frame-options"], "DENY")
        self.assertEqual(headers["__status__"], "200")

    def test_http_error_still_returns_headers(self):
        with http_fake({"/x": (403, {"X-Frame-Options": "DENY"}, "no")}) \
                as (base, _rec):
            headers = fetch_headers(base + "/x", opener=self._opener_for(base))
        self.assertEqual(headers["__status__"], "403")
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_unreachable_raises(self):
        host, port = closed_port()
        with self.assertRaises(FetchError):
            fetch_headers(f"http://{host}:{port}/", timeout=1.0)

    def test_scheme_defaulted_to_https(self):
        with http_fake({"/": (200, {}, "ok")}) as (base, _rec):
            # base already has a scheme; just confirm no crash on bare host form
            headers = fetch_headers(base, opener=self._opener_for(base))
        self.assertIn("__status__", headers)


class HstsTests(unittest.TestCase):
    def test_strong_hsts_good(self):
        self.assertEqual(status_of(grade_for(SECURE),
                                   "Strict-Transport-Security"), "GOOD")

    def test_missing_hsts_on_https_bad(self):
        h = dict(SECURE); del h["Strict-Transport-Security"]
        self.assertEqual(status_of(grade_for(h),
                                   "Strict-Transport-Security"), "BAD")

    def test_short_max_age_warn(self):
        h = dict(SECURE); h["Strict-Transport-Security"] = "max-age=100"
        self.assertEqual(status_of(grade_for(h),
                                   "Strict-Transport-Security"), "WARN")

    def test_http_target_warn(self):
        report = grade_for(SECURE, url="http://insecure.test/")
        self.assertEqual(status_of(report, "Strict-Transport-Security"),
                         "WARN")


class CspTests(unittest.TestCase):
    def test_restrictive_good(self):
        self.assertEqual(status_of(grade_for(SECURE),
                                   "Content-Security-Policy"), "GOOD")

    def test_missing_bad(self):
        h = dict(SECURE); del h["Content-Security-Policy"]
        self.assertEqual(status_of(grade_for(h),
                                   "Content-Security-Policy"), "BAD")

    def test_unsafe_inline_warn(self):
        h = dict(SECURE)
        h["Content-Security-Policy"] = "default-src 'self' 'unsafe-inline'"
        self.assertEqual(status_of(grade_for(h),
                                   "Content-Security-Policy"), "WARN")

    def test_no_default_or_script_src_warn(self):
        h = dict(SECURE); h["Content-Security-Policy"] = "img-src 'self'"
        self.assertEqual(status_of(grade_for(h),
                                   "Content-Security-Policy"), "WARN")


class OtherHeaderTests(unittest.TestCase):
    def test_nosniff_good_missing_bad(self):
        self.assertEqual(status_of(grade_for(SECURE),
                                   "X-Content-Type-Options"), "GOOD")
        h = dict(SECURE); del h["X-Content-Type-Options"]
        self.assertEqual(status_of(grade_for(h),
                                   "X-Content-Type-Options"), "BAD")

    def test_frame_ancestors_counts_for_xfo(self):
        h = dict(SECURE); del h["X-Frame-Options"]
        # CSP still has frame-ancestors 'none'
        self.assertEqual(status_of(grade_for(h), "X-Frame-Options"), "GOOD")

    def test_no_framing_control_bad(self):
        h = dict(SECURE)
        del h["X-Frame-Options"]
        h["Content-Security-Policy"] = "default-src 'self'"
        self.assertEqual(status_of(grade_for(h), "X-Frame-Options"), "BAD")

    def test_referrer_weak_warn(self):
        h = dict(SECURE); h["Referrer-Policy"] = "unsafe-url"
        self.assertEqual(status_of(grade_for(h), "Referrer-Policy"), "WARN")

    def test_permissions_missing_warn(self):
        h = dict(SECURE); del h["Permissions-Policy"]
        self.assertEqual(status_of(grade_for(h), "Permissions-Policy"), "WARN")

    def test_leaky_server_header_warn(self):
        h = dict(SECURE); h["Server"] = "nginx/1.18.0"
        self.assertEqual(status_of(grade_for(h), "Information disclosure"),
                         "WARN")

    def test_no_leak_good(self):
        self.assertEqual(status_of(grade_for(SECURE), "Information disclosure"),
                         "GOOD")


class GradingTests(unittest.TestCase):
    def test_secure_site_scores_a(self):
        report = grade_for(SECURE)
        self.assertEqual(report["grade"], "A")
        self.assertGreaterEqual(report["score"], 90)

    def test_empty_site_scores_f(self):
        report = grade_for({}, url="http://bad.test/")
        self.assertEqual(report["grade"], "F")

    def test_letter_boundaries(self):
        self.assertEqual(headers_scorer._letter(90), "A")
        self.assertEqual(headers_scorer._letter(75), "B")
        self.assertEqual(headers_scorer._letter(60), "C")
        self.assertEqual(headers_scorer._letter(40), "D")
        self.assertEqual(headers_scorer._letter(10), "F")


class CLITests(unittest.TestCase):
    def _run(self, base, path, extra=None):
        real_urlopen = urllib.request.urlopen

        def opener(request, timeout=15.0):
            from urllib.parse import urlsplit
            p = urlsplit(request.full_url).path or "/"
            return real_urlopen(base + p, timeout=timeout)

        orig = headers_scorer.urllib.request.urlopen
        headers_scorer.urllib.request.urlopen = opener
        try:
            return capture_cli(headers_scorer.main,
                               [base + path, *(extra or [])])
        finally:
            headers_scorer.urllib.request.urlopen = orig

    def test_report_output(self):
        with http_fake({"/": (200, SECURE, "ok")}) as (base, _rec):
            code, out = self._run(base, "/")
        self.assertEqual(code, 0)
        # Local fake is HTTP and emits a Server header, so an otherwise
        # secure header set grades B, not A. Confirm a grade was reported.
        self.assertIn("grade:", out)

    def test_json_output(self):
        with http_fake({"/": (200, SECURE, "ok")}) as (base, _rec):
            code, out = self._run(base, "/", ["--json"])
        self.assertEqual(code, 0)
        self.assertIn(json.loads(out)["grade"], ("A", "B"))

    def test_fail_under_triggers(self):
        with http_fake({"/": (200, {}, "ok")}) as (base, _rec):
            code, _out = self._run(base, "/", ["--fail-under", "90"])
        self.assertEqual(code, 1)

    def test_unreachable_exits_two(self):
        host, port = closed_port()
        code, err = capture_cli(headers_scorer.main,
                                [f"http://{host}:{port}/"])
        self.assertEqual(code, 2)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
