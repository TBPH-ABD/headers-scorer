# headers-scorer

Grade a website's HTTP security headers. One request, a clear per-header
verdict, and a letter grade from **A** to **F** — the quick check you run before
a pentest report or a deploy.

## Why

The HTTP response headers are the cheapest security control a site has and the
most commonly misconfigured. A missing `Content-Security-Policy`, a weak
`Strict-Transport-Security`, a `Server: nginx/1.18.0` leaking a version — each is
a finding on its own. `headers-scorer` checks them all in one pass and tells you
not just *what* is wrong but *why it matters*.

It is read-only reconnaissance: a single GET (or HEAD) to a URL you give it.

## What it grades

| Header | GOOD when |
| --- | --- |
| `Strict-Transport-Security` | present with `max-age ≥ 180 days` (on HTTPS) |
| `Content-Security-Policy` | present, no `unsafe-inline`/`unsafe-eval`, with a `default-src`/`script-src` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY`/`SAMEORIGIN`, or CSP `frame-ancestors` |
| `Referrer-Policy` | a privacy-preserving value |
| `Permissions-Policy` | present |
| Information disclosure | no `Server` / `X-Powered-By` / version headers |

Each check is scored GOOD (2), WARN (1), or BAD (0); the total becomes a
percentage and a letter grade.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Grade a site
python3 headers_scorer.py https://example.com

# Bare host (https:// is assumed)
python3 headers_scorer.py example.com

# Use a HEAD request
python3 headers_scorer.py example.com --head

# Machine-readable
python3 headers_scorer.py example.com --json

# Fail CI if the score is below a threshold
python3 headers_scorer.py example.com --fail-under 75
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `url` | Target URL (`https://` assumed if omitted) | required |
| `--head` | Use a HEAD request instead of GET | off |
| `--json` | Emit the report as JSON | off |
| `--fail-under SCORE` | Exit non-zero if the score is below `SCORE` (0–100) | — |

## Example

```
$ python3 headers_scorer.py https://example.com
headers-scorer  https://example.com/  (HTTP 200)
grade: C  (64/100)

  [GOOD] Strict-Transport-Security: present (max-age=63072000).
  [BAD ] Content-Security-Policy: missing: the strongest defence against XSS...
  [GOOD] X-Content-Type-Options: nosniff.
  [BAD ] X-Frame-Options: missing: the page can be framed, enabling clickjacking.
  [WARN] Referrer-Policy: missing: full referrer URLs may leak to other origins.
  [WARN] Permissions-Policy: missing: powerful features are not restricted.
  [WARN] Information disclosure: leaks implementation detail via Server: ECS
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

Standard-library `unittest`. HTTP is exercised against a local fake server, so
the suite never reaches the internet.

## Scope

Run it against sites you own or are explicitly authorized to assess. It only
reads response headers and changes nothing on the target.

## License

MIT — see [LICENSE](LICENSE).
