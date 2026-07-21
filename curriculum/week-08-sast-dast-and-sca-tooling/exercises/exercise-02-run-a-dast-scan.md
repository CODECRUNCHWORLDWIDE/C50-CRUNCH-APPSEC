# Exercise 2 — Run a DAST Scan

**Goal:** Run OWASP ZAP against your own running lab target — first an anonymous baseline scan, then an authenticated full scan — entirely inside the isolated `appsec-lab` Docker network, and read the resulting alerts critically rather than at face value.

**Estimated time:** 90 minutes.

> **Isolation reminder.** Every scan below targets `juice-shop` by its Docker container name over the `appsec-lab` network — never a real host, never anything reachable from outside your lab. Active scanning sends real, deliberately-malicious-looking payloads; that's exactly why it only ever happens against a target you own, with the isolation from Week 1 verified, not assumed.

## Setup

Confirm your lab is up and reachable:

```bash
docker network ls | grep appsec-lab
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:3000   # expect 200
mkdir -p c50-week-08/exercise-02/zap-reports && cd c50-week-08/exercise-02
```

## Task 1 — Baseline scan (anonymous, passive + spider)

```bash
docker run --rm --network appsec-lab \
  -v "$(pwd)/zap-reports:/zap/wrk/:rw" \
  zaproxy/zap-stable zap-baseline.py \
  -t http://juice-shop:3000 \
  -J baseline-report.json -r baseline-report.html
```

This may exit with a non-zero status code even on success — `zap-baseline.py` uses the exit code to signal "warnings/alerts found," not "the scan crashed." Check `zap-reports/baseline-report.html` in a browser: if it opens and shows alert categories, the scan ran correctly.

## Task 2 — Get a session token for authenticated scanning

Create a throwaway account in your own lab (never reuse a real password anywhere):

```bash
curl -s -X POST http://127.0.0.1:3000/api/Users \
  -H 'Content-Type: application/json' \
  -d '{"email":"appsec-student@lab.local","password":"Str0ngLabPass!23","passwordRepeat":"Str0ngLabPass!23"}'

curl -s -X POST http://127.0.0.1:3000/rest/user/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"appsec-student@lab.local","password":"Str0ngLabPass!23"}'
```

The login response includes an `"authentication": {"token": "..."}` field. Copy that JWT — you'll inject it as a bearer token in Task 3.

## Task 3 — Authenticated full scan

```bash
docker run --rm --network appsec-lab \
  -v "$(pwd)/zap-reports:/zap/wrk/:rw" \
  zaproxy/zap-stable zap-full-scan.py \
  -t http://juice-shop:3000 \
  -z "-config replacer.full_list(0).description=auth \
      -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).regex=false \
      -config replacer.full_list(0).replacement='Bearer PASTE_YOUR_TOKEN_HERE'" \
  -J full-report.json -r full-report.html
```

This will take noticeably longer than the baseline scan — the active scanner is now sending crafted payloads to every discovered input, including ones only reachable once logged in (basket, checkout, profile). That's expected; go do something else for 10–20 minutes.

## Task 4 — Compare the two scans

Write `compare.py`:

```python
import json

def load(path):
    with open(path) as f:
        return json.load(f)

baseline = load("zap-reports/baseline-report.json")
full = load("zap-reports/full-report.json")

def alert_count(report):
    total = 0
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            total += len(alert.get("instances", []))
    return total

print(f"Baseline (anonymous) total alert instances: {alert_count(baseline)}")
print(f"Full scan (authenticated) total alert instances: {alert_count(full)}")
```

```bash
python3 compare.py
```

## Task 5 — Read three alerts critically

From `full-report.json`, pick three alerts of different **risk** levels (per Lecture 2, Section 6) and, in `alert-review.md`, for each one record: the alert name, its risk and confidence ratings, the specific URL/parameter it fired on, and your own verdict — is this a real, actionable finding, a low-priority informational note, or a likely false positive given the endpoint's actual context (Lecture 2, Section 6's JSON-API header example is exactly the kind of reasoning to apply here)?

## Expected result (spot checks)

- The authenticated full scan should report meaningfully more alert instances than the anonymous baseline — if it doesn't, your bearer-token injection likely isn't working; check the response body of one request to confirm you're actually logged in (Juice Shop's UI, loaded through the same token, should show you logged in).
- At least one of your three reviewed alerts should be Medium risk or higher.

## Done when…

- [ ] `baseline-report.json` and `full-report.json` both exist and open as valid HTML reports.
- [ ] `compare.py` runs and shows the authenticated scan finding more than the anonymous one.
- [ ] `alert-review.md` has three alerts reviewed with risk/confidence noted and a justified verdict for each.
- [ ] You can explain, from memory, why an anonymous crawl systematically undercounts an application's real attack surface — tying directly back to Week 1's `requires_auth` column in your `attack_surface` table.

## Stretch

- Add a second replacer rule targeting a different header, or try ZAP's AJAX spider (`-j` flag on `zap-baseline.py`) to see whether it discovers additional routes in Juice Shop's Angular front end that the plain HTML spider missed.
- Pick one Medium-or-higher alert and manually reproduce it with `curl` — construct the exact request ZAP describes and confirm the vulnerable behavior yourself, the DAST equivalent of Exercise 1's hand-traced taint flow.

## Submission

Commit `baseline-report.json`, `full-report.json`, `compare.py`, and `alert-review.md` to your portfolio under `c50-week-08/exercise-02/`. Keep both JSON reports exactly as produced — Exercise 3 loads `full-report.json` directly into your findings database.
