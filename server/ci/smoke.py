#!/usr/bin/env python3
"""End-to-end smoke against a running API server."""
import json, sys, urllib.request

BASE = "http://127.0.0.1:8985"

def call(method, path, body=None, cookie=None, headers=None):
    hdrs = {}
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    if cookie: hdrs["Cookie"] = cookie
    if headers: hdrs.update(headers)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{BASE}{path}", data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req) as r:
            set_cookie = r.headers.get("Set-Cookie", "")
            return r.status, r.read().decode(), set_cookie
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), ""

def ok(label, status, expected):
    mark = "PASS" if status == expected else "FAIL"
    print(f"{mark}  {label}: {status}")
    return status == expected

fails = 0

# health
s, _, _ = call("GET", "/healthz")
if not ok("health", s, 200): fails += 1

# signup with fake-but-shell-safe email
s, body, sc = call("POST", "/api/v1/auth/signup", {
    "email": "grace@hopper.mil",
    "password": "so-many-bugs-so-little-time",
    "orgName": "Northwind Travel",
})
if not ok("signup", s, 201): fails += 1
cookie = sc.split(";")[0] if sc else None

# me
s, me, _ = call("GET", "/api/v1/auth/me", cookie=cookie)
if not ok("me (authed)", s, 200): fails += 1
print("      user:", json.loads(me)["user"]["email"])

# me unauth
s, _, _ = call("GET", "/api/v1/auth/me")
if not ok("me (unauth)", s, 401): fails += 1

# create deployment
s, body, _ = call("POST", "/api/v1/deployments", {"name": "prod", "environment": "production"}, cookie=cookie)
if not ok("create deployment", s, 201): fails += 1
d = json.loads(body)
dep_id, token = d["deployment"]["id"], d["ingestToken"]
print(f"      id={dep_id} token={token[:8]}...")

# list deployments
s, body, _ = call("GET", "/api/v1/deployments", cookie=cookie)
if not ok("list deployments", s, 200): fails += 1
print(f"      count={len(json.loads(body)['deployments'])}")

# ingest headers
daemon = {"Authorization": f"Bearer {token}", "X-AV-Deployment": dep_id}

# upsert session
s, _, _ = call("POST", "/api/v1/ingest/sessions", {
    "externalId": "sess-real-1", "agent": "refund-agent",
    "openedAt": "2026-08-24T09:12:04Z",
}, headers=daemon)
if not ok("ingest session", s, 200): fails += 1

# ingest events
s, body, _ = call("POST", "/api/v1/ingest/events", [
    {"sessionExternalId": "sess-real-1", "seq": 0, "kind": "sys", "tag": "SESSION",
     "body": "sess-real-1 opened", "occurredAt": "2026-08-24T09:12:04Z"},
    {"sessionExternalId": "sess-real-1", "seq": 1, "kind": "tool", "tag": "TOOL",
     "body": "lookup_booking", "occurredAt": "2026-08-24T09:12:26Z",
     "addToolsAllowed": 1, "addPromptTokens": 1408, "addCostUsdMicros": 4100},
    {"sessionExternalId": "sess-real-1", "seq": 2, "kind": "block", "tag": "BLOCKED",
     "body": "HTTP 403 issue_refund $8400", "occurredAt": "2026-08-24T09:13:41Z",
     "addToolsBlocked": 1, "addBlockedPayoutUsdMicros": 8400000000},
], headers=daemon)
if not ok("ingest events", s, 200): fails += 1
print("      inserted:", json.loads(body)["inserted"])

# ingest duplicate — must be idempotent
s, body, _ = call("POST", "/api/v1/ingest/events", [
    {"sessionExternalId": "sess-real-1", "seq": 0, "kind": "sys", "tag": "SESSION",
     "body": "sess-real-1 opened (dup)", "occurredAt": "2026-08-24T09:12:04Z"},
], headers=daemon)
if not ok("ingest duplicate events (idempotent)", s, 200): fails += 1

# ingest bad token
s, _, _ = call("POST", "/api/v1/ingest/sessions", {
    "externalId": "x", "agent": "a", "openedAt": "2026-08-24T09:12:04Z",
}, headers={"Authorization": "Bearer nope", "X-AV-Deployment": dep_id})
if not ok("ingest bad token", s, 401): fails += 1

# ingest missing headers
s, _, _ = call("POST", "/api/v1/ingest/sessions", {
    "externalId": "x", "agent": "a", "openedAt": "2026-08-24T09:12:04Z",
})
if not ok("ingest missing headers", s, 401): fails += 1

# overview
s, body, _ = call("GET", "/api/v1/overview", cookie=cookie)
if not ok("overview", s, 200): fails += 1
ov = json.loads(body)
print(f"      sessions={ov['stats']['sessions']} tools_allowed={ov['stats']['toolsAllowed']} tools_blocked={ov['stats']['toolsBlocked']}")

# read one session
sess_id = ov["sessions"][0]["id"]
s, body, _ = call("GET", f"/api/v1/sessions/{sess_id}", cookie=cookie)
if not ok("read session", s, 200): fails += 1
events = json.loads(body)["session"]["events"]
print(f"      events in stream: {len(events)}")

# weak password
s, _, _ = call("POST", "/api/v1/auth/signup", {
    "email": "weak@test.dev", "password": "short", "orgName": "X",
})
if not ok("weak password rejected", s, 400): fails += 1

# duplicate email
s, _, _ = call("POST", "/api/v1/auth/signup", {
    "email": "grace@hopper.mil", "password": "correct-horse-battery-staple", "orgName": "Y",
})
if not ok("duplicate email rejected", s, 409): fails += 1

# tenant isolation: create a second org, verify its overview is empty
s, sig, sc2 = call("POST", "/api/v1/auth/signup", {
    "email": "linus@torvalds.fi", "password": "just-for-fun-linus-1991",
    "orgName": "Torvalds Ltd",
})
if not ok("second signup", s, 201): fails += 1
cookie2 = sc2.split(";")[0] if sc2 else None
s, body, _ = call("GET", "/api/v1/overview", cookie=cookie2)
if not ok("tenant isolation: fresh org empty", s, 200): fails += 1
print(f"      second org sessions={json.loads(body)['stats']['sessions']}")

# rotate token
s, body, _ = call("POST", f"/api/v1/deployments/{dep_id}/rotate-token", None, cookie=cookie)
if not ok("rotate token", s, 200): fails += 1
new_token = json.loads(body)["ingestToken"]

# old token no longer works
s, _, _ = call("POST", "/api/v1/ingest/sessions", {
    "externalId": "x", "agent": "a", "openedAt": "2026-08-24T09:12:04Z",
}, headers={"Authorization": f"Bearer {token}", "X-AV-Deployment": dep_id})
if not ok("old token revoked", s, 401): fails += 1

# new token works
s, _, _ = call("POST", "/api/v1/ingest/sessions", {
    "externalId": "sess-real-2", "agent": "a", "openedAt": "2026-08-24T09:12:04Z",
}, headers={"Authorization": f"Bearer {new_token}", "X-AV-Deployment": dep_id})
if not ok("new token works", s, 200): fails += 1

print()
if fails == 0:
    print("ALL BACKEND CHECKS PASSED")
else:
    print(f"{fails} FAILURES")
    sys.exit(1)
