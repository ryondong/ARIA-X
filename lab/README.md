# ARIA-X auth lab

A deliberately broken app on loopback so the auth capability can be **scored**
instead of believed. No dependencies, no Docker, throwaway credentials.

```bash
./run-auth.sh lab        # http://127.0.0.1:8899
./run-auth.sh verify     # 7 capability checks, no model, no API key
```

## Faults and the one probe that proves each

| id | fault | proof | tool |
|----|-------|-------|------|
| L1 | username enumeration by response differential | `POST /login` with a known vs unknown user returns different messages | `http_matrix` variants / `http_request` |
| L2 | auth by unsigned `sid` cookie only | any `sid` in `SESSIONS` is accepted | `http_session` |
| L3 | IDOR on the object id | `/account/2` readable while signed in as alice | `id_walk`, `http_session` |
| L4 | trailing-slash handler skips the role check | `/admin` → 302, `/admin/` → 200 console | `http_matrix family=auth_presence` |
| L5 | `X-Forwarded-For` trusted as loopback | `GET /api/admin/users` with `X-Forwarded-For: 127.0.0.1` → 200 | `http_matrix family=header_trust` |
| L6 | `X-Original-URL` trusted | any value → 200 | `http_matrix family=header_trust` |
| L7 | JWT HS256, secret `secret`, role claim trusted | crack, re-forge `role=admin`, `/api/me` echoes it | `jwt_inspect --crack --forge` |
| L8 | 4-digit one-time code, no lockout, limiter keyed on XFF | 10k space, ~46 attempts on average | `code_probe --xff-rotate` |
| L9 | reset code echoed in the response | `POST /reset` body contains the code | `http_request` |
| L10 | `.git`, `.env`, `backup.sql`, `db.sqlite3` served | each returns 200 with a real body | `artifact_probe` |
| L11 | source map served, carrying a credential | `/static/app.js.map` → `sourcesContent` with `DB_PASSWORD` | `route_mine` |
| L12 | unauthenticated export | `GET /export?format=csv` returns the accounts CSV | `http_request` |
| L13 | soft-404 (200 + "Not Found") on everything unknown | `/nope` → 200 with the same 79-byte body | `artifact_probe` |
| L14 | internal notes JSON with no auth | `GET /api/v1/internal/notes` | `http_request` |
| L15 | session cookie issued before authentication | `GET /login` sets `sid` | `http_session` |
| L16 | captcha wall in front of a 2-digit code | `GET /secure/00` returns a reCAPTCHA-shaped 200 | `code_probe` (blocked), token lane (solved) |
| L17 | local solver stand-in | `POST /solver {sitekey}` → `tok-<sitekey>` | `ARIAX_SOLVER_URL` |
| L18 | RS256 verifier trusts the token's own alg | HS256 signed with `keys/rsa.pub` is accepted | `jwt_sign` |
| L19 | JS challenge that mints a clearance cookie | `GET /js/42` walls for urllib, clears for a browser | `browser_session` |

`db.sqlite3` additionally has a deleted row (`invoices.id = 3`, "Secret Co") that
is still in the file — use `sqlite3 db.sqlite3 ".recover"` after downloading it
through `artifact_probe` to practise the recovery path.

## Scoring

`verify_auth_capability.py` drives the real tools through the real registry, so
scope enforcement, rate limiting, evidence writing and redaction are all active.
It passes only when the tool lands the actual artifact, not when it returns 200.

Run it after every change to `src/aria_x/tools/auth.py`, and again after any
`git pull` from upstream.

## Rules

- Loopback only. Passwords are deliberately trivial.
- The lab rate-limits `/otp/*` and `/reset/verify` at 6 attempts per IP — that is
  a feature, not a bug: it is what the `xff_rotate` path exists for.
- Delete `lab/fixtures/` to regenerate the served artifacts.
- `run-auth.sh` points `ARIAX_SOLVER_URL` at `/solver` for you; a real key
  (`ARIAX_CAPTCHA_KEY`) takes precedence over the local stand-in.
