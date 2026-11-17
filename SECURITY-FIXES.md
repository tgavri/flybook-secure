# SECURITY-FIXES — FlyBook

Remediations for the findings in the security assessment report. Group: **[dit fulde navn]** and **Luka [efternavn]**.

Each change is mapped to its finding ID and CWE. See the report for full detail.

| Finding | Fix | File | CWE |
| --- | --- | --- | --- |
| F01 Command injection | Removed `system()`; strict allow-list selects a hardcoded process name, no user input in any command | `cgi-bin/status_check.cpp` | CWE-78 |
| F02 Buffer overflow | `std::string` instead of fixed `char[1024]` + `strcat` | `cgi-bin/status_check.cpp` | CWE-120 |
| F03 SQL injection | Real prepared statements with bound parameters in every query | `api/API.php` | CWE-89 |
| F05 Unsalted MD5 | `password_verify()` (bcrypt/Argon2) instead of `md5()`; see migration note below | `api/API.php` | CWE-916 |
| F06 Hardcoded API key | API key read from env, compared with `hash_equals()` | `api/API.php` | CWE-798 |
| F07 Creds in GET | Login/booking moved to POST body | `api/API.php` | CWE-598 |
| F08 IDOR | Booking user derived from the session token, never from a request parameter | `api/API.php` | CWE-639 |
| F09 CSRF | State changes are POST-only; add a per-session CSRF token (see TODO) | `api/API.php` | CWE-352 |
| F10 Root DB user / hardcoded pw | Non-root `flybook_app` user; secrets from `.env`, not committed | `docker-compose.yml`, `.env.example` | CWE-798/250 |
| F11 Exposed DB port | DB bound to `127.0.0.1:3307` only | `docker-compose.yml` | CWE-668 |
| F12 Container as root | `USER www-data`, `cap_drop: [ALL]`, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` | CWE-250 |
| F13 No TLS | Services bound to loopback; run behind a TLS reverse proxy with HSTS | `docker-compose.yml` | CWE-319 |
| F15 No healthcheck | `HEALTHCHECK` added | `Dockerfile` | — |
| F17/F04/F14 Outdated images | `php:8.3-apache`, `mysql:8.4` | `Dockerfile`, `docker-compose.yml` | CWE-1104 |
| F18/F19 XSS | `textContent` / `.text()` instead of `innerHTML` / `.html()`; CSP header | `web-app/vendor/autocomp.js`, `web-app/service.html`, `api/API.php` | CWE-79 |
| F20 Outdated JS libs / no SRI | Update jQuery/Bootstrap; add `integrity` + `crossorigin` to script tags | `web-app/*.html` | CWE-1104/353 |
| F21 Missing headers | CSP, X-Content-Type-Options, Referrer-Policy set | `api/API.php` | CWE-693 |
| F22 Info disclosure | Generic error responses; set `ServerTokens Prod`, `ServerSignature Off` | server config | CWE-200 |
| F23 Predictable token | `bin2hex(random_bytes(32))` instead of `md5(rand())` | `api/API.php` | CWE-330/338 |

## Migration note (F05)
`password_verify()` needs passwords stored with `password_hash()`. Add a registration/password-set path that calls:
```php
$hash = password_hash($plaintextPassword, PASSWORD_DEFAULT);
```
and store `$hash`. Existing MD5 rows must be reset (e.g. force a password change on next login).

## TODO (further hardening, not yet in code)
- Per-session anti-CSRF token on all POST actions (F09).
- TLS termination + HSTS at a reverse proxy (F13).
- Subresource Integrity hashes on external `<script>`/`<link>` (F20).
- `.well-known/security.txt` (F16).

## Client-side XSS fixes (snippets)

**`web-app/vendor/autocomp.js`** — replace the three `innerHTML` lines (around 25–28) with:
```js
var strong = document.createElement("strong");
strong.textContent = arr[i].substr(0, val.length);
b.appendChild(strong);
b.appendChild(document.createTextNode(arr[i].substr(val.length)));
var hidden = document.createElement("input");
hidden.type = "hidden";
hidden.value = arr[i];
b.appendChild(hidden);
```

**`web-app/service.html`** — lines 77 and 86, change `.html(res)` to `.text(res)`:
```js
$('#mysqlStart').text(res);
$('#apacheStart').text(res);
```
