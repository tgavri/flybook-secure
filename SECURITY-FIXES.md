# SECURITY-FIXES — FlyBook
 
Remediations for the findings in the security assessment report.
Group: **[dit fulde navn]** and **Luka [efternavn]**.
 
Each section shows the **vulnerable code**, **why it is a problem**, and **the fix**.
The `hardening` branch contains the applied changes; compare it against `main` to see the full diff.
 
## Summary
 
| Finding | File | CWE | Fix in one line |
| --- | --- | --- | --- |
| F01 Command injection | `cgi-bin/status_check.cpp` | CWE-78 | Allow-list; no user input in any command |
| F02 Buffer overflow | `cgi-bin/status_check.cpp` | CWE-120 | `std::string` instead of `char[1024]`+`strcat` |
| F03 SQL injection | `api/API.php` | CWE-89 | Bound parameters in every query |
| F05 Unsalted MD5 | `api/API.php` | CWE-916 | `password_hash()`/`password_verify()` |
| F06 Hardcoded API key | `api/API.php` | CWE-798 | Key from env, `hash_equals()` |
| F07 Credentials in URL | `api/API.php` | CWE-598 | Login/booking moved to POST |
| F08 IDOR | `api/API.php` | CWE-639 | User derived from token, not request |
| F09 CSRF | `api/API.php` | CWE-352 | POST-only (+ TODO: CSRF token) |
| F10 Root DB user / hardcoded pw | `docker-compose.yml` | CWE-798/250 | Non-root user; secrets in `.env` |
| F11 Exposed DB port | `docker-compose.yml` | CWE-668 | Bound to `127.0.0.1` |
| F12 Container as root | `Dockerfile` | CWE-250 | `USER www-data`, `cap_drop`, `no-new-privileges` |
| F13 No TLS | `docker-compose.yml` | CWE-319 | Loopback + reverse-proxy TLS note |
| F17/F04/F14 Outdated images | `Dockerfile`, compose | CWE-1104 | `php:8.3`, `mysql:8.4` |
| F18/F19 XSS | `autocomp.js`, `service.html`, `API.php` | CWE-79 | `textContent`/`.text()` + CSP |
| F21 Missing headers | `api/API.php` | CWE-693 | CSP, X-Content-Type-Options, Referrer-Policy |
| F22 Info disclosure | server config | CWE-200 | Generic errors; `ServerTokens Prod` |
| F23 Predictable token | `api/API.php` | CWE-330/338 | `random_bytes()` instead of `md5(rand())` |
 
---
 
## F01 — OS command injection (CWE-78)
 
**Vulnerable code** (`cgi-bin/status_check.cpp`):
```cpp
char t[1024]="ps -eo lstart,cmd | grep ";
char *value = getenv("QUERY_STRING");
strcat(t,value);                       // attacker-controlled text appended
system(strcat(t," | grep -v grep | head -n 1 | awk ..."));
```
**Problem:** the HTTP query string is concatenated straight into a shell command and run with `system()`. Because the CGI container runs as root, a request such as `status_check?x;id` runs `id` as root. We proved this on an Intel machine: the payload returned `uid=0(root)`.
 
**Fix:** never put user input in a command. The request only *selects* a service from a fixed allow-list; the command is built from hardcoded strings only.
```cpp
std::string key = getenv("QUERY_STRING") ? getenv("QUERY_STRING") : "";
std::string target;
if      (key == "apache") target = "apache2";
else if (key == "mysqld") target = "mysqld";
else { std::cout << "invalid request\n"; return 0; }   // anything else is rejected
std::string cmd = "pgrep -a " + target;                // target is allow-listed, not user text
```
 
## F02 — Buffer overflow (CWE-120)
 
**Problem:** the same line uses a fixed `char t[1024]` and `strcat` with no length check. A query string longer than the buffer overflows it.
 
**Fix:** `std::string` grows automatically — there is no fixed buffer and no `strcat`.
 
## F03 — SQL injection (CWE-89)
 
**Vulnerable code** (`api/API.php`, one of six places):
```php
$records = $conn->prepare(
  'SELECT * FROM passengers WHERE email="'.$_GET['email'].'" and password= "'.md5($_GET['pass']).'"'
);
```
**Problem:** `prepare()` is called, but the values are concatenated into the string, so there are no real placeholders — it gives zero protection. Logging in with `email=" OR "1"="1" -- -` and any password returned the **entire passengers table** (names, e-mails, passport numbers, password hashes, tokens).
 
**Fix:** real bound parameters in every query.
```php
$stmt = $conn->prepare('SELECT * FROM passengers WHERE email = :email');
$stmt->bindValue(':email', $email, PDO::PARAM_STR);
$stmt->execute();
```
We also set `PDO::ATTR_EMULATE_PREPARES => false` so the database, not PHP, handles the parameters.
 
## F05 — Unsalted MD5 password hashing (CWE-916)
 
**Vulnerable code:** `md5($_GET['pass'])`.
 
**Problem:** MD5 is fast and unsalted, so identical passwords produce identical hashes and rainbow tables work. After the F03 dump we recovered the plaintext (`alice-1234`, `bob-1234`) instantly — `md5('alice-1234')` equals the stored hash exactly.
 
**Fix:** `password_verify()` against a bcrypt/Argon2 hash created with `password_hash()`. Existing MD5 rows must be reset (see migration note below).
 
## F06 — Hardcoded API "key" (CWE-798)
 
**Problem:** the only API authentication was a string literal in the source: `if($_GET["API_KEY"]=="Flight booker 1.2 plus edition")`. Anyone reading the code (or traffic) has it.
 
**Fix:** the key is read from the environment and compared in constant time with `hash_equals()`.
 
## F07 — Credentials in GET (CWE-598)
 
**Problem:** e-mail, password and token travelled as URL query parameters, so they end up in browser history and server access-logs.
 
**Fix:** `Login()` and `Book()` accept only POST and read `$_POST`, keeping secrets out of the URL.
 
## F08 — IDOR on booking (CWE-639)
 
**Vulnerable code:**
```php
'INSERT INTO bookings (passenger, flight,status) VALUES ('" . $_GET['passenger'] . "', ...)'
```
**Problem:** the booking trusted the `passenger` id from the request, so a user could book (or act) as someone else.
 
**Fix:** the user is looked up **from the session token**, and the booking is tied to that id — the request can no longer choose the passenger.
```php
$stmt = $conn->prepare('SELECT id FROM passengers WHERE token = :token');
// ... then INSERT uses $user['id'], never a request parameter
```
 
## F09 — CSRF (CWE-352)
 
**Problem:** booking was a state change over GET with no anti-CSRF token, so a crafted link could trigger it.
 
**Fix:** state changes are POST-only. **TODO:** add a per-session CSRF token (noted, not yet in code).
 
## F10–F12 — Container & database hardening (CWE-250/798/668)
 
**Vulnerable config** (`docker-compose.yml`): DB root password `12345678` hardcoded, app connects as `root`, port `3307:3306` exposed on all interfaces; `Dockerfile` has no `USER` so everything runs as root.
 
**Fix:**
- Non-root `flybook_app` DB user; passwords come from `.env` (git-ignored), nothing hardcoded (F10).
- DB port bound to `127.0.0.1:3307` only (F11).
- `USER www-data`, `cap_drop: [ALL]`, `security_opt: no-new-privileges` (F12).
## F13 — No TLS (CWE-319)
 
**Fix:** services bound to loopback; run behind a TLS-terminating reverse proxy with HSTS (documented, as TLS is an infrastructure change).
 
## F17 / F04 / F14 — Outdated images (CWE-1104)
 
**Problem:** `php:7.3-apache` (PHP 7.3 is end-of-life, with KEV CVEs) and an old `mysql:8.0`.
 
**Fix:** `php:8.3-apache` and `mysql:8.4`, to be rebuilt regularly. A `HEALTHCHECK` was also added (F15).
 
## F18 / F19 — Cross-site scripting (CWE-79)
 
**Vulnerable code** (`web-app/vendor/autocomp.js`): `b.innerHTML += "<input ... value='" + arr[i] + "'>"` — airport names from the database written as HTML; and `service.html` inserting CGI output with jQuery `.html(res)`.
 
**Fix:** build DOM nodes with `textContent`/`createTextNode` and use jQuery `.text()`, so data is never parsed as HTML. A `Content-Security-Policy` header is added as defence in depth.
 
## F21 — Missing security headers (CWE-693)
 
**Fix:** `API.php` now sends `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
 
## F22 — Information disclosure (CWE-200/209)
 
**Problem:** the default Apache error page and `$e->getMessage()` leaked versions and internal detail.
 
**Fix:** generic JSON errors to the client, detail only to the server log; set `ServerTokens Prod` / `ServerSignature Off` in Apache config.
 
## F23 — Predictable session token (CWE-330/338)
 
**Vulnerable code:** `$token = md5(rand());`
 
**Problem:** `rand()` is not cryptographically secure, so tokens are predictable and sessions can be hijacked. SonarQube flagged both the weak hash and the weak PRNG here.
 
**Fix:** `$token = bin2hex(random_bytes(32));` — a cryptographically secure 256-bit token.
 
---
 
## Migration note (F05)
`password_verify()` needs passwords stored with `password_hash()`:
```php
$hash = password_hash($plaintextPassword, PASSWORD_DEFAULT);
```
The seeded MD5 rows must be reset (e.g. force a password change on next login) before the fixed login works.
 
## Remaining hardening (not yet in code)
- Per-session anti-CSRF token on all POST actions (F09).
- TLS termination + HSTS at a reverse proxy (F13).
- Subresource Integrity on external `<script>`/`<link>` (F20).
- `.well-known/security.txt` (F16).
- Compile `status_check.cpp` during the Docker build (the binary is git-ignored).
