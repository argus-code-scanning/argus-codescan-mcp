# GitHub Release v0.7.0 — copy/paste

## Release settings

- **Tag:** `v0.7.0` (from `main`, after the version bump is merged)
- **Title:** `v0.7.0 — threat intelligence, template injection, rate-limit & lockout checks`

---

## Release notes

### Argus v0.7.0

Free and open source (MIT). Created by Okiri Gabriel.

#### Threat intelligence (new: `argus scan threats`)

- Matches your repository against **known indicators of compromise**: malware URLs, attacker domains and IPs, and malware file hashes. A match is critical.
- Sources: your own `.argus/iocs.txt`, plus abuse.ch ThreatFox, URLhaus and MalwareBazaar with a free Auth-Key (`ARGUS_ABUSECH_AUTH_KEY`).
- Matching is local; nothing from your code is uploaded. Also runs inside `scan malware` and `scan all`, and as the MCP tool `scan_threats`. (#184)

#### API abuse: missing rate limiting and login lockout (new)

- Finds login, token, password-reset, OTP and register endpoints and reports when there is **no rate limiter** or **no account lockout** (brute force, credential stuffing, OTP guessing).
- Works across 10 languages and 24 frameworks: Express, NestJS, Fastify, Flask, FastAPI, Django, Spring, JAX-RS, Ktor, Laravel, Symfony, Slim, Rails, Sinatra, Go (net/http, gin, echo, chi, Fiber), ASP.NET Core, Rust (actix, axum) and Phoenix. It recognises each ecosystem's own rate limiters, including custom ones. (#192)

#### Template injection (SSTI, new)

- Flags user input that becomes a **template** in Flask/Jinja2, Django, EJS, Pug, Handlebars, Nunjucks, lodash, Twig, Blade, Smarty, FreeMarker, Velocity and ERB. This usually leads to remote code execution. Template files and fixed templates are not flagged.
- In both the Python and the npm package. (#190)

#### Supply-chain and malware

- **Malicious GitHub Actions:** workflows that dump all secrets, send secrets out, run encoded payloads or crypto miners, and self-hosted runners reachable from pull requests. (#184)
- **Crypto drainers:** clipboard hijackers that swap wallet addresses, and permit-phishing signatures. (#184)
- **Python install-time malware:** `setup.py` install hooks that download or run code, and `.pth` files that run code at every Python start. (#176)
- **npm native-build hooks:** commands in `binding.gyp` that run on `npm install` even without install scripts. (#177)

#### Maintenance

- Argus's own dependencies have 0 known vulnerabilities; CI runs on Node 20, 22 and 24 (Node 18 is end-of-life). The npm package now requires Node 20+. (#178)

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.6.0
npx argus-codescan@0.10.0 scan all . --fail-on high
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:0.7.0
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.7.0 (requires `argus-languages>=0.6.0`) |
| `argus-languages` (PyPI) | 0.6.0 |
| `argus-codescan` (npm) | 0.10.0 (Node 20+) |
| Docker image (GHCR) | 0.7.0 |
