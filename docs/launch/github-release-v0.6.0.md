# GitHub Release v0.6.0 — copy/paste

## Release settings

- **Tag:** `v0.6.0` (from `main`, after the version bump is merged)
- **Title:** `v0.6.0 — supply-chain malware, Java dependency scanning, AI malware triage`

---

## Release notes

### Argus v0.6.0

Free and open source (MIT). Created by Okiri Gabriel.

#### Supply-chain and worm malware

- **Install-script malware (npm):** `preinstall` / `postinstall` / `prepare` hooks that download and run code, run inline code or decode payloads are flagged, and a hook can't hide behind `npm run`. Common tools (husky, patch-package, node-gyp, prisma, tsc…) are allowed. (#170)
- **Credential stealers:** a file that reads several credential stores (npm/GitHub tokens, cloud metadata, Vault, Kubernetes, AWS/GCP, SSH, wallets) and also makes a network call is flagged. So are TruffleHog/Gitleaks run from code and common exfiltration endpoints. (#170)
- **Worm spreading:** package code that runs `npm publish`, `twine upload` or `gem push`, or lists a maintainer's npm packages, is flagged. Release tooling is excluded. (#170)
- **Known-malicious packages:** every lockfile package (npm, yarn, pnpm, poetry, uv, requirements, composer, Maven/Gradle) is checked against OSV's confirmed-malware (`MAL-`) records and reported as critical. (#168, #171)
- **Remote dependency sources:** dependencies installed over plain HTTP, from archives, or from git without a pinned commit. (#167, thanks @daniyyell-dev)

#### Java and Kotlin

- **Maven/Gradle dependency CVEs without Trivy:** reads `pom.xml` (with `${properties}`), `gradle.lockfile`, `build.gradle(.kts)` and version catalogs, and reports CVEs with the nearest fixed version (e.g. Log4Shell → 2.15.0). (#171)
- **Java, Kotlin and Spring rules in the npm package:** SQL injection, XXE, LDAP injection, unsigned JWTs, Spring Security `permitAll()` / CSRF disabled, JSP web shells, Spring Boot Actuator and H2 console. Same rules as the Python package. (#172)

#### AI

- **`triage_malware` MCP tool:** bounded, redacted evidence snippets and safe text-only decoding, so your AI assistant can explain whether a suspicious file looks malicious. Nothing is executed. (#161, thanks @Holmes-R)

#### Fewer false positives

- **Command injection:** only shell execution with dynamic input is flagged, across Python, JS/TS, Java, Go, Ruby, C#, Perl and shell. Argument-list calls and `regex.exec()` are no longer reported. (#160, thanks @Holmes-R)
- **Method calls:** `redis.eval()` and other `.eval()` / `.exec()` method calls are no longer treated as code execution. (#169)
- **npm SQL rule:** parameterized queries and log messages are no longer flagged. (#169)
- **JSP rule:** ordinary Java code that starts a process (`ProcessBuilder`) is no longer reported as a critical JSP web shell. (#172)

#### Reports and docs

- **npm audit:** findings show the installed version of the affected package. Opengrep paths are relative. (#169)
- **Docs:** new [usage guide by language](https://github.com/argus-code-scanning/argus-codescan-mcp/blob/main/docs/usage-by-language.md) covering Java, Kotlin, Python, Node, PHP, Go and more. (#173)
- **Offline:** `--no-network` / `ARGUS_NO_NETWORK=1` turns off online lookups.

---

## Install

```bash
pip install -U argus-scan          # pulls argus-languages 0.5.0
npx argus-codescan@0.9.0 scan all . --fail-on high
docker pull ghcr.io/argus-code-scanning/argus-codescan-mcp:0.6.0
```

| Package | Version |
|---|---|
| `argus-scan` (PyPI) | 0.6.0 (requires `argus-languages>=0.5.0`) |
| `argus-languages` (PyPI) | 0.5.0 |
| `argus-codescan` (npm) | 0.9.0 |
| Docker image (GHCR) | 0.6.0 |
