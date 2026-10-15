# Security model

Sentinel Local is a personal, single-user Windows console built on Microsoft Defender. It is not designed for public hosting, shared network access, hostile local administrators or malware detection certification.

## Boundaries to preserve

- Bind only to `127.0.0.1`. Require the exact Host and reject foreign origins. Never add permissive CORS.
- A launch nonce is used once and rotated. Sensitive API reads and writes require both an HttpOnly/SameSite session cookie and a private header token. Cookies are shared across ports, so a cookie alone must never unlock the API or recover its token.
- The private token is delivered in the launch redirect's URL fragment, immediately removed from the address bar, and stored in browser session storage for the exact origin/port. Request targets containing launch secrets must not be logged.
- Serve only the three explicitly allowed web assets. Never serve the application directory, data directory or arbitrary file paths.
- Treat file names, publishers, startup values and event fields as untrusted text. Use DOM text nodes rather than HTML interpolation.
- Do not accept arbitrary process commands. PowerShell scripts are constant; user paths travel as JSON on stdin. Use argument arrays, `shell=False`, and the trusted Windows module directory.
- Require a valid Microsoft publisher signature on the installed Defender command tool before invoking it.
- Scan success requires matching event evidence. Exit code zero or an end timestamp cannot override a cancellation event. Keep uncertain results unverified.
- Never delete or quarantine files because of heuristic patterns, missing signatures, changed hashes, unfamiliar startup entries or open ports. Defender retains its existing remediation policy.
- Preserve Windows protection, firewall, tamper protection and exclusions. A missing check is not a safe default.
- Do not kill a running scan to quit the console. Windows shutdown, sign-out or forced termination can still interrupt work.

## Data and limits

Runtime state belongs in `%LOCALAPPDATA%\SentinelLocal`, restricted to the current account, SYSTEM and Administrators. Reports can contain private paths, IP addresses and security configuration. The repository and release ZIP must not contain runtime databases, instance files, access tokens or real PC reports.

This user-level monitor is not tamper resistant. It can miss transient changes, unsupported persistence mechanisms, evasion, packed malware and events outside the bounded history. The static script patterns are review aids. A local account or administrator can inspect or alter the app's state. Defender cloud behavior is controlled by existing Windows policy.

## Reporting a vulnerability

If GitHub's private vulnerability reporting is available, use the repository's Security tab. Do not place live session links, credentials, private PC reports or executable malware in a public issue. For a public report, provide a minimal benign reproduction and redact machine-specific details.

Security-relevant changes should include a regression that fails when the affected boundary is removed. Run the existing HTTP and scan-evidence tests before changing any authentication, process launch, file path or completion logic.
