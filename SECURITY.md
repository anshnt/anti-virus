# Security model

Sentinel Local is a single-user Windows antivirus development build with an independent ClamAV engine and optional Defender integration. It is not designed for public hosting, shared network access or hostile local administrators. Detection superiority and production certification have not been established.

## Boundaries to preserve

- Bind only to `127.0.0.1`. Require the exact Host and reject foreign origins. Never add permissive CORS.
- A launch nonce is used once and rotated. Sensitive API reads and writes require both an HttpOnly/SameSite session cookie and a private header token. Cookies are shared across ports, so a cookie alone must never unlock the API or recover its token.
- The private token is delivered in the launch redirect's URL fragment, immediately removed from the address bar, and stored in browser session storage for the exact origin/port. Request targets containing launch secrets must not be logged.
- Serve only the three explicitly allowed web assets. Never serve the application directory, data directory or arbitrary file paths.
- Treat file names, publishers, startup values and event fields as untrusted text. Use DOM text nodes rather than HTML interpolation.
- Do not accept arbitrary process commands. PowerShell scripts are constant; user paths travel as JSON on stdin. Use argument arrays, `shell=False`, and the trusted Windows module directory.
- Require a valid Microsoft publisher signature on the installed Defender command tool before invoking it.
- The independent engine must come from the pinned official ClamAV release archive with its exact size/SHA-256. Validate installed program/DLL/certificate hashes before execution. Production scanning uses only official databases. FreshClam validates database updates; respect its CDN throttling/cooldown. No general custom-database upload route is exposed.
- Run untrusted parsing in the separate engine process. Scan private stable snapshots, associate output only with those generated paths, and store the SHA-256 of the bytes actually scanned. Process errors and incomplete/limited results must not turn into clean results or actionable signature detections.
- Quarantine requires an open independent-engine signature detection. Lock and verify the original handle, reject protected paths/links, compare its current content hash, persist an encrypted DPAPI copy and metadata, and verify recovery before deleting through that exact handle. Never remove a pathname after releasing the identity check.
- Keep prepared/removal-unverified vault records recoverable after a crash or removal failure. Recovery must verify integrity, create a separate `.restored` file and never overwrite or execute an original. DPAPI needs the original Windows account/key material and does not defeat same-account malware.
- Persist recovery intent and a unique destination before writing. Audit pending vault operations only in the single-instance engine's startup path. Verify ciphertext and completed output hashes; preserve partial/changed outputs and retry into a new path. Never infer successful original removal or retry deletion after restart. Reject links/hard links in encrypted/recovery files. Database and encryption files still require the underlying disk/Windows profile to survive; this is not an external backup or a guarantee against hardware failure.
- The Test Center accepts no caller-supplied sample/database paths. Its fixed harmless marker, test-only signature, evidence ledger, encrypted vault and recovery outputs live in an isolated temporary workspace. Production scanning retains official-only databases. Synthetic positives must never be counted as PC infections or malware efficacy evidence. A forced process termination can leave harmless temporary diagnostic files; normal completion/failure cleans the workspace.
- Scan success requires matching event evidence. Exit code zero or an end timestamp cannot override a cancellation event. Keep uncertain results unverified.
- Never delete or quarantine files because of heuristic patterns, missing signatures, changed hashes, unfamiliar startup entries or open ports. Defender retains its existing remediation policy.
- Preserve Windows protection, firewall, tamper protection and exclusions. A missing check is not a safe default.
- Do not kill a running scan to quit the console. Windows shutdown, sign-out or forced termination can still interrupt work.
- Optional sign-in launch may modify only the app's own current-user Run entry after explicit UI selection. Unknown/conflicting values must be left alone. A per-user Run entry is not an elevated service or pre-login protection.

## Data and limits

Runtime state belongs in `%LOCALAPPDATA%\SentinelLocal`, restricted to the current account, SYSTEM and Administrators. Reports can contain private paths, IP addresses and security configuration. The repository and release ZIP must not contain runtime databases, instance files, access tokens or real PC reports.

This user-level monitor is not tamper resistant. It can miss transient changes, unsupported persistence mechanisms, evasion, packed malware and events outside the bounded history. The static script patterns are review aids. A local account or administrator can inspect or alter the app's state. Defender cloud behavior is controlled by existing Windows policy.

## Reporting a vulnerability

If GitHub's private vulnerability reporting is available, use the repository's Security tab. Do not place live session links, credentials, private PC reports or executable malware in a public issue. For a public report, provide a minimal benign reproduction and redact machine-specific details.

Security-relevant changes should include a regression that fails when the affected boundary is removed. Run the existing HTTP and scan-evidence tests before changing any authentication, process launch, file path or completion logic.
