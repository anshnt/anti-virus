# Validation and limits

The initial app was validated on Windows 11 with Python 3.13 on 15 October 2026. The published source includes portable launcher paths and neutral remote-access wording rather than a particular user's personal preferences.

## Automated checks

The original 33-test suite covers scan GUID correlation, cancellation winning over successful process metadata, absent/ambiguous evidence, file hashing limits, unsafe path rejection, integrity changes, safe watch removal, stale job recovery and PowerShell input isolation.

HTTP tests cover launch nonce rotation, cookie flags, expiry, private-header access for API reads/writes, cookie-only rejection, Host/Origin/CSRF checks, malformed tokens, bounded request bodies, static path traversal, export without session fields, unknown actions and safe quit. Three portable-launcher/source-package regressions bring the published suite to **36 tests, all passed locally on Python 3.13**. The JavaScript syntax check and source ZIP verification also passed. Windows CI is configured to run the full suite on Python 3.11 and 3.13; its result must be checked after pushing.

## Live checks completed on the original installation

- Windows protection, firewall, signature, remote-access, startup and TCP evidence was read successfully; protected exclusions remained visibly unavailable to a standard user.
- A Microsoft-signed Defender command tool completed a real custom scan of a harmless local README, with correlated start and completion events. This passed again after API authentication changes.
- A signature update completed successfully. A Windows executable was inspected without execution and returned its full SHA-256 and valid Microsoft signature.
- A harmless watched file was edited and detected as changed. Removing its watch preserved the file.
- A comment-only script fixture in Downloads produced a review alert and was removed after validation. No test payload was executed.
- Safe quit/reopen, loopback-only listening and application-data directory ACLs were verified.
- The dashboard, file inspection submission, remote-access inventory, startup inventory, network tables, review filter and authenticated report download were checked in the browser. The desktop layout was visually inspected and no console errors were observed in the tested flow.

No machine-specific reports, host names, user names, IP addresses, runtime records or screenshots from that installation are included in this repository.

## Not established by these checks

No test malware was downloaded or created. This is not an independent malware benchmark, penetration test or antivirus certification. No new full multi-hour scan was run for application validation. Prior interrupted scans were kept as interrupted rather than marked complete.

The complete native Windows Security and print-dialog flows, administrator-only policy visibility, reboot behavior, other viewport sizes, hostile local users, huge directories and third-party antivirus integration were not separately validated. Passing tests do not prove that every threat is detected or that every Windows configuration is supported.
