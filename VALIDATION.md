# Validation and limits

## 2.1 development update: restart recovery and interactive diagnostics

The complete local suite contains **89 tests**, all passing on Windows/Python 3.13 on 15 October 2026. Fourteen new tests cover forced interruption before and after source removal, written/partial/missing recovery outputs, corrupted encrypted copies, foreign recovery paths, hard links, second-client isolation, engine-verification failure, missing definitions, unexpected official findings and diagnostic isolation/cleanup and Windows temporary-path canonicalization. JavaScript syntax and source packaging also passed. CI results must be verified separately after pushing.

The installed application's **Test Center** was run through its browser button. All six checks passed in **23.0 seconds**: three harmless files scanned with official databases (21.9 seconds; no findings/skips/errors), two expected matches against an isolated synthetic signature (plain text and ZIP), actual Windows DPAPI quarantine, exact-byte recovery, production-ledger isolation and temporary workspace cleanup. No real malware or EICAR was created, downloaded or executed. The synthetic signature never entered the production database directory. No browser errors were observed in the demonstrated flow.

Recovery interruption tests inject abrupt process-loss exceptions around real file/encryption operations. They are not physical power-cut, disk-controller failure, filesystem-corruption or complete process-kill campaigns. Startup audits preserve originals and partial outputs rather than retrying deletion. Wider destructive durability testing belongs in disposable test systems.

This update does not implement a privileged system service, signed kernel blocker, behavioral/ransomware protection or an independent comparison with Defender. It does not make the full antivirus product target complete.

## Independent-engine development build

The expanded build adds independent ClamAV scanning, official definition updates, stable batched snapshots, post-arrival Downloads scans, cancellation, optional sign-in launch and DPAPI quarantine/recovery. Its product target and incomplete production gates are documented in [PRODUCT_PLAN.md](PRODUCT_PLAN.md).

Live validation on 15 October 2026 installed the official ClamAV 1.5.4 x64 archive after verifying its pinned release SHA-256, updated official CVD databases through FreshClam, and scanned four benign files (including an empty file and a Unicode filename) successfully. The observed cold scan took 21.5 seconds. This tiny corpus is not a throughput or false-positive benchmark.

An isolated test-only hash signature matched a harmless text marker and the same marker inside a ZIP. The detected benign fixture then exercised encrypted quarantine and separate-copy recovery. Production databases and real detection history were not modified by this synthetic test. No real malware or EICAR was downloaded, created or executed.

New regressions exercise archive traversal, release digest rejection, engine file tampering, stable byte hashes, exact snapshot/result association, false filename output, scan limits/errors/cancellation, background policy, startup conflicts, DPAPI integrity, source-change races, hard links, exclusive file locks, encryption/recovery failures and crash-safe vault records. Windows malformed-request handling was hardened to drain only small bounded rejected bodies before closing, so an unread body cannot routinely discard its error response on Windows.

The complete development suite now contains **75 tests**, including regressions preventing a second installer/engine client from deleting active scan snapshots and bounding recovery names for long original filenames. In the real installed app, an independent scan submitted from the browser completed successfully; a separate scan was cancelled without changing its original file; and a newly created harmless Downloads file was automatically scanned by the independent background worker. Its fixture was removed after validation. Sign-in launch remained off, and pre-execution blocking remained explicitly unimplemented. These checks do not establish detection superiority.

Full-PC throughput, pre-execution blocking, behavioral detection, privileged service/driver behavior and comparative malware efficacy against Defender remain unvalidated. No production-safety or superiority claim follows from these integration checks.

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
