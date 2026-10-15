# Sentinel Local

A Windows antivirus **development build with an independent ClamAV engine**, official signature updates, encrypted quarantine and local background scanning. Defender remains an additional Windows protection layer. The product target is a full antivirus, but this build is not yet a certified replacement and has not been shown to outperform Defender. See [the product target and release gates](PRODUCT_PLAN.md).

## Run locally

1. Install **Python 3.11 or newer** on 64-bit Intel/AMD Windows. Python 3.13 is the tested version. No third-party Python packages are needed.
2. Clone this repository, or download and extract its source ZIP.
3. Double-click **Start Sentinel Local.cmd**, or run `py -3 launch.py` from this folder.
4. Open **Antivirus → Install verified engine**, then update Sentinel signatures. The pinned official Windows engine download is about 215 MB; engine files and virus databases need additional local storage. The runtime is downloaded from Cisco Talos's official release, verified by its pinned SHA-256 and kept outside the Git checkout.

The launcher starts a background user process bound only to `127.0.0.1` and opens a private browser session. Run it again to reopen the app. The normal port is 8769; a free loopback port is selected if unavailable. Sessions last eight hours. Independent scans use ClamAV; the optional Defender features require Windows Defender and its services.

Closing the tab leaves scans and monitors running. Use **Settings & help → Quit local console** to stop the app. Quit is blocked during an operation. Independent scans can be cancelled from Antivirus. Optional Windows sign-in launch is available in Settings and is off by default; it creates only a current-user Run value when enabled. No elevated service or kernel driver is installed. Defender runs independently.

## Features

- **Independent antivirus:** ClamAV file/folder, priority-folder and fixed-drive scans with its official virus databases. Executables, archives and documents are inspected by the engine without being executed.
- **Signature updates:** FreshClam verifies official database updates, manually or every six hours while the app runs. Engine upgrades remain pinned source changes rather than arbitrary binary downloads.
- **Encrypted quarantine:** manual action for engine signature detections, with a matching SHA-256, exclusive source handle, Windows DPAPI encryption, recovery verification and durable metadata before original removal. Heuristic/PUA/limit indicators cannot remove a file. Files over 64 MB, installed Windows/program files, links and changed/locked content are blocked.
- **Recovery:** a separate private `.restored` copy; no original is overwritten or automatically opened. Recovery requires the same Windows account/key material. The vault is not a portable backup.
- **Restart recovery:** interrupted quarantine/recovery is audited at startup. Encrypted copies are verified, completed recovery writes can be recognized by SHA-256, and incomplete outputs are preserved. Retrying recovery writes a new uniquely named copy. Original deletion is never retried at startup.
- **Test Center:** a one-click harmless diagnostic scans three fixtures using official signatures, then uses a separate synthetic signature/ledger to test plain-text and ZIP detection, real Windows DPAPI quarantine and byte-for-byte recovery. Its six-step walkthrough stays separate from real threat history. Temporary test data is cleaned when the run ends; a forced process termination can leave a harmless temporary directory in the user's Temp folder. This is not a malware benchmark or PC safety scan.
- **Defender scans:** additional Windows quick/full/custom scans, signature updates and recorded detections.
- **Verified scan history:** matches scan GUIDs to Windows start/completion/cancellation events. Missing or ambiguous evidence stays unverified.
- **Protection overview:** real-time, behavior and tamper protection, PUA settings, firewall profiles, signature age, restart flags and exclusions visibility.
- **File Lab:** full SHA-256 fingerprint up to 256 MB, Authenticode signature/publisher, selected script review patterns in the first 1 MB, and an optional list of your own SHA-256 hashes. Files are not executed.
- **Persistence review:** current Run/RunOnce entries, Startup folders, startup-change alerts and selected remote-access service/process checks. No remote-access app is automatically approved, disabled or removed.
- **Network review:** listening TCP ports and up to 100 established TCP connections with app/process information. Binding scope is not proof of internet reachability.
- **Downloads scanning:** changed/new regular Downloads files are queued for independent scanning after settling; unfinished `.part`, `.tmp` and `.crdownload` files are ignored. The top-level default Downloads folder is monitored up to 6,000 entries, with a bounded pending queue. Existing files form the initial baseline. This is post-arrival detection, not pre-execution blocking.
- **Integrity Watch:** up to 16 local files, up to 64 MB each, compared against saved SHA-256 baselines. Normal edits can trigger alerts.
- **Local records:** activity history, review filter, authenticated JSON export and browser print/PDF view.

Change monitors run every 20 seconds while the app runs. Independent scanning copies stable content into private snapshots, batches up to 1,024 files / roughly 256 MB per engine run, and limits individual files to 256 MB. Enumeration is bounded to one million files. Skips, inaccessible files, engine limits, errors and cancellation are reported; a partial scan is not a clean result. Cold signature loading can take tens of seconds and multiple GiB of RAM. Windows evidence refreshes every four minutes; Defender event queries are bounded to 180 events from 14 days.

## Interpret the evidence

To see the workflow, open **Test Center → Run harmless self-test** after engine setup. Cold loading can take tens of seconds. For your own file, use **Antivirus → File or folder → Scan with Sentinel**. Review errors/skips as well as findings. Manual quarantine is available only for an attributable signature detection; recovery is a separate `.restored` copy that is never launched.

An empty detection history or completed scan cannot prove that every threat is absent. An unsigned file, changed startup entry, open port, hash-list match or script pattern is a **review indicator**, not a malware verdict. A valid signature is not a safety guarantee.

Independent detection does not guarantee safety; false positives are possible. Quarantine is manual and reversible through a separate recovery copy. Defender scans follow existing Windows remediation policy. The app does not disable Windows protection, add Defender exclusions, change firewall policy, request UAC or restart Windows. Protected checks may be unavailable to a standard account.

File inspection and independent scan enumeration reject UNC/device paths, alternate streams, reparse points, offline files and cloud placeholders. The default Downloads folder is watched rather than a browser's custom directory. WSL/VM disk contents are not inspected as mounted guest filesystems. There is no Windows kernel sensor, boot-time blocker, ransomware rollback or tamper-resistant service in this build. These gaps remain explicit release gates in [PRODUCT_PLAN.md](PRODUCT_PLAN.md).

## Privacy and local access

The interface loads no external fonts/scripts/analytics and uploads no file contents. Engine installation and signature updates contact the official ClamAV release/distribution services. **Defender's existing Microsoft cloud reporting, sample submission and update policies still apply.** Windows signature checks can use normal Windows trust services.

Runtime data is under `%LOCALAPPDATA%\SentinelLocal`: engine binaries/databases, private scan snapshots, encrypted vault, recovered copies, history, settings, cached evidence, baselines and instance metadata. Its directory is restricted to the current user, SYSTEM and Administrators. Reports contain private paths/network details. Malware with the current user's privileges or administrator access can tamper with this user-level app; DPAPI is not protection against the same compromised account.

The service uses an exact loopback Host allowlist, one-use launch links, an HttpOnly/SameSite cookie, a separate private header on every API request, Origin checks for mutations, bounded JSON bodies, no CORS, CSP and an exact static-file allowlist. There is no general shell endpoint. See [SECURITY.md](SECURITY.md) for the trust boundaries. **Do not forward the port, bind it to a LAN or deploy it as a public web service.**

To uninstall, disable optional sign-in launch, quit safely and remove the source folder. Review/recover needed quarantined files before erasing `%LOCALAPPDATA%\SentinelLocal`; deleting that directory erases the vault and recovery data. Never commit this data to Git.

## Develop and validate

```powershell
py -3 -m unittest discover -s tests -v
node --check web/app.js
py -3 tools/package_source.py
py -3 tools/setup_antivirus.py
py -3 tools/validate_independent.py --live
```

Node.js is needed only for the JavaScript syntax check. `setup_antivirus.py` is an alternative to UI setup and requires the console to be stopped first; it refuses to interrupt a running instance. The opt-in live validation uses harmless files and an isolated synthetic test signature; it does not download malware or modify production databases. Windows CI runs benign regressions and syntax/package checks without downloading the engine or real malware. Source packaging excludes runtime data and vendor binaries. The downloaded runtime includes ClamAV's license files; see its upstream project for licensing.

See [VALIDATION.md](VALIDATION.md) for performed checks and their limits, and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. When working from multiple source checkouts, quit the running console before testing another checkout; they share the per-user data directory.

## References

- [Microsoft Defender command-line scanning](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [Defender scan events](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Windows Protection History](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app)
