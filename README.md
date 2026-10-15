# Sentinel Local

A Windows security console that uses **Microsoft Defender as its antivirus engine**. It adds scan controls, evidence, local file inspection and change monitoring in a browser dashboard. It is a personal helper, not an independently certified antivirus or a guarantee that all malware is absent.

## Run locally

1. Install **Python 3.11 or newer** on Windows. Python 3.13 is the tested version. No third-party Python packages are needed.
2. Clone this repository, or download and extract its source ZIP.
3. Double-click **Start Sentinel Local.cmd**, or run `py -3 launch.py` from this folder.

The launcher starts a background service bound only to `127.0.0.1` and opens a private browser session. Run it again to reopen the app. The normal port is 8769; a free loopback port is selected if that port is unavailable. Sessions last eight hours. Windows Defender and its services must be available for antivirus features; permissions determine which checks Windows allows.

Closing the tab leaves scans and change monitors running. Use **Settings & help → Quit local console** to stop the console. Quit is blocked during an app scan, update or inspection. Defender runs independently. The console does not install a service, scheduled task, browser extension or Windows startup entry.

## Features

- **Scan Center:** Defender quick, full and custom file/folder scans, signature updates and recorded detections.
- **Verified scan history:** matches scan GUIDs to Windows start/completion/cancellation events. Missing or ambiguous evidence stays unverified.
- **Protection overview:** real-time, behavior and tamper protection, PUA settings, firewall profiles, signature age, restart flags and exclusions visibility.
- **File Lab:** full SHA-256 fingerprint up to 256 MB, Authenticode signature/publisher, selected script review patterns in the first 1 MB, and an optional list of your own SHA-256 hashes. Files are not executed.
- **Persistence review:** current Run/RunOnce entries, Startup folders, startup-change alerts and selected remote-access service/process checks. No remote-access app is automatically approved, disabled or removed.
- **Network review:** listening TCP ports and up to 100 established TCP connections with app/process information. Binding scope is not proof of internet reachability.
- **Downloads watch:** review alerts for changed/new executable and script files in the current user's default Downloads folder, top level only, up to 6,000 entries. Existing files form the initial baseline.
- **Integrity Watch:** up to 16 local files, up to 64 MB each, compared against saved SHA-256 baselines. Normal edits can trigger alerts.
- **Local records:** activity history, review filter, authenticated JSON export and browser print/PDF view.

Change monitors run every 20 seconds while the console runs. Windows evidence refreshes every four minutes, with manual refresh available. Event queries are bounded to 180 recent Defender events from the last 14 days. Each Windows section reports availability and its check time; unavailable checks are not assumed safe.

## Interpret the evidence

An empty detection history or completed scan cannot prove that every threat is absent. An unsigned file, changed startup entry, open port, hash-list match or script pattern is a **review indicator**, not a malware verdict. A valid signature is not a safety guarantee.

Defender scans follow the existing Windows protection/remediation policy and can quarantine threats Defender confirms. The console does not disable protection, add exclusions, restore quarantined files, delete suspicious files, change firewall policy, request UAC or restart Windows. Protected checks may be unavailable to a standard account; review them through Windows Security.

File inspection and custom path entry reject UNC/device paths, alternate streams, reparse points, offline files and cloud placeholders. Full scans follow Defender's own policy. The default Downloads folder is watched rather than any custom download directory configured in a browser. The console has no separate malware database, kernel sensor, ransomware rollback, UDP inspection or enterprise response system.

## Privacy and local access

The console loads no external fonts, scripts or analytics and uploads no file contents. **Defender's existing Microsoft cloud reporting, sample submission and update policies still apply.** Windows signature checks can use normal Windows trust services.

Runtime data is under `%LOCALAPPDATA%\SentinelLocal`: history, settings, cached evidence, baselines, instance metadata and errors. Its directory is restricted to the current Windows user, SYSTEM and Administrators. Exported reports contain local paths and network details; keep them private as appropriate. Local account access or administrator malware can tamper with this user-level helper.

The service uses an exact loopback Host allowlist, one-use launch links, an HttpOnly/SameSite cookie, a separate private header on every API request, Origin checks for mutations, bounded JSON bodies, no CORS, CSP and an exact static-file allowlist. There is no general shell endpoint. See [SECURITY.md](SECURITY.md) for the trust boundaries. **Do not forward the port, bind it to a LAN or deploy it as a public web service.**

To uninstall, quit safely and remove the source folder. Remove `%LOCALAPPDATA%\SentinelLocal` separately if you also want to erase local settings and evidence. Do not commit this data to Git.

## Develop and validate

```powershell
py -3 -m unittest discover -s tests -v
node --check web/app.js
py -3 tools/package_source.py
```

Node.js is needed only for the optional JavaScript syntax check. The app needs no JavaScript build or dependency install. Windows CI runs the tests and syntax check. The packaging command writes a source-only ZIP under `dist/`, excluding runtime data.

See [VALIDATION.md](VALIDATION.md) for performed checks and their limits, and [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. When working from multiple source checkouts, quit the running console before testing another checkout; they share the per-user data directory.

## References

- [Microsoft Defender command-line scanning](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
- [Defender scan events](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [Windows Protection History](https://support.microsoft.com/en-us/windows/security/windows-security/protection-history-in-the-windows-security-app)
