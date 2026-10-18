# Development

Use Windows and Python 3.11 or newer; Python 3.13 is the validated version. The app uses the Python standard library and buildless HTML/CSS/JavaScript. Avoid adding packages or downloading models unless a concrete feature requires them.

## Layout

| Path | Purpose |
| --- | --- |
| `launch.py`, `Start Sentinel Local.cmd` | Per-user launcher and private browser bootstrap |
| `app/windows.py` | Constant PowerShell readers and Microsoft-signed Defender commands |
| `app/core.py` | Local store, jobs, event correlation, file inspection and monitors |
| `app/antivirus.py` | Pinned ClamAV installation, runtime verification, CVD updates and stable batched scans |
| `app/vault.py` | DPAPI quarantine, exclusive file identity and separate-copy recovery |
| `app/cleaner.py` | PC Cleaner: junk categories, Recycle Bin, large/old files, uninstallers and startup apps |
| `app/startup.py` | Optional current-user Windows sign-in launch |
| `app/server.py` | Authenticated loopback HTTP service and explicit API actions |
| `web/` | Dashboard, styles and safe DOM rendering |
| `tests/` | Benign regression fixtures and isolated HTTP tests |
| `tools/package_source.py` | Source-only distribution ZIP |
| `tools/setup_antivirus.py`, `tools/validate_independent.py` | Explicit engine setup and isolated benign live validation |

## Validate a change

```powershell
py -3 -m unittest discover -s tests -v
node --check web/app.js
git diff --check
```

Run focused live checks when changing engine integration; a harmless custom file scan is sufficient for plumbing checks. `tools/validate_independent.py --live` uses an installed official engine, a temporary evidence store and an isolated test-only hash signature against harmless text/archive fixtures. It verifies positive result plumbing and quarantine without real malware. Do not create EICAR, download malware, execute test payloads, weaken Defender or launch a full multi-hour scan merely to test the UI. Record what was actually checked and leave untested cases explicit.

Use temporary directories for tests. Keep test engines and HTTP servers isolated from the real per-user database. Stop the running console before manually testing a different source checkout. Preserve existing users' settings and don't assume a remote-access tool is approved just because it is signed or installed.

Add comments where they explain security constraints or non-obvious Windows behavior. Follow the boundaries in [SECURITY.md](SECURITY.md). Never commit runtime evidence, private reports, tokens or session links.
