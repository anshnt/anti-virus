# Development

Use Windows and Python 3.11 or newer; Python 3.13 is the validated version. The app uses the Python standard library and buildless HTML/CSS/JavaScript. Avoid adding packages or downloading models unless a concrete feature requires them.

## Layout

| Path | Purpose |
| --- | --- |
| `launch.py`, `Start Sentinel Local.cmd` | Per-user launcher and private browser bootstrap |
| `app/windows.py` | Constant PowerShell readers and Microsoft-signed Defender commands |
| `app/core.py` | Local store, jobs, event correlation, file inspection and monitors |
| `app/server.py` | Authenticated loopback HTTP service and explicit API actions |
| `web/` | Dashboard, styles and safe DOM rendering |
| `tests/` | Benign regression fixtures and isolated HTTP tests |
| `tools/package_source.py` | Source-only distribution ZIP |

## Validate a change

```powershell
py -3 -m unittest discover -s tests -v
node --check web/app.js
git diff --check
```

Run focused live checks when changing Defender integration; a harmless custom file scan is sufficient for plumbing checks. Do not create EICAR, download malware, execute test payloads, weaken Defender or launch a full multi-hour scan merely to test the UI. Record what was actually checked and leave untested cases explicit.

Use temporary directories for tests. Keep test engines and HTTP servers isolated from the real per-user database. Stop the running console before manually testing a different source checkout. Preserve existing users' settings and don't assume a remote-access tool is approved just because it is signed or installed.

Add comments where they explain security constraints or non-obvious Windows behavior. Follow the boundaries in [SECURITY.md](SECURITY.md). Never commit runtime evidence, private reports, tokens or session links.
