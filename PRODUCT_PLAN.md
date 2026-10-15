# Product target: a full Windows antivirus

The target is an independent antivirus product with demonstrable protection beyond the starting Defender dashboard. **This target is not yet achieved.** A working ClamAV integration is a meaningful independent detection layer; it does not establish superior protection to Defender.

## Current development build

| Capability | Evidence / current boundary |
| --- | --- |
| Independent detection | Official ClamAV 1.5.4 runs outside the web process against official CVD databases. Scanning does not require a Defender scan command. |
| Definition updates | FreshClam validates official databases; manual updates and six-hour checks while running are implemented. |
| Scan scope | Files, folders, priority folders and accessible fixed drives; stable snapshots are processed in batches. Skips, errors and limits remain visible. |
| Remediation | Manual, Windows-user-encrypted quarantine tied to the exact scanned SHA-256; an exclusive file handle prevents deleting a replacement. |
| Recovery | A recovery-verified encrypted copy precedes original removal. Recovery writes a separate `.restored` file and never overwrites or launches an original. |
| Background operation | Post-arrival Downloads scans, integrity/startup monitoring, safe cancellation, optional per-user Windows sign-in launch. |
| Windows coexistence | Existing Defender, firewall and tamper settings remain active. RustDesk or any other remote tool is not automatically disabled. |
| Safety evidence | Benign regression tests, synthetic positive/archive detection, real official-database scanning, encrypted quarantine/recovery tests and HTTP access-control tests. |

## Release gates before calling this a full Defender replacement

1. **Pre-execution enforcement:** design a Windows minifilter and privileged broker with authenticated, bounded communication, content-generation identities, executable mapping checks, explicit timeout policy and deadlock prevention. Validate on disposable VMs before use on a real PC.
2. **Driver trust:** create the vendor's signing/Hardware Dev Center process, run driver verification/compatibility checks and obtain production signatures. Driver signature enforcement must remain enabled. These are external release prerequisites; an unsigned prototype cannot be silently loaded on this PC.
3. **Always-on protection:** a reviewed system service, least-privilege worker isolation, restart/boot recovery, secure updater, bounded queues, native notifications and a native installer/uninstaller. A per-user sign-in entry is not a tamper-resistant system service.
4. **Broader detection:** separately tested behavioral/ransomware and fileless attack coverage, script interception, exploit coverage, rootkit/offline strategy and supported handling of WSL/virtual disks. An open port or unsigned file must never be used alone as a malware verdict.
5. **Response completeness:** false-positive handling, audited exception policy, durable crash recovery, multiple-user quarantine isolation and robust remediation of locked/running threats without damaging Windows.
6. **Release engineering:** signed installer/binaries, verified engine upgrade and rollback, SBOM/third-party licensing, update trust-key rotation, repair paths and reproducible release artifacts.
7. **Independent assessment:** adversarial penetration testing, parser isolation and fuzzing, independent malware evaluation and a documented vulnerability response process.

## What “better than Defender” must mean

Compare both products on the same dated, legally obtained and independently labelled corpus in isolated Windows test systems. Keep the OS, configuration, update time, internet/cloud policy and hardware comparable. Do not download or execute real malware on the user's everyday PC.

Publish results rather than a made-up protection score:

- Static and execution-stage detection, including missed families and evasion cases.
- Ransomware/fileless/credential-theft protection where the relevant feature exists.
- False-positive rate on a large representative clean software corpus.
- Time to block, file-open overhead, full-scan throughput, memory/CPU and update bandwidth.
- Remediation/recovery success, crash survival, update rollback and coexistence failures.
- Confidence intervals, raw counts, sample provenance, exact versions and all limitations.

The release claim must identify the dimensions where Sentinel wins and where it loses. Feature count, unit tests, four benign files and a synthetic test signature are not evidence of better malware detection.

## References

- [ClamAV scanning and the Windows/Linux on-access distinction](https://docs.clamav.net/manual/Usage/Scanning.html)
- [Windows minifilter callbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-and-postoperation-callback-routines)
- [Windows driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [Microsoft driver signing options](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings)
