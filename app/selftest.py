"""Explicit benign end-to-end diagnostic; never alters production definitions.

No caller-controlled sample, signature, executable, database or output path is
accepted. Synthetic positives belong to a temporary, isolated evidence ledger.
"""
import hashlib
import tempfile
import time
import uuid
import zipfile
from pathlib import Path

from .antivirus import Antivirus
from .core import Store, now
from .vault import Vault

MARKER = b'Harmless Sentinel Local self-test text. Not malware. Never executed.\n'
TEST_NAME = 'Sentinel.Benign.SelfTest.TestOnly'


class SyntheticScanner(Antivirus):
    """Only the self-test calls this class with an internally generated HDB."""
    def __init__(self, store, installed, signature):
        super().__init__(store)
        self.runtime, self.database = installed.runtime, installed.database
        self.signature = signature

    def _args(self, target):
        return [str(self.runtime / 'clamscan.exe'), '--database=' + str(self.signature),
                '--stdout', '--no-summary', '--max-filesize=256M', '--max-scansize=1024M',
                '--max-recursion=20', '--max-files=10000', '--alert-exceeds-max=yes',
                '--follow-dir-symlinks=0', '--follow-file-symlinks=0', str(target)]


class SelfTest:
    def __init__(self, installed):
        self.installed = installed
        self.progress = None

    def run(self):
        started = time.monotonic()
        result = {'status': 'running', 'started': now(), 'steps': [],
                  'scope': 'Harmless diagnostic only. Not a malware benchmark or a scan of your PC.'}
        def step(title, detail, status='passed'):
            result['steps'].append({'title': title, 'detail': detail, 'status': status})
            self.progress = {'phase': title, 'steps': list(result['steps'])}
        try:
            self.progress = {'phase': 'Checking installed engine and official databases', 'steps': []}
            self.installed.verify()
            if not self.installed.status()['definitionsReady']:
                raise ValueError('Install and update official signatures before running the diagnostic.')
            with tempfile.TemporaryDirectory(prefix='Sentinel-SelfTest-') as temporary:
                root = Path(temporary)
                fixtures = root / 'fixtures'
                fixtures.mkdir()
                for name in ('ordinary.txt', 'unicode-café.txt', 'empty.txt'):
                    (fixtures / name).write_text('' if name == 'empty.txt' else 'Harmless local diagnostic text.\n', encoding='utf-8')
                store = Store(root / 'isolated-ledger')
                official = Antivirus(store)
                official.runtime, official.database = self.installed.runtime, self.installed.database
                self.progress = {'phase': 'Scanning 3 harmless files with official signatures (cold loading can take 30 seconds)', 'steps': []}
                clean = official.scan(uuid.uuid4().hex, [fixtures])
                if clean['status'] != 'completed' or clean['scanned'] != 3 or clean['detected'] != 0:
                    raise ValueError('Official-database fixture check did not return the expected complete result: ' + str(clean))
                step('Official signatures', f"3 harmless files scanned; zero findings, skips or errors. {clean['seconds']} seconds.")

                sample = fixtures / 'harmless-self-test.txt'
                sample.write_bytes(MARKER)
                archive = fixtures / 'harmless-archive.zip'
                with zipfile.ZipFile(archive, 'x') as output:
                    output.writestr('harmless-self-test.txt', MARKER)
                signature = root / 'isolated-test-only.hdb'
                signature.write_text(hashlib.md5(MARKER).hexdigest() + ':' + str(len(MARKER)) + ':' + TEST_NAME + '\n', encoding='ascii')
                synthetic = SyntheticScanner(store, self.installed, signature)
                self.progress = {'phase': 'Testing harmless text and ZIP against isolated synthetic signature', 'steps': list(result['steps'])}
                positive = synthetic.scan(uuid.uuid4().hex, [sample, archive])
                detections = store.rows('SELECT * FROM detections')
                if positive['status'] != 'completed' or positive['scanned'] != 2 or len(detections) != 2 or any(d['verdict'] != 'infected' or TEST_NAME not in d['signature'] for d in detections):
                    raise ValueError('Synthetic text/archive detection did not produce two attributable test results.')
                step('Synthetic detection + archive', '2 expected test matches: plain text and the same text inside a ZIP. These are not real threats.')

                vault = Vault(store)
                expected = {str(sample): MARKER, str(archive): archive.read_bytes()}
                entries = [vault.quarantine(d['id']) for d in detections]
                if sample.exists() or archive.exists():
                    raise ValueError('The test source was not removed after encrypted quarantine.')
                step('Encrypted quarantine', '2 temporary fixtures encrypted using Windows DPAPI. Exact scanned hashes checked before original removal.')
                for entry in entries:
                    row = store.rows('SELECT * FROM vault WHERE id=?', (entry,))[0]
                    recovered = Path(vault.recover(entry))
                    if recovered.suffix != '.restored' or recovered.read_bytes() != expected[row['path']]:
                        raise ValueError('The recovered test bytes do not match their original.')
                step('Separate-copy recovery', 'Both recovered files match their originals byte for byte. Nothing was opened or executed.')
                if self.installed.store.rows('SELECT id FROM detections WHERE signature LIKE ?', ('%' + TEST_NAME + '%',)):
                    raise ValueError('A synthetic finding unexpectedly exists in the production ledger. Review the records.')
                step('Production isolation', 'Official definitions and real threat/vault history were not changed by this diagnostic.')
            step('Temporary data cleaned', 'Harmless fixtures, synthetic signature, isolated ledger and recovery copies removed.')
            result['status'] = 'completed'
        except Exception as exc:
            step('Diagnostic stopped', str(exc), 'failed')
            result['status'], result['error'] = 'failed', str(exc)
        finally:
            result['seconds'], result['finished'] = round(time.monotonic() - started, 1), now()
            self.progress = None
        return result
