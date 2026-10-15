"""Opt-in live validation with benign files and a synthetic signature, never malware.

Uses installed official engine files, temporary evidence storage and an isolated
test-only hash signature. Does not change production definitions or detections.
"""
import argparse
import hashlib
import json
import tempfile
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.antivirus import Antivirus, VERSION
from app.core import DATA, Store
from app.vault import Vault


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', required=True, help='Run the installed official engine on harmless temporary fixtures.')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='Sentinel-benign-validation-') as temporary:
        root = Path(temporary)
        files = root / 'fixtures'
        files.mkdir()
        for name in ('normal.txt', 'unicode-café.txt', 'readme.md', 'empty.txt'):
            (files / name).write_text('' if name == 'empty.txt' else 'Harmless Sentinel Local validation text.\n', encoding='utf-8')
        store = Store(root / 'isolated-data')
        av = Antivirus(store)
        av.runtime = DATA / 'antivirus' / ('clamav-' + VERSION)
        av.database = DATA / 'antivirus/database'
        result = av.scan(uuid.uuid4().hex, [files])
        assert result['status'] == 'completed' and result['scanned'] == 4 and result['detected'] == 0, result
        print('Official-database benign scan:', json.dumps(result), flush=True)

        marker = b'Harmless Sentinel Local synthetic detection marker. Not malware. Never executed.\n'
        sample = files / 'synthetic-marker.txt'
        sample.write_bytes(marker)
        test_db = root / 'synthetic-test-only.hdb'
        test_db.write_text(hashlib.md5(marker).hexdigest() + ':' + str(len(marker)) + ':Sentinel.Benign.Validation.TestOnly\n', encoding='ascii')
        # This override exists only in this opt-in isolated validation tool. The
        # production scanner always uses --official-db-only=yes and its CVD dir.
        def test_args(target):
            return [str(av.runtime / 'clamscan.exe'), '--database=' + str(test_db), '--stdout', '--no-summary', str(target)]
        with patch.object(av, '_args', side_effect=test_args):
            positive = av.scan(uuid.uuid4().hex, [sample])
            assert positive['status'] == 'completed' and positive['detected'] == 1, positive
            archive = files / 'benign-archive.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('synthetic-marker.txt', marker)
            nested = av.scan(uuid.uuid4().hex, [archive])
            assert nested['detected'] == 1, nested
        row = store.rows('SELECT * FROM detections WHERE path=?', (str(sample),))[0]
        vault = Vault(store)
        vault_id = vault.quarantine(row['id'])
        assert not sample.exists()
        recovered = Path(vault.recover(vault_id))
        assert recovered.read_bytes() == marker and recovered.suffix == '.restored'
        print('Synthetic signature, archive inspection and encrypted quarantine/recovery passed.', flush=True)
        print('This validates plumbing on benign fixtures; it is not a malware detection benchmark.', flush=True)


if __name__ == '__main__':
    main()
