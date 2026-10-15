import hashlib
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app.antivirus import ARCHIVE_SHA256, Antivirus, archive_member, classify_scan, sha256
from app.core import Engine, Store
from app.vault import Vault, locked_source, permitted_source, protect
from app import startup


class AntivirusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.store = Store(self.root / 'data')
        self.av = Antivirus(self.store)
        self.sample = self.root / 'benign.txt'
        self.sample.write_text('Harmless independent antivirus regression fixture.', encoding='utf-8')

    def tearDown(self):
        self.temporary.cleanup()

    def test_unsafe_archive_paths_rejected(self):
        for name in ('../escape.exe', '/absolute.exe', 'C:/absolute.exe', 'engine/a:stream', 'engine/trailing. '):
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive_member(name)

    def test_bad_engine_download_never_executes_or_extracts(self):
        with patch('app.antivirus.subprocess.Popen') as run, patch('app.antivirus.zipfile.ZipFile') as extract:
            with self.assertRaises(ValueError):
                self.av.install(self.sample)
        run.assert_not_called()
        extract.assert_not_called()

    def test_runtime_tampering_is_blocked(self):
        self.av.runtime.mkdir()
        scanner = self.av.runtime / 'clamscan.exe'
        scanner.write_bytes(b'not an executable; never run')
        (self.av.runtime / 'runtime-manifest.json').write_text(json.dumps({'archiveSha256': ARCHIVE_SHA256, 'files': {'clamscan.exe': sha256(scanner)}}))
        self.assertEqual(self.av.verify(), scanner)
        scanner.write_bytes(b'changed benign fixture')
        with self.assertRaises(ValueError):
            self.av.verify()

    def test_snapshot_hash_is_of_stable_copied_bytes(self):
        snapshot, actual = self.av._snapshot(self.sample)
        self.assertEqual(actual, hashlib.sha256(self.sample.read_bytes()).hexdigest())
        self.sample.write_text('Later unrelated edit', encoding='utf-8')
        self.assertNotEqual(actual, hashlib.sha256(self.sample.read_bytes()).hexdigest())
        snapshot.unlink()

    def batch(self, code=0, suffix='OK', spoof=False):
        snapshot, sha = self.av._snapshot(self.sample)
        batch = [{'snapshot': snapshot, 'path': str(self.sample), 'sha256': sha}]
        def run(args, callback, cancellable=False):
            self.assertIn('--official-db-only=yes', args)
            self.assertNotIn(str(self.sample), args)
            if spoof:
                callback(str(self.sample) + ': Fake.Name FOUND')
            else:
                callback(str(snapshot) + ': ' + suffix)
            return code
        with patch.object(self.av, '_run', side_effect=run):
            result = self.av.scan_batch(batch)
        self.assertFalse(snapshot.exists())
        self.assertTrue(self.sample.exists())
        return result

    def test_batch_accepts_exact_snapshot_result(self):
        items, error = self.batch(1, 'Test.Signature FOUND')
        self.assertFalse(error)
        self.assertEqual(items[0]['verdict'], 'infected')

    def test_script_heuristic_cannot_authorize_quarantine(self):
        self.assertEqual(self.batch(1, 'Heuristics.Script.Review FOUND')[0][0]['verdict'], 'review')

    def test_scan_limits_are_not_clean_or_confirmed_malware(self):
        items, error = self.batch(1, 'Heuristics.Limits.Exceeded.MaxFileSize FOUND')
        self.assertEqual(items[0]['verdict'], 'limited')
        self.assertEqual(classify_scan(1, items, 0), 'partial')

    def test_fake_filename_output_does_not_create_a_detection(self):
        items, error = self.batch(1, spoof=True)
        self.assertTrue(error)
        self.assertEqual(items[0]['verdict'], 'error')

    def test_error_exit_cannot_create_confirmed_quarantine_candidate(self):
        items, error = self.batch(2, 'Test.Signature FOUND')
        self.assertTrue(error)
        self.assertEqual(items[0]['verdict'], 'review')

    def test_empty_file_is_a_valid_zero_byte_scan(self):
        self.assertEqual(self.batch(0, 'Empty file')[0][0]['verdict'], 'no_detection')

    def test_missing_output_stays_an_error(self):
        snapshot, sha = self.av._snapshot(self.sample)
        with patch.object(self.av, '_run', return_value=0):
            items, _ = self.av.scan_batch([{'snapshot': snapshot, 'path': str(self.sample), 'sha256': sha}])
        self.assertEqual(items[0]['verdict'], 'error')

    def test_cancel_and_errors_never_report_completion(self):
        self.assertEqual(classify_scan(0, [], 0, cancelled=True), 'cancelled')
        self.assertEqual(classify_scan(2, [], 1), 'failed')
        self.assertEqual(classify_scan(1, [], 0), 'unverified')
        self.assertEqual(classify_scan(0, [], 0, skipped=1), 'partial')

    def test_missing_roots_count_as_skips(self):
        counts = {'enumerated': 0, 'skipped': 0, 'limitReached': False}
        self.assertEqual(list(self.av.files([self.root / 'missing'], counts)), [])
        self.assertEqual(counts['skipped'], 1)

    def test_read_only_store_open_does_not_reset_running_job(self):
        with self.store.connect() as c:
            c.execute("INSERT INTO jobs VALUES('running','av-custom','running','2026',NULL,'working',NULL)")
        Store(self.store.folder)
        self.assertEqual(self.store.rows('SELECT status FROM jobs')[0]['status'], 'running')


@unittest.skipUnless(os.name == 'nt', 'Windows DPAPI and file-handle behavior')
class VaultTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.engine = Engine(self.root / 'data', start=False)
        self.store = self.engine.store
        self.vault = self.engine.vault
        self.source = self.root / 'harmless-test-file.txt'
        self.content = b'Benign quarantine regression fixture. Never executable.'
        self.source.write_bytes(self.content)
        self.detection = 'a' * 32
        with self.store.connect() as c:
            c.execute('INSERT INTO detections VALUES(?,?,?,?,?,?,?,?)',
                      (self.detection, 'fixture', '2026', str(self.source), 'Test.Fixture', hashlib.sha256(self.content).hexdigest(), 'infected', 'open'))

    def tearDown(self):
        self.temporary.cleanup()

    def test_dpapi_round_trip_and_ciphertext(self):
        encrypted = protect(self.content)
        self.assertNotIn(self.content, encrypted)
        self.assertEqual(protect(encrypted, decrypt=True), self.content)

    def test_quarantine_then_recovery_never_overwrites_original(self):
        vault_id = self.vault.quarantine(self.detection)
        self.assertFalse(self.source.exists())
        encrypted = self.vault.folder / (vault_id + '.dpapi')
        self.assertNotIn(self.content, encrypted.read_bytes())
        self.source.write_bytes(b'New user file at the original location')
        recovered = Path(self.vault.recover(vault_id))
        self.assertEqual(recovered.read_bytes(), self.content)
        self.assertEqual(recovered.suffix, '.restored')
        self.assertEqual(self.source.read_bytes(), b'New user file at the original location')

    def test_changed_source_blocks_removal(self):
        self.source.write_text('Different benign contents')
        with self.assertRaises(ValueError):
            self.vault.quarantine(self.detection)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.store.rows('SELECT * FROM vault'), [])

    def test_review_indicators_cannot_remove_files(self):
        with self.store.connect() as c:
            c.execute("UPDATE detections SET verdict='review'")
        with self.assertRaises(ValueError):
            self.vault.quarantine(self.detection)
        self.assertTrue(self.source.exists())

    def test_failed_encryption_preserves_original(self):
        with patch('app.vault.protect', side_effect=RuntimeError('simulated encryption failure')):
            with self.assertRaises(RuntimeError):
                self.vault.quarantine(self.detection)
        self.assertTrue(self.source.exists())

    def test_unrecoverable_encrypted_copy_preserves_original(self):
        real_protect = protect
        def corrupted(content, decrypt=False):
            return real_protect(content, decrypt=True) if decrypt else b'not a valid DPAPI blob'
        with patch('app.vault.protect', side_effect=corrupted):
            with self.assertRaises(OSError):
                self.vault.quarantine(self.detection)
        self.assertTrue(self.source.exists())
        self.assertEqual(self.store.rows('SELECT * FROM vault'), [])

    def test_failed_removal_keeps_recoverable_encrypted_copy(self):
        @contextmanager
        def locked(*args):
            def fail():
                raise PermissionError('simulated removal failure')
            yield self.content, fail
        with patch('app.vault.locked_source', locked):
            with self.assertRaises(PermissionError):
                self.vault.quarantine(self.detection)
        record = self.store.rows('SELECT * FROM vault')[0]
        self.assertEqual(record['status'], 'removal_unverified')
        self.assertTrue(self.source.exists())
        recovered = Path(self.vault.recover(record['id']))
        self.assertEqual(recovered.read_bytes(), self.content)

    def test_unsafe_ids_and_protected_source_blocked(self):
        for raw in ('../escape', '', None):
            with self.assertRaises(ValueError):
                self.vault.quarantine(raw)
        with self.assertRaises(ValueError):
            permitted_source(Path(__file__), self.store.folder)

    def test_exclusive_source_lock_blocks_writers(self):
        with locked_source(self.source.resolve(), self.store.folder):
            with self.assertRaises(PermissionError):
                self.source.write_bytes(b'Unexpected concurrent change')

    def test_hardlinked_file_cannot_be_removed(self):
        os.link(self.source, self.root / 'second-name.txt')
        with self.assertRaises(ValueError):
            self.vault.quarantine(self.detection)
        self.assertTrue(self.source.exists())

    def test_ciphertext_tampering_blocks_recovery(self):
        vault_id = self.vault.quarantine(self.detection)
        encrypted = self.vault.folder / (vault_id + '.dpapi')
        data = bytearray(encrypted.read_bytes())
        data[-1] ^= 1
        encrypted.write_bytes(data)
        with self.assertRaises(OSError):
            self.vault.recover(vault_id)


class BackgroundPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = Engine(Path(self.temp.name) / 'data', start=False)

    def tearDown(self):
        self.temp.cleanup()

    def test_invalid_policy_rejected(self):
        with self.assertRaises(ValueError):
            self.engine.antivirus_policy({'scanDownloads': 'yes', 'autoUpdate': True})

    def test_monitor_only_scan_not_exposed_as_generic_job(self):
        with self.assertRaises(ValueError):
            self.engine.job('av-watch', ['C:\\anything'])

    def test_policy_off_prevents_background_update(self):
        self.engine.antivirus_policy({'scanDownloads': False, 'autoUpdate': False})
        with patch.object(self.engine.antivirus, 'status', return_value={'installed': True, 'definitionsReady': True, 'lastUpdate': None}), patch.object(self.engine, 'job') as job:
            self.engine._antivirus_background()
        job.assert_not_called()

    def test_recent_update_not_immediately_repeated(self):
        from app.core import now
        with patch.object(self.engine.antivirus, 'status', return_value={'installed': True, 'definitionsReady': True, 'lastUpdate': now()}), patch.object(self.engine, 'job') as job:
            self.engine._antivirus_background()
        job.assert_not_called()

    def test_due_update_is_scheduled_by_the_background_worker(self):
        with patch.object(self.engine.antivirus, 'status', return_value={'installed': True, 'definitionsReady': True, 'lastUpdate': None}), patch.object(self.engine, 'job') as job:
            self.engine._antivirus_background()
        job.assert_called_once_with('av-update')
        self.assertGreater(self.engine.store.get('antivirus_update_attempt'), 0)

    def test_startup_conflicting_value_not_overwritten(self):
        with patch('app.startup.current', return_value='some other application'), patch('app.startup.command', return_value='this application'):
            with self.assertRaises(ValueError):
                startup.configure(True, self.engine.store)

    def test_startup_non_boolean_value_rejected(self):
        with self.assertRaises(ValueError):
            startup.configure('yes', self.engine.store)


if __name__ == '__main__':
    unittest.main()
