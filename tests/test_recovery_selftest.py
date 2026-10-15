import hashlib
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from app.core import Engine
from app.selftest import MARKER, TEST_NAME, SelfTest
from app.vault import Vault, locked_source


class PowerLoss(BaseException):
    """Bypass normal Exception handlers to simulate abrupt process loss."""


@unittest.skipUnless(os.name == 'nt', 'Windows quarantine and DPAPI')
class RestartRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.engine = Engine(self.root / 'data', start=False)
        self.store, self.vault = self.engine.store, self.engine.vault
        self.source = self.root / 'harmless.txt'
        self.content = b'Harmless restart regression fixture. Never executable.'
        self.source.write_bytes(self.content)
        self.detection = 'b' * 32
        with self.store.connect() as c:
            c.execute('INSERT INTO detections VALUES(?,?,?,?,?,?,?,?)', (self.detection, 'test', '2026', str(self.source), 'Synthetic.TestOnly', hashlib.sha256(self.content).hexdigest(), 'infected', 'open'))

    def tearDown(self):
        self.temp.cleanup()

    def row(self):
        return self.store.rows('SELECT * FROM vault')[0]

    def test_restart_before_removal_never_retries_deletion(self):
        @contextmanager
        def crash(*args):
            def remove():
                raise PowerLoss()
            yield self.content, remove
        with patch('app.vault.locked_source', crash), self.assertRaises(PowerLoss):
            self.vault.quarantine(self.detection)
        self.assertEqual(self.row()['status'], 'prepared')
        restarted = Engine(self.store.folder, start=False)
        self.assertEqual(self.row()['status'], 'removal_unverified')
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertEqual(Path(restarted.vault.recover(self.row()['id'])).read_bytes(), self.content)
        self.assertEqual(self.store.rows('SELECT status FROM detections')[0]['status'], 'removal_unverified')

    def test_restart_after_removal_preserves_recoverable_copy(self):
        @contextmanager
        def crash(*args):
            with locked_source(*args) as locked:
                yield locked
            raise PowerLoss()
        with patch('app.vault.locked_source', crash), self.assertRaises(PowerLoss):
            self.vault.quarantine(self.detection)
        self.assertFalse(self.source.exists())
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'removal_unverified')
        self.assertEqual(Path(self.vault.recover(self.row()['id'])).read_bytes(), self.content)

    def interrupted_recovery(self):
        item = self.vault.quarantine(self.detection)
        with patch('app.vault.os.fsync', side_effect=PowerLoss()), self.assertRaises(PowerLoss):
            self.vault.recover(item)
        self.assertEqual(self.row()['status'], 'recovering')
        return item, Path(self.row()['recovery'])

    def test_restart_completes_written_recovery_only_after_hash_check(self):
        _, output = self.interrupted_recovery()
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'recovered')
        self.assertEqual(output.read_bytes(), self.content)
        self.assertEqual(self.store.rows('SELECT status FROM recovery_attempts')[0]['status'], 'verified')

    def test_partial_recovery_is_preserved_and_retry_uses_new_path(self):
        item, output = self.interrupted_recovery()
        output.write_bytes(b'partial bytes from a simulated power failure')
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'recovery_incomplete')
        self.assertEqual(self.store.rows('SELECT status FROM recovery_attempts')[0]['status'], 'incomplete')
        recovered = Path(self.vault.recover(item))
        self.assertNotEqual(output, recovered)
        self.assertEqual(recovered.read_bytes(), self.content)
        self.assertEqual(output.read_bytes(), b'partial bytes from a simulated power failure')
        self.assertEqual(len(self.store.rows('SELECT * FROM recovery_attempts')), 2)

    def test_missing_recovery_output_can_be_retried(self):
        item, output = self.interrupted_recovery()
        output.unlink()
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'recovery_incomplete')
        self.assertEqual(Path(self.vault.recover(item)).read_bytes(), self.content)

    def test_corrupt_vault_at_restart_blocks_recovery_without_touching_source(self):
        @contextmanager
        def fail(*args):
            def remove():
                raise OSError('simulated removal error')
            yield self.content, remove
        with patch('app.vault.locked_source', fail), self.assertRaises(OSError):
            self.vault.quarantine(self.detection)
        (self.vault.folder / (self.row()['id'] + '.dpapi')).write_bytes(b'corrupt test blob')
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'recovery_blocked')
        self.assertEqual(self.source.read_bytes(), self.content)
        self.assertIn('could not be verified', self.store.rows('SELECT * FROM vault_checks')[0]['detail'])
        with self.assertRaises(OSError):
            self.vault.recover(self.row()['id'])

    def test_arbitrary_recovery_path_cannot_be_accepted_as_completed(self):
        _, output = self.interrupted_recovery()
        outside = self.root / 'not-a-recovery.txt'
        outside.write_bytes(self.content)
        with self.store.connect() as c:
            c.execute('UPDATE vault SET recovery=?', (str(outside),))
        self.vault.reconcile()
        self.assertEqual(self.row()['status'], 'recovery_incomplete')
        self.assertEqual(outside.read_bytes(), self.content)
        self.assertTrue(output.exists())

    def test_hardlinked_ciphertext_rejected(self):
        item = self.vault.quarantine(self.detection)
        os.link(self.vault.folder / (item + '.dpapi'), self.root / 'copy.dpapi')
        with self.assertRaises(ValueError):
            self.vault.recover(item)

    def test_second_vault_client_does_not_reconcile_active_recovery(self):
        _, _ = self.interrupted_recovery()
        Vault(self.store)
        self.assertEqual(self.row()['status'], 'recovering')


class SelfTestBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = Engine(Path(self.temp.name) / 'production', start=False)
        self.diagnostic = self.engine.selftest

    def tearDown(self):
        self.temp.cleanup()

    def test_engine_verification_failure_never_launches_scanner(self):
        with patch.object(self.engine.antivirus, 'verify', side_effect=ValueError('changed engine')), patch('app.antivirus.subprocess.Popen') as spawn:
            result = self.diagnostic.run()
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['steps'][-1]['status'], 'failed')
        self.assertIsNone(self.diagnostic.progress)
        spawn.assert_not_called()

    def test_missing_definitions_stop_without_creating_test_workspace(self):
        with patch.object(self.engine.antivirus, 'verify'), patch.object(self.engine.antivirus, 'status', return_value={'definitionsReady': False}), patch('app.selftest.tempfile.TemporaryDirectory') as temporary:
            self.assertEqual(self.diagnostic.run()['status'], 'failed')
        temporary.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'Windows DPAPI')
    def test_diagnostic_isolates_signatures_findings_vault_and_removes_fixtures(self):
        workspaces = []
        def run(scanner, args, callback, cancellable=False):
            listing = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--file-list=')))
            workspaces.append(listing.parents[3])
            synthetic = '--official-db-only=yes' not in args
            if synthetic:
                signature = Path(next(a.split('=', 1)[1] for a in args if a.startswith('--database=')))
                self.assertEqual(signature.name, 'isolated-test-only.hdb')
                self.assertIn(TEST_NAME, signature.read_text())
                self.assertTrue(signature.is_relative_to(listing.parents[3]))
            for name in listing.read_text(encoding='utf-8').splitlines():
                callback(name + ': ' + (TEST_NAME + '.UNOFFICIAL FOUND' if synthetic else 'OK'))
            return 1 if synthetic else 0
        with patch('app.antivirus.Antivirus.verify'), patch.object(self.engine.antivirus, 'status', return_value={'definitionsReady': True}), patch('app.antivirus.Antivirus.status', return_value={'definitionsReady': True}), patch('app.antivirus.Antivirus._run', autospec=True, side_effect=run):
            result = self.diagnostic.run()
        self.assertEqual(result['status'], 'completed', result)
        self.assertEqual(len(result['steps']), 6)
        self.assertTrue(all(s['status'] == 'passed' for s in result['steps']))
        self.assertEqual(self.engine.store.rows('SELECT * FROM detections'), [])
        self.assertEqual(self.engine.store.rows('SELECT * FROM vault'), [])
        self.assertTrue(workspaces)
        self.assertTrue(all(not p.exists() for p in workspaces))

    def test_unexpected_official_finding_stops_diagnostic(self):
        with patch.object(self.engine.antivirus, 'verify'), patch.object(self.engine.antivirus, 'status', return_value={'definitionsReady': True}), patch('app.selftest.Antivirus.scan', return_value={'status': 'completed', 'scanned': 3, 'detected': 1}):
            result = self.diagnostic.run()
        self.assertEqual(result['status'], 'failed')
        self.assertIn('expected complete result', result['error'])
        self.assertFalse(any(step['title'] == 'Encrypted quarantine' for step in result['steps']))


if __name__ == '__main__':
    unittest.main()
