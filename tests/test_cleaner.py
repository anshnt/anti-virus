import _winapi
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import cleaner
from app.core import Store


def old(path, days=3):
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


class JunkCleaningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.junk = self.root / 'junk'
        (self.junk / 'nested').mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_only_old_files_and_empty_old_folders_are_removed(self):
        stale, fresh = self.junk / 'nested' / 'stale.tmp', self.junk / 'fresh.tmp'
        stale.write_bytes(b'x' * 10)
        fresh.write_bytes(b'y')
        old(stale)
        old(self.junk / 'nested')
        result = cleaner.clean_roots([self.junk], older_than=time.time() - cleaner.JUNK_AGE)
        self.assertEqual(result, {'freed': 10, 'removed': 1, 'failed': 0})
        self.assertFalse((self.junk / 'nested').exists())
        self.assertTrue(fresh.exists())
        self.assertTrue(self.junk.exists())

    def test_junctions_are_never_followed(self):
        precious = self.root / 'documents'
        precious.mkdir()
        (precious / 'thesis.docx').write_bytes(b'keep me')
        old(precious / 'thesis.docx')
        _winapi.CreateJunction(str(precious), str(self.junk / 'link'))
        self.assertEqual(list(cleaner.walk(self.junk)), [])
        cleaner.clean_roots([self.junk])
        self.assertTrue((precious / 'thesis.docx').exists())
        # A junction used as a category root is refused outright.
        self.assertEqual(list(cleaner.walk(self.junk / 'link')), [])

    def test_name_pattern_limits_matches(self):
        for name in ('thumbcache_96.db', 'iconcache_16.db'):
            (self.junk / name).write_bytes(b'1')
        found = [Path(p).name for p, _, _ in cleaner.walk(self.junk, 'thumbcache_*.db')]
        self.assertEqual(found, ['thumbcache_96.db'])


class UninstallCommandTests(unittest.TestCase):
    def test_quoted_and_unquoted_commands(self):
        exe = os.path.join(os.environ['SystemRoot'], 'System32', 'cmd.exe')
        self.assertEqual(cleaner.split_command(f'"{exe}" /S'), (exe, '/S'))
        self.assertEqual(cleaner.split_command(f'{exe} /uninstall now'), (exe, '/uninstall now'))

    def test_msi_repair_command_becomes_uninstall(self):
        exe, args = cleaner.split_command('MsiExec.exe /I{DE0C11C6-CDCB-4D93-A4B7-C9B4F492EA16}')
        self.assertTrue(exe.lower().endswith(r'system32\msiexec.exe'))
        self.assertEqual(args, '/X{DE0C11C6-CDCB-4D93-A4B7-C9B4F492EA16}')

    def test_missing_or_unparseable_uninstaller_is_refused(self):
        for command in (r'"C:\nowhere\unins000.exe"', 'not a command'):
            with self.assertRaises(ValueError):
                cleaner.split_command(command)


class CleanerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cleaner = cleaner.Cleaner(Store(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def test_recycle_only_accepts_files_from_the_last_scan(self):
        target = Path(self.temp.name) / 'big.iso'
        target.write_bytes(b'z')
        with patch.object(cleaner, 'send_to_recycle_bin') as send:
            with self.assertRaises(ValueError):
                self.cleaner.recycle([str(target)])
            self.cleaner.review = [{'path': str(target), 'bytes': 1, 'modified': 0, 'reason': 'Large file'}]
            self.assertEqual(self.cleaner.recycle([str(target)])['moved'], 1)
        send.assert_called_once()
        self.assertEqual(self.cleaner.review, [])

    def test_clean_rejects_unknown_or_empty_categories(self):
        for categories in ([], ['C:\\Users'], 'temp', ['temp'] * 9):
            with self.assertRaises(ValueError):
                self.cleaner.clean(categories)

    def test_clean_runs_in_background_and_records_result(self):
        roots = {'temp': ('Temp', '', [Path(self.temp.name) / 'missing'], None)}
        with patch.object(cleaner, 'junk_categories', return_value=roots), patch.object(cleaner, 'recycle_bin', return_value=None), \
                patch.object(self.cleaner, '_review_files', return_value=[]):
            self.cleaner.clean(['temp'])
            for _ in range(100):
                if not self.cleaner.busy:
                    break
                time.sleep(0.05)
        self.assertIsNone(self.cleaner.error)
        self.assertEqual(self.cleaner.last['removed'], 0)
        self.assertIsNotNone(self.cleaner.analyzed)


if __name__ == '__main__':
    unittest.main()
