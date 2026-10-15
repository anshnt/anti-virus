import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import launch
from tools import package_source


class PortableSourceTests(unittest.TestCase):
    def test_mutex_is_stable_per_user_and_distinct_between_users(self):
        with patch('launch.Path.home', return_value=Path('C:/Users/FirstUser')):
            first = launch.mutex_name()
            self.assertEqual(first, launch.mutex_name())
        with patch('launch.Path.home', return_value=Path('C:/Users/SecondUser')):
            self.assertNotEqual(first, launch.mutex_name())
        self.assertNotIn('FirstUser', first)

    def test_unsupported_python_rejected_before_starting_process(self):
        with patch('launch.sys.version_info', (3, 10, 0)), patch('launch.subprocess.Popen') as spawn:
            with self.assertRaises(SystemExit):
                launch.main()
        spawn.assert_not_called()

    def test_source_package_excludes_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for filename in package_source.FILES:
                (root / filename).write_text('benign source fixture', encoding='utf-8')
            for directory in package_source.PATTERNS:
                (root / directory).mkdir()
            (root / 'app/core.py').write_text('# harmless source fixture', encoding='utf-8')
            (root / 'app/instance.json').write_text('{"nonce":"not-a-real-token"}', encoding='utf-8')
            (root / 'app/sentinel.sqlite3').write_bytes(b'not a real database')
            (root / 'web/private-report.json').write_text('{}', encoding='utf-8')
            with patch('tools.package_source.ROOT', root):
                names = [p.relative_to(root).as_posix() for p in package_source.source_files()]
            self.assertIn('app/core.py', names)
            self.assertFalse(any(name.endswith(('.json', '.sqlite3')) for name in names))


if __name__ == '__main__':
    unittest.main()
