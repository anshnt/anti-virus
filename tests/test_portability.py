import tempfile
import time
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

    def test_packaged_exe_relaunches_itself_not_python(self):
        from app import startup
        with patch('app.startup.sys.frozen', True, create=True), patch('app.startup.sys.executable', r'C:\Apps\SentinelLocal.exe'):
            self.assertEqual(startup.launch_args('--serve'), [r'C:\Apps\SentinelLocal.exe', '--serve'])
            self.assertEqual(startup.command(), r'C:\Apps\SentinelLocal.exe --no-browser')
        self.assertTrue(startup.launch_args('--serve')[1].endswith('launch.py'))

    def test_quit_request_waits_for_running_work(self):
        import ctypes
        import threading
        import uuid
        from types import SimpleNamespace
        from unittest.mock import MagicMock
        from app.server import quit_on_event
        name = 'Local\SentinelLocal.Test.' + uuid.uuid4().hex
        busy = [True]

        def request_stop():
            if busy[0]:
                raise ValueError('A scan is running.')
        server = SimpleNamespace(engine=SimpleNamespace(request_stop=request_stop, store=MagicMock()), shutdown=MagicMock())
        worker = threading.Thread(target=quit_on_event, args=(server, name), daemon=True)
        worker.start()
        kernel = ctypes.WinDLL('kernel32')
        kernel.OpenEventW.restype = ctypes.c_void_p
        kernel.SetEvent.argtypes = [ctypes.c_void_p]
        event = None
        for _ in range(100):
            event = event or kernel.OpenEventW(0x0002, False, name)
            if event:
                break
            time.sleep(0.02)
        kernel.SetEvent(event)
        time.sleep(0.3)
        server.shutdown.assert_not_called()
        busy[0] = False
        kernel.SetEvent(event)
        worker.join(5)
        server.shutdown.assert_called_once()

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
