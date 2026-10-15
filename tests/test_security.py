import base64
import hashlib
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from app import windows
from app.core import Engine, digest, file_path, scan_result, script_indicators
from app.server import LocalServer


def ev(record, event_id, scan='one', kind='Full Scan', **fields):
    return {'record': record, 'id': event_id, 'time': '2026-10-15T00:00:00+00:00',
            'fields': {'Scan ID': scan, 'Scan Parameters': kind, **fields}}


class ScanEvidenceTests(unittest.TestCase):
    def test_rpc_interruption_wins_even_with_success_exit_and_completion(self):
        events = [ev(1, 1000), ev(2, 1001), ev(3, 1002, **{'Stop Reason': 'RPC connection rundown'})]
        state, detail = scan_result(events, set(), 'full', 0)
        self.assertEqual(state, 'interrupted')
        self.assertIn('RPC connection rundown', detail)

    def test_exit_code_and_end_timestamp_cannot_prove_completion(self):
        self.assertEqual(scan_result([ev(1, 1000)], set(), 'full', 0)[0], 'unverified')

    def test_old_completion_cannot_validate_new_scan(self):
        events = [ev(1, 1000, 'old'), ev(2, 1001, 'old'), ev(3, 1000, 'new')]
        self.assertEqual(scan_result(events, {1, 2}, 'full', 0)[0], 'unverified')

    def test_other_scan_completion_cannot_validate_this_scan(self):
        self.assertEqual(scan_result([ev(1, 1000), ev(2, 1001, 'other')], set(), 'full', 0)[0], 'unverified')

    def test_unique_correlated_completion(self):
        self.assertEqual(scan_result([ev(1, 1000), ev(2, 1001)], set(), 'full', 0)[0], 'completed')

    def test_ambiguous_concurrent_scans_stay_unverified(self):
        self.assertEqual(scan_result([ev(1, 1000), ev(2, 1000, 'other'), ev(3, 1001)], set(), 'full', 0)[0], 'unverified')

    def test_failed_command_cannot_be_green(self):
        self.assertEqual(scan_result([ev(1, 1000), ev(2, 1001)], set(), 'full', 2)[0], 'unverified')

    def test_empty_windows_pipeline_not_a_threat_record(self):
        with patch('app.windows.powershell', return_value={'sections': {'threats': {'ok': True, 'data': {}}}}):
            self.assertEqual(windows.snapshot()['sections']['threats']['data'], [])


class FileAndStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.file = self.folder / 'benign.txt'
        self.file.write_text('A harmless local test file.', encoding='utf-8')
        self.engine = Engine(self.folder / 'data', start=False)

    def tearDown(self):
        self.engine.stop.set()
        self.temp.cleanup()

    def test_full_sha256_matches_known_bytes(self):
        self.assertEqual(digest(self.file), hashlib.sha256(self.file.read_bytes()).hexdigest())

    def test_limits_do_not_produce_partial_hashes(self):
        with self.assertRaises(ValueError):
            digest(self.file, limit=2)

    def test_unc_device_ads_and_relative_paths_rejected(self):
        for raw in ('\\\\server\\share\\file', '\\\\?\\C:\\test', 'C:\\test:stream', '../file', 'C:relative'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                file_path(raw)

    def test_reparse_and_cloud_files_rejected(self):
        for attrs in (0x400, 0x1000, 0x40000, 0x400000):
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_file_attributes=attrs)):
                with self.assertRaises(ValueError):
                    file_path(str(self.file))

    def test_static_patterns_never_execute_file(self):
        sample = self.folder / 'example.ps1'
        sample.write_text('# A documentation example: powershell -EncodedCommand SAMPLE', encoding='utf-8')
        self.assertIn('Encoded PowerShell command', script_indicators(sample))
        self.assertEqual(script_indicators(self.file), [])
        self.assertFalse((self.folder / 'SAMPLE').exists())

    def test_integrity_detects_changes_without_replacing_baseline(self):
        self.engine.integrity_add(str(self.file))
        original = digest(self.file)
        self.file.write_text('Normal edit by its owner', encoding='utf-8')
        self.engine._integrity()
        record = self.engine.status()['integrity'][0]
        self.assertEqual(record['status'], 'changed')
        self.assertEqual(record['hash'], original)
        self.assertNotEqual(record['lastHash'], original)
        self.engine.integrity_remove(str(self.file))
        self.assertTrue(self.file.exists())

    def test_missing_integrity_file_becomes_unavailable(self):
        self.engine.integrity_add(str(self.file))
        self.file.unlink()
        self.engine._integrity()
        self.assertEqual(self.engine.status()['integrity'][0]['status'], 'unavailable')

    def test_unavailable_snapshot_not_converted_to_safe_defaults(self):
        self.engine.snapshot = {'sections': {'defender': {'ok': False, 'error': 'Denied'}}, 'checkedAt': None}
        self.assertFalse(self.engine.status()['snapshot']['sections']['defender']['ok'])
        self.assertNotIn('AntivirusEnabled', self.engine.status()['snapshot']['sections']['defender'])

    def test_interrupted_jobs_not_reported_as_success_after_restart(self):
        with self.engine.store.connect() as c:
            c.execute("INSERT INTO jobs VALUES('test','full','running','2026',NULL,'running',NULL)")
        restarted = Engine(self.folder / 'data', start=False)
        self.assertEqual(restarted.status()['jobs'][0]['status'], 'unverified')

    def test_hash_list_rejects_commands_and_bad_values(self):
        with self.assertRaises(ValueError):
            self.engine.settings({'watchDownloads': True, 'hashes': [';Remove-Item C:\\']})

    def test_stopped_engine_cannot_accept_new_scan(self):
        self.engine.request_stop()
        with self.assertRaises(ValueError):
            self.engine.job('quick')

    def test_powershell_user_path_stays_in_stdin(self):
        dangerous = r'C:\example\$(Write-Output SECRET); example.txt'
        with patch('app.windows.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout='{}')) as run:
            windows.powershell('$request.path | ConvertTo-Json', {'path': dangerous})
        args, kwargs = run.call_args
        command = base64.b64decode(args[0][-1]).decode('utf-16-le')
        self.assertNotIn(dangerous, command)
        self.assertEqual(json.loads(kwargs['input'])['path'], dangerous)
        self.assertFalse(kwargs['shell'])


class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.engine = Engine(Path(self.temp.name), start=False)
        self.server = LocalServer(('127.0.0.1', 0), self.engine, metadata=False)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ''

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def call(self, method='GET', path='/api/state', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        h = {'Cookie': self.cookie, 'X-CSRF-Token': self.server.csrf} if self.cookie else {}
        if body is not None:
            body = json.dumps(body)
            h.update({'Content-Type': 'application/json', 'Origin': self.server.origin, 'X-CSRF-Token': self.server.csrf})
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        response = conn.getresponse()
        result = (response.status, dict(response.getheaders()), response.read())
        conn.close()
        return result

    def login(self):
        result = self.call(path='/open/' + self.server.nonce)
        self.cookie = result[1]['Set-Cookie'].split(';')[0]
        return result

    def test_health_is_only_nonsensitive_public_endpoint(self):
        self.assertEqual(self.call(path='/health')[0], 200)
        for path in ('/', '/api/state', '/api/export', '/app.js'):
            self.assertEqual(self.call(path=path)[0], 401)

    def test_bootstrap_one_use_and_cookie_flags(self):
        nonce = self.server.nonce
        result = self.login()
        self.assertEqual(result[0], 303)
        self.assertIn('HttpOnly', result[1]['Set-Cookie'])
        self.assertIn('SameSite=Strict', result[1]['Set-Cookie'])
        self.assertEqual(self.call(path='/open/' + nonce)[0], 401)
        self.assertEqual(self.call()[0], 200)

    def test_cookie_alone_cannot_read_api_or_recover_token(self):
        self.login()
        for route in ('/api/state', '/api/export'):
            self.assertEqual(self.call(path=route, headers={'X-CSRF-Token': ''})[0], 403)
        result = self.call()
        self.assertNotIn('csrf', json.loads(result[2]))

    def test_report_requires_private_header_and_is_downloadable(self):
        self.login()
        result = self.call(path='/api/export')
        self.assertEqual(result[0], 200)
        self.assertIn('attachment', result[1]['Content-Disposition'])
        self.assertNotIn(self.server.csrf, result[2].decode())

    def test_dns_rebinding_host_and_origin_are_rejected(self):
        self.login()
        self.assertEqual(self.call(headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.call(headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.call(headers={'Sec-Fetch-Site': 'cross-site'})[0], 403)

    def test_csrf_missing_wrong_and_wrong_origin_cannot_mutate(self):
        self.login()
        for headers in ({'X-CSRF-Token': ''}, {'X-CSRF-Token': 'wrong'}, {'Origin': 'https://evil.example'}, {'Origin': ''}):
            self.assertEqual(self.call('POST', '/api/settings', {'watchDownloads': False, 'hashes': []}, headers)[0], 403)
        self.assertEqual(self.engine.store.get('settings'), None)

    def test_authenticated_settings_work(self):
        self.login()
        self.assertEqual(self.call('POST', '/api/settings', {'watchDownloads': False, 'hashes': []})[0], 200)
        self.assertFalse(self.engine.store.get('settings')['watchDownloads'])

    def test_static_whitelist_rejects_traversal_and_database(self):
        self.login()
        for path in ('/../app/core.py', '/%2e%2e/launch.py', '/.data/sentinel.sqlite3', '/launch.py', '/app.js?x=1'):
            self.assertEqual(self.call(path=path)[0], 404)
        result = self.call(path='/')
        self.assertEqual(result[0], 200)
        self.assertIn("frame-ancestors 'none'", result[1]['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', result[1])

    def test_body_limit_and_wrong_mime(self):
        self.login()
        self.assertEqual(self.call('POST', '/api/settings', {}, {'Content-Length': '70000'})[0], 413)
        self.assertEqual(self.call('POST', '/api/settings', {}, {'Content-Type': 'text/plain'})[0], 415)

    def test_unknown_actions_do_not_run_commands(self):
        self.login()
        with patch('app.windows.run_defender') as run:
            self.assertEqual(self.call('POST', '/api/execute', {'command': 'whoami'})[0], 404)
            self.assertEqual(self.call('POST', '/api/job', {'kind': 'shell'})[0], 400)
        run.assert_not_called()

    def test_expired_session_rejected(self):
        self.login()
        self.server.expires = time.time() - 1
        self.assertEqual(self.call()[0], 401)

    def test_non_ascii_invalid_tokens_are_rejected_without_exception(self):
        self.login()
        self.assertEqual(self.call('POST', '/api/settings', {}, {'X-CSRF-Token': '\u00ff'})[0], 403)
        self.assertEqual(self.call(headers={'Cookie': 'sentinel_session=wrong'})[0], 401)

    def test_quit_blocked_during_scan(self):
        self.login()
        self.engine.scan_lock.acquire()
        try:
            self.assertEqual(self.call('POST', '/api/quit', {})[0], 400)
        finally:
            self.engine.scan_lock.release()


if __name__ == '__main__':
    unittest.main()
