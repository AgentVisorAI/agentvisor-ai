#!/usr/bin/env python3
"""Finite loopback provider contracts; no external API account or network is used."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('provider_smoke', ROOT/'scripts/provider-smoke.py')
SMOKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SMOKE)
KEY = 'sk-loopback-provider-fixture-only'


def stream():
    frames = [
        {'choices': [{'index': 0, 'delta': {'content': 'Hello!'}, 'finish_reason': None}]},
        {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]},
        {'choices': [], 'usage': {'prompt_tokens': 9, 'completion_tokens': 2, 'total_tokens': 11}},
    ]
    return ''.join('data: '+json.dumps(x)+'\n\n' for x in frames).encode()+b'data: [DONE]\n\n'


@contextlib.contextmanager
def provider(response, status=200, pause=None):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            seen.append({'path': self.path, 'headers': dict(self.headers),
                         'body': json.loads(self.rfile.read(int(self.headers['Content-Length'])))})
            if pause is not None:
                pause.wait(timeout=20)
            self.send_response(status)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(response)))
            self.end_headers()
            try:
                self.wfile.write(response)
            except (BrokenPipeError, ConnectionResetError):
                pass
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:'+str(server.server_port), seen
    finally:
        if pause is not None:
            pause.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('Loopback fixture did not exit')


class StreamContracts(unittest.TestCase):
    def test_complete_stream(self):
        self.assertEqual(SMOKE.stream_contract(stream())['usage']['total_tokens'], 11)

    def test_incomplete_and_error_streams_fail(self):
        invalid = [stream().replace(b'data: [DONE]\n\n', b''), stream()[:-1],
                   stream()+b'data: {}\n\n', stream().replace(b'"stop"', b'null'),
                   stream().replace(b'"stop"', b'"error"'), stream().replace(b'"stop"', b'1'),
                   stream().replace(b'"index": 0, "delta": {}', b'"index": 1, "delta": {}'),
                   stream().replace(b'data: [DONE]', b'data: {"choices":[{"index":0,"delta":{"content":"late"}}]}\n\ndata: [DONE]'),
                   stream().replace(b'Hello!', b' '), stream().replace(b'"total_tokens": 11', b'"total_tokens": 12'),
                   stream().replace(b'"completion_tokens": 2', b'"completion_tokens": true'),
                   stream().replace(b'"prompt_tokens": 9', b'"prompt_tokens": NaN'),
                   stream().replace(b'"prompt_tokens": 9', b'"prompt_tokens": 9, "prompt_tokens": 9'),
                   b'event: error\ndata: {}\n\n'+stream(), b'data: {"error":{}}\n\n'+stream()]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(SMOKE.ValidationError):
                SMOKE.stream_contract(value)

    def test_provider_url_boundary(self):
        for value in ['http://example.org', 'https://user:pass@example.org', 'https://example.org/v1',
                      'https://example.org?q=1', 'https://example.org/#secret', 'https://example.org:invalid']:
            with self.subTest(value=value), self.assertRaises(SMOKE.ValidationError):
                SMOKE.provider_url(value)
        self.assertEqual(SMOKE.provider_url('https://api.openai.com/'), 'https://api.openai.com')
        self.assertEqual(SMOKE.provider_url('http://127.0.0.1:1234'), 'http://127.0.0.1:1234')


class RealDaemonContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.daemon = Path(os.environ.get('AGENTVISORD', ROOT/'target/debug/agentvisord'))
        cls.cli = Path(os.environ.get('AVCTL', ROOT/'target/debug/avctl'))
        if not cls.daemon.is_file() or not cls.cli.is_file():
            raise RuntimeError('Build agentvisord and avctl or set AGENTVISORD and AVCTL; this suite does not skip live contracts')

    def execute(self, directory, origin, extra=(), allow=True, key=KEY, timeout=45):
        command = [sys.executable, str(ROOT/'scripts/provider-smoke.py'), '--model', 'loopback-fixture',
                   '--base-url', origin, '--output-dir', str(directory),
                   '--agentvisord', str(self.daemon), '--avctl', str(self.cli), '--timeout-seconds', '30']
        if allow:
            command.append('--allow-live-request')
        environment = os.environ.copy()
        environment['OPENAI_API_KEY'] = key
        return subprocess.run(command+list(extra), env=environment, capture_output=True, text=True, timeout=timeout)

    def test_opt_in_and_key_required_before_network(self):
        with tempfile.TemporaryDirectory() as folder, provider(stream()) as (origin, seen):
            for kwargs in ({'allow': False}, {'key': ''}):
                result = self.execute(Path(folder)/'result', origin, **kwargs)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse((Path(folder)/'result').exists())
            self.assertEqual(seen, [])

    def test_complete_authenticated_stream_and_signed_receipt(self):
        with tempfile.TemporaryDirectory() as folder, provider(stream()) as (origin, seen):
            output = Path(folder)/'result'
            result = self.execute(output, origin)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr+(output/'daemon.log').read_text())
            report = json.loads((output/'result.json').read_text())
            self.assertEqual(report['status'], 'passed')
            self.assertEqual(len(report['checks']), 11)
            self.assertEqual(report['cleanup'], {'private_files_removed': True, 'daemon_exited': True, 'errors': []})
            self.assertEqual(len(seen), 1)
            request = seen[0]
            self.assertEqual(request['path'], '/v1/chat/completions')
            headers = {k.lower(): v for k,v in request['headers'].items()}
            self.assertEqual(headers['authorization'], 'Bearer '+KEY)
            self.assertEqual(request['body']['max_completion_tokens'], 32)
            self.assertTrue(request['body']['stream_options']['include_usage'])
            self.assertFalse(request['body']['store'])
            self.assertEqual(set(p.name for p in output.iterdir()), {'result.json','receipt.json','daemon.log'})
            for path in output.iterdir():
                self.assertNotIn(KEY, path.read_text())
                self.assertFalse(path.stat().st_mode & 0o077)

    def test_truncated_response_fails_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as folder, provider(stream().replace(b'data: [DONE]\n\n', b'')) as (origin, seen):
            output = Path(folder)/'result'
            result = self.execute(output, origin)
            self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
            report = json.loads((output/'result.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertTrue(report['cleanup']['private_files_removed'])
            self.assertTrue(report['cleanup']['daemon_exited'])
            self.assertFalse((output/'receipt.json').exists())
            self.assertEqual(len(seen), 1)

    def test_provider_auth_failure_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as folder, provider(b'{"error":{"code":"invalid_api_key"}}', 401) as (origin, seen):
            output = Path(folder)/'result'
            result = self.execute(output, origin)
            self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
            report = json.loads((output/'result.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertTrue(report['cleanup']['private_files_removed'])
            self.assertTrue(report['cleanup']['daemon_exited'])
            self.assertEqual(len(seen), 1)
            self.assertNotIn(KEY, (output/'daemon.log').read_text())

    def test_cancellation_during_upstream_wait_cleans_up(self):
        pause = threading.Event()
        with tempfile.TemporaryDirectory() as folder, provider(stream(), pause=pause) as (origin, seen):
            output = Path(folder)/'result'
            command = [sys.executable, str(ROOT/'scripts/provider-smoke.py'), '--allow-live-request',
                       '--model', 'loopback-fixture', '--base-url', origin, '--output-dir', str(output),
                       '--agentvisord', str(self.daemon), '--avctl', str(self.cli)]
            environment = os.environ.copy()
            environment['OPENAI_API_KEY'] = KEY
            process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic()+20
                while not seen and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(len(seen), 1)
                process.send_signal(signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=18)
                self.assertEqual(process.returncode, 1, stdout+stderr)
                report = json.loads((output/'result.json').read_text())
                self.assertIn('cancelled', report['error'])
                self.assertTrue(report['cleanup']['private_files_removed'])
                self.assertTrue(report['cleanup']['daemon_exited'])
                self.assertFalse(list(output.glob('.provider-*')))
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    process.communicate(timeout=18)

    def test_startup_failure_cleans_up(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder)/'result'
            result = self.execute(output, 'http://127.0.0.1:1', extra=['--agentvisord', '/usr/bin/false'])
            self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
            report = json.loads((output/'result.json').read_text())
            self.assertEqual(report['status'], 'failed')
            self.assertTrue(report['cleanup']['private_files_removed'])
            self.assertTrue(report['cleanup']['daemon_exited'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
