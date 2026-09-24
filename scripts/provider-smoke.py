#!/usr/bin/env python3
"""Opt-in OpenAI-compatible provider drill through the real authenticated daemon.

This sends one fixed greeting prompt with at most 32 generated tokens. An
explicit model and --allow-live-request are required. The API key stays in
OPENAI_API_KEY; private identity/signing keys and the spool are removed after
the test. No existing daemon, database, or user configuration is modified.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_RESPONSE = 1024 * 1024


class ValidationError(Exception):
    """Messages contain only fixture-generated, non-secret diagnostics."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def provider_url(value):
    parsed = urlsplit(value)
    try:
        loopback = ipaddress.ip_address(parsed.hostname or '').is_loopback
    except ValueError:
        loopback = parsed.hostname == 'localhost'
    if (parsed.username is not None or parsed.password is not None or parsed.query
            or parsed.fragment or parsed.path not in ('', '/') or not parsed.hostname
            or parsed.scheme not in ('https', 'http')
            or (parsed.scheme == 'http' and not loopback)):
        raise ValidationError('Provider URL must be an HTTPS origin; HTTP is allowed only on loopback')
    try:
        parsed.port
    except ValueError:
        raise ValidationError('Provider URL has an invalid port') from None
    return value.rstrip('/')


def mint(secret, subject):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
    now = int(time.time())
    header = {'alg': 'HS256', 'typ': 'JWT', 'kid': 'dev-hmac'}
    claims = {'sub': subject, 'iss': 'provider-smoke', 'aud': 'agentvisor-ai',
              'iat': now, 'exp': now + 300, 'jti': str(uuid.uuid4()),
              'instance_uid': subject, 'charter': 'validation', 'version': '1.0',
              'scopes': ['*']}
    signing = encode(json.dumps(header).encode()) + '.' + encode(json.dumps(claims).encode())
    return signing + '.' + encode(hmac.new(secret, signing.encode(), hashlib.sha256).digest())


def stream_contract(body):
    """Require a complete non-error stream, actual text, and final usage."""
    try:
        text = body.decode('utf-8')
        if not text.endswith(('\n\n', '\r\n\r\n')):
            raise ValueError('incomplete frame')
        values = []
        done = False
        content = ''
        terminal = False
        usage = None
        for frame in re.split(r'\r?\n\r?\n', text):
            if any(line.partition(':')[2].strip() == 'error'
                   for line in frame.splitlines() if line.startswith('event:')):
                raise ValueError('error event')
            data = '\n'.join(line[5:].lstrip(' ') for line in frame.splitlines() if line.startswith('data:'))
            if not data:
                continue
            if done:
                raise ValueError('data after completion')
            if data == '[DONE]':
                done = True
                continue
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate field')
                    result[key] = value
                return result
            def invalid_constant(_value):
                raise ValueError('invalid JSON number')
            value = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
            if not isinstance(value, dict) or 'error' in value:
                raise ValueError('error frame')
            values.append(value)
            choices = value.get('choices')
            if not isinstance(choices, list) or len(choices) > 1:
                raise ValueError('unexpected choice count')
            for choice in choices:
                if (terminal or not isinstance(choice, dict)
                        or type(choice.get('index')) is not int or choice['index'] != 0
                        or not isinstance(choice.get('delta'), dict)):
                    raise ValueError('invalid or post-terminal choice')
                piece = choice['delta'].get('content')
                if piece is not None and not isinstance(piece, str):
                    raise ValueError('invalid text delta')
                if isinstance(piece, str):
                    content += piece
                reason = choice.get('finish_reason')
                if reason is not None:
                    if reason not in ('stop', 'length'):
                        raise ValueError('invalid text completion reason')
                    terminal = True
            if value.get('usage') is not None:
                usage = value['usage']
        if not done or not terminal or not content.strip() or not values or not isinstance(usage, dict):
            raise ValueError('missing completion evidence')
        if any(type(usage.get(key)) is not int or usage[key] < 0
               for key in ['prompt_tokens', 'completion_tokens', 'total_tokens']):
            raise ValueError('invalid usage')
        if usage['total_tokens'] != usage['prompt_tokens'] + usage['completion_tokens']:
            raise ValueError('inconsistent usage')
        if not 1 <= usage['completion_tokens'] <= 32 or usage['prompt_tokens'] < 1:
            raise ValueError('missing or excessive token usage')
        return {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'usage': usage}
    except (ValueError, TypeError, AttributeError, KeyError):
        raise ValidationError('Provider stream was incomplete, contained an error, or lacked valid usage') from None


def request(base, path, token=None, data=None, session=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if session:
        headers['X-AV-Session'] = session
    req = Request(base + path, headers=headers,
                  data=json.dumps(data).encode() if data is not None else None)
    opener = build_opener(ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=15)
    except HTTPError as error:
        response = error
    with response:
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValidationError('HTTP response exceeded the validation size bound')
        return response.status, body


def run(args):
    if not args.allow_live_request:
        raise ValidationError('Use --allow-live-request to authorize one bounded provider request')
    if not args.model or len(args.model) > 200 or any(ord(c) < 32 for c in args.model):
        raise ValidationError('Specify an explicit valid model identifier')
    upstream = provider_url(args.base_url)
    key = os.environ.get('OPENAI_API_KEY', '')
    if not key or any(c in key for c in '\r\n\0'):
        raise ValidationError('Configure a valid OPENAI_API_KEY in the environment')
    if not 10 <= args.timeout_seconds <= 300:
        raise ValidationError('Timeout must be between 10 and 300 seconds')
    binaries = {name: Path(getattr(args, name)).resolve() for name in ['agentvisord', 'avctl']}
    if any(not p.is_file() or not os.access(p, os.X_OK) for p in binaries.values()):
        raise ValidationError('Build agentvisord and avctl before running the drill')
    output = Path(args.output_dir).absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (output.is_symlink() or output.stat().st_uid != os.getuid()
            or output.stat().st_mode & 0o077 or any(output.iterdir())):
        raise ValidationError('Output must be an empty owner-only directory')
    report = {'status': 'running', 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'provider_origin': upstream, 'model': args.model, 'maximum_output_tokens': 32,
              'checks': [], 'binary_sha256': {n: hashlib.sha256(p.read_bytes()).hexdigest() for n, p in binaries.items()}}
    process = None
    work = Path(tempfile.mkdtemp(prefix='.provider-', dir=output))
    secret = os.urandom(32).hex().encode()
    identity = mint(secret, 'provider-' + uuid.uuid4().hex)
    secrets = [key, secret.decode(), identity]
    old_handlers = {}

    def cancelled(_signum, _frame):
        raise ValidationError('Provider validation was cancelled or exceeded its total deadline')

    def check(label, condition):
        if not condition:
            raise ValidationError(label)
        report['checks'].append(label)

    try:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
            old_handlers[sig] = signal.signal(sig, cancelled)
        signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds)
        for name, binary in binaries.items():
            shutil.copy2(binary, work / name)
        (work / 'identity.secret').write_bytes(secret)
        (work / 'identity.secret').chmod(0o600)
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        base = 'http://127.0.0.1:' + str(port)
        config = {'config_version': 1, 'listen': '127.0.0.1:' + str(port),
                  'upstream_url': upstream, 'upstream_api_key_env': 'OPENAI_API_KEY',
                  'require_identity': True, 'enforce_identity_scopes': True,
                  'identity_hmac_secret_file': str(work / 'identity.secret'),
                  'identity_allowed_issuers': ['provider-smoke'], 'default_workflow': 'signed',
                  'dashboard_enabled': False, 'atif_spool_dir': str(work / 'spool'),
                  'bridge_data_dir': str(work / 'bridge'), 'shutdown_drain_timeout_s': 5}
        (work / 'config.toml').write_text('\n'.join(k+' = '+json.dumps(v) for k, v in config.items())+'\n')
        environment = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR')}
        environment.update(OPENAI_API_KEY=key, AV_SIGNING_SEED_FILE=str(work / 'signing.seed'), RUST_LOG='warn')
        with (work / 'daemon.log').open('wb') as log:
            process = subprocess.Popen([str(work / 'agentvisord'), '--config', str(work / 'config.toml')],
                                       cwd=work, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
        ready = time.monotonic() + 20
        while True:
            if process.poll() is not None:
                raise ValidationError('Validation daemon exited before readiness')
            try:
                if request(base, '/readyz')[0] == 200:
                    break
            except (URLError, OSError):
                pass
            if time.monotonic() >= ready:
                raise ValidationError('Validation daemon did not become ready')
            time.sleep(0.05)
        check('authenticated daemon becomes ready', True)
        body = {'model': args.model, 'messages': [{'role': 'user', 'content': 'Reply with one brief greeting.'}],
                'stream': True, 'stream_options': {'include_usage': True}, 'max_completion_tokens': 32, 'store': False}
        check('anonymous inference is refused', request(base, '/v1/chat/completions', data=body)[0] == 401)
        session = 'provider-' + uuid.uuid4().hex
        status, response = request(base, '/v1/chat/completions', token=identity, data=body, session=session)
        check('authenticated provider request succeeds (HTTP ' + str(status) + ')', status == 200)
        report['stream'] = stream_contract(response)
        check('stream completes with text, terminal marker, and bounded token usage', True)
        check('provider and client credentials are absent from the response', all(s.encode() not in response for s in secrets))
        status, closed = request(base, '/v1/sessions/' + session + '/close', token=identity, data={})
        check('signed session closes with a receipt', status == 200 and json.loads(closed).get('kind') == 'receipt')
        status, receipt = request(base, '/v1/sessions/' + session + '/promote', token=identity, data={})
        check('receipt promotion succeeds', status == 200)
        parsed = json.loads(receipt)
        check('receipt records actual provider token usage', all(parsed['cost'][k] == report['stream']['usage'][k]
                                                               for k in ['prompt_tokens', 'completion_tokens']))
        (work / 'receipt.json').write_bytes(receipt)
        cli_env = {k: v for k, v in environment.items() if k not in ('OPENAI_API_KEY', 'AV_SIGNING_SEED_FILE')}
        public = subprocess.run([str(work / 'avctl'), 'pubkey', '--seed', str(work / 'signing.seed')],
                                env=cli_env, capture_output=True, text=True, timeout=10, check=True)
        public_key = json.loads(public.stdout)['public_key_hex']
        verify = subprocess.run([str(work / 'avctl'), 'receipt-verify', str(work / 'receipt.json'),
                                 '--public-key-hex', public_key], env=cli_env, capture_output=True, timeout=10)
        check('receipt verifies against the fixture signing key', verify.returncode == 0)
        parsed['cost']['prompt_tokens'] += 1
        (work / 'tampered.json').write_text(json.dumps(parsed))
        tampered = subprocess.run([str(work / 'avctl'), 'receipt-verify', str(work / 'tampered.json'),
                                   '--public-key-hex', public_key], env=cli_env, capture_output=True, timeout=10)
        check('receipt tampering is refused', tampered.returncode != 0)
        check('receipt contains no provider or client credentials', all(s.encode() not in receipt for s in secrets))
        (output / 'receipt.json').write_bytes(receipt)
        report['public_key_hex'] = public_key
        report['status'] = 'passed'
    except (ValidationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['status'] = 'failed'
        report['error'] = str(error) if isinstance(error, ValidationError) else type(error).__name__ + ' during validation'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        cleanup_errors = []
        try:
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as error:
            cleanup_errors.append(type(error).__name__ + ' stopping owned daemon')
        try:
            if (work / 'daemon.log').exists():
                diagnostic = (work / 'daemon.log').read_text(errors='replace')
                for value in secrets:
                    diagnostic = diagnostic.replace(value, '<redacted>')
                (output / 'daemon.log').write_text(diagnostic)
        except OSError as error:
            cleanup_errors.append(type(error).__name__ + ' saving sanitized diagnostics')
        try:
            shutil.rmtree(work)
        except OSError as error:
            cleanup_errors.append(type(error).__name__ + ' removing private files')
        report['cleanup'] = {'private_files_removed': not work.exists(),
                             'daemon_exited': process is None or process.poll() is not None,
                             'errors': cleanup_errors}
        if cleanup_errors or not all(report['cleanup'][k] for k in ('private_files_removed', 'daemon_exited')):
            report['status'] = 'failed'
            report.setdefault('error', 'Fixture cleanup did not complete')
        report['finished_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (output / 'result.json').write_text(json.dumps(report, indent=2)+'\n')
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-live-request', action='store_true')
    parser.add_argument('--model', required=True)
    parser.add_argument('--base-url', default='https://api.openai.com')
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--timeout-seconds', type=int, default=120)
    parser.add_argument('--agentvisord', default=str(ROOT/'target/release/agentvisord'))
    parser.add_argument('--avctl', default=str(ROOT/'target/release/avctl'))
    os.umask(0o077)
    try:
        report = run(parser.parse_args())
        print(json.dumps({'status': report['status'], 'checks': len(report['checks']),
                          'error': report.get('error')}))
        return 0 if report['status'] == 'passed' else 1
    except (ValidationError, OSError) as error:
        print(str(error) if isinstance(error, ValidationError) else 'Validation setup failed', file=__import__('sys').stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
