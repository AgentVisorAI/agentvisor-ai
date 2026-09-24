#!/usr/bin/env python3
"""Create, decrypt-check, and atomically publish a private encrypted PG archive.

BACKUP_DATABASE_URL and BACKUP_PASSPHRASE are required. Credentials never enter
command arguments or emitted diagnostics. Only ciphertext leaves the private
temporary directory. No existing database is modified by this command.
"""

import argparse
from contextlib import contextmanager
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import unquote, urlsplit


class BackupError(Exception):
    pass


@contextmanager
def finishing_cleanup():
    handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


@contextmanager
def private_workdir(output):
    temporary = tempfile.TemporaryDirectory(prefix='.backup-', dir=output)
    try:
        yield Path(temporary.name)
    finally:
        with finishing_cleanup():
            temporary.cleanup()


def digest(path, deadline=None):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            if deadline is not None and time.monotonic() >= deadline:
                raise BackupError('Backup deadline exceeded during archive verification')
            result.update(chunk)
    return result.hexdigest()


def stop_owned_group(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            process.wait()
            return
        time.sleep(0.05)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def run_phase(name, command, env, deadline, stdin=None):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise BackupError('Backup deadline exceeded before ' + name)
    process = None
    completed = False
    try:
        # Tool errors can contain database identifiers or credentials. Keep
        # them private and report the phase and exit status instead.
        process = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        process.communicate(stdin, timeout=remaining)
        if process.returncode:
            raise BackupError(name + ' failed with exit status ' + str(process.returncode))
        completed = True
    except subprocess.TimeoutExpired:
        raise BackupError('Backup deadline exceeded during ' + name) from None
    finally:
        if process is not None and not completed:
            with finishing_cleanup():
                stop_owned_group(process)


def private_output_dir(path):
    path = Path(path).absolute()
    if '\n' in str(path) or '\r' in str(path):
        raise BackupError('Output directory must not contain line breaks')
    if path.is_symlink():
        raise BackupError('Output directory must not be a symbolic link')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise BackupError('Output directory must be owned by this user with mode 0700')
    return path


def connection_service(database_url, path):
    """Use libpq's private service file so the URI never enters argv."""
    try:
        if re.search(r'%(?![0-9a-fA-F]{2})', database_url):
            raise ValueError('Invalid percent encoding')
        uri = urlsplit(database_url)
        parameters = {}
        # Preserve case in percent-encoded Unix socket paths. urlsplit's
        # hostname property lowercases non-DNS hosts as well.
        authority = uri.netloc.rsplit('@', 1)[-1]
        host = uri.hostname
        if authority and not authority.startswith('['):
            host = authority.rsplit(':', 1)[0] if ':' in authority else authority
        for key, value in [('host', host), ('port', uri.port),
                           ('user', uri.username), ('password', uri.password)]:
            if value is not None:
                parameters[key] = unquote(str(value))
        if uri.path and uri.path != '/':
            parameters['dbname'] = unquote(uri.path[1:])
        # libpq URI queries use percent encoding, not HTML form encoding;
        # a literal '+' is part of the value, including passwords/options.
        for option in uri.query.split('&') if uri.query else []:
            if '=' not in option:
                raise ValueError('Connection option requires a value')
            key, value = option.split('=', 1)
            parameters[unquote(key)] = unquote(value)
    except ValueError:
        raise BackupError('Invalid PostgreSQL connection URI') from None
    if uri.fragment:
        raise BackupError('PostgreSQL connection URI must not contain a fragment')
    password = parameters.pop('password', None)
    # Service files contain one unquoted key=value per line. Reject values
    # that their parser would trim or reinterpret instead of silently
    # changing an operator-supplied connection. Password whitespace is
    # preserved through the dump-only PGPASSWORD environment variable.
    for key, value in parameters.items():
        if (not key or not all(c in 'abcdefghijklmnopqrstuvwxyz_' for c in key)
                or any(c in value for c in '\r\n\0') or value != value.strip()):
            raise BackupError('Connection URI contains an unsupported service-file option')
    if password is not None and '\0' in password:
        raise BackupError('Connection password must not contain NUL bytes')
    path.write_text('[agentvisor_backup]\n' + ''.join(k+'='+v+'\n' for k, v in parameters.items()))
    path.chmod(0o600)
    return password


def create_backup(args):
    database_url = os.environ.get('BACKUP_DATABASE_URL', '')
    passphrase = os.environ.get('BACKUP_PASSPHRASE', '')
    if not database_url or not passphrase:
        raise BackupError('BACKUP_DATABASE_URL and BACKUP_PASSPHRASE are required')
    if not database_url.startswith(('postgres://', 'postgresql://')):
        raise BackupError('BACKUP_DATABASE_URL must be a PostgreSQL connection URI')
    if any(character in passphrase for character in '\r\n\0'):
        raise BackupError('BACKUP_PASSPHRASE must be a single line without NUL bytes')
    if len(passphrase.encode()) > 65536:
        raise BackupError('BACKUP_PASSPHRASE exceeds the supported size')
    if not 1 <= args.timeout_seconds <= 86400:
        raise BackupError('Timeout must be between 1 and 86400 seconds')
    output = private_output_dir(args.output_dir)
    deadline = time.monotonic() + args.timeout_seconds
    environment = dict(os.environ)
    for key in list(environment):
        if key in ('BACKUP_DATABASE_URL', 'BACKUP_PASSPHRASE') or key.startswith('PG'):
            environment.pop(key, None)
    started = datetime.datetime.now(datetime.timezone.utc)
    filename = 'agentvisor-' + started.strftime('%Y%m%d-%H%M%S') + '-' + uuid.uuid4().hex[:12] + '.dump.gpg'
    destination = output / filename
    with private_workdir(output) as work:
        plaintext = work / 'backup.dump'
        encrypted = work / 'backup.dump.gpg'
        verified = work / 'verified.dump'
        gnupg = work / 'gnupg'
        gnupg.mkdir(mode=0o700)
        service = work / 'pg_service.conf'
        password = connection_service(database_url, service)
        dump_env = dict(environment, PGSERVICEFILE=str(service))
        if password is not None:
            dump_env['PGPASSWORD'] = password
        run_phase('pg_dump', [args.pg_dump, '--dbname=service=agentvisor_backup', '--format=custom', '--compress=9',
                  '--no-owner', '--no-privileges', '--no-password',
                  '--lock-wait-timeout=60000', '--file', str(plaintext)], dump_env, deadline)
        if not plaintext.is_file() or plaintext.stat().st_size == 0:
            raise BackupError('pg_dump did not produce a nonempty archive')
        run_phase('archive validation', [args.pg_restore, '--list', str(plaintext)], environment, deadline)
        common = [args.gpg, '--no-options', '--homedir', str(gnupg), '--batch',
                  '--no-autostart', '--no-symkey-cache', '--pinentry-mode', 'loopback',
                  '--passphrase-fd', '0']
        secret_input = passphrase.encode() + b'\n'
        run_phase('encryption', common + ['--symmetric', '--cipher-algo', 'AES256',
                  '--s2k-count', '65011712', '--s2k-digest-algo', 'SHA256',
                  '--compress-algo', 'none', '--output', str(encrypted), str(plaintext)],
                  environment, deadline, secret_input)
        run_phase('decryption verification', common + ['--output', str(verified),
                  '--decrypt', str(encrypted)], environment, deadline, secret_input)
        if not verified.is_file() or digest(plaintext, deadline) != digest(verified, deadline):
            raise BackupError('Decrypted archive does not match the original dump')
        if not encrypted.is_file() or encrypted.stat().st_size == 0:
            raise BackupError('Encryption did not produce a nonempty artifact')
        ciphertext_digest = digest(encrypted, deadline)
        encrypted.chmod(0o600)
        with encrypted.open('rb') as stream:
            os.fsync(stream.fileno())
        # A link publishes the complete artifact atomically without replacing
        # any existing file, including a malicious or accidental symlink.
        os.link(encrypted, destination)
        directory_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return {'file': str(destination), 'sha256': ciphertext_digest,
            'bytes': destination.stat().st_size, 'encrypted': True,
            'decryption_verified': True, 'archive_validated': True,
            'created_at': started.isoformat()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--pg-dump', default='pg_dump')
    parser.add_argument('--pg-restore', default='pg_restore')
    parser.add_argument('--gpg', default='gpg')
    parser.add_argument('--timeout-seconds', type=int, default=900)
    args = parser.parse_args()
    os.umask(0o077)

    def cancelled(_signum, _frame):
        # A second cancellation must not interrupt owned-child or file
        # cleanup after the first signal began unwinding the command.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    try:
        result = create_backup(args)
        print(json.dumps(result), flush=True)
        return 0
    except KeyboardInterrupt:
        print('Backup interrupted; private temporary files were removed.', file=sys.stderr)
        return 130
    except (BackupError, OSError):
        # Never echo raw subprocess output or exception paths containing
        # operator-provided data. The exception class/phase is enough for CI.
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, BackupError) else 'Backup file or tool operation failed'
        print(message + '; no backup was reported for upload.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
