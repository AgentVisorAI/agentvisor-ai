#!/usr/bin/env python3
"""Drill encrypted backup/restore in an isolated, disposable PostgreSQL 18 container."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

IMAGE = 'postgres:18-bookworm@sha256:3725f4e2499eef5134592b3b4ab79a543ed7f8e533b05b5b637af926630f6650'
ROOT = Path(__file__).resolve().parent.parent


@contextmanager
def uninterrupted_cleanup():
    previous = {sig: signal.signal(sig, signal.SIG_IGN)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def stop_owned_group(process):
    # Docker clients can have credential-helper or plugin descendants. Killing
    # only the immediate client can leave those descendants running on cancel.
    with uninterrupted_cleanup():
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
            except PermissionError:
                # Darwin can report EPERM while a signalled process group
                # is disappearing. Confirm that our direct child exits;
                # do not send more signals to an inaccessible group.
                process.wait(timeout=max(0.1, deadline - time.monotonic()))
                return
            time.sleep(0.05)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run(command, **kwargs):
    timeout = kwargs.pop('timeout', 120)
    input_data = kwargs.pop('input', None)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True,
                               start_new_session=True, **kwargs)
    try:
        stdout, stderr = process.communicate(input_data, timeout=timeout)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command, stdout, stderr)
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except BaseException:
        stop_owned_group(process)
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                stream.close()


def inside():
    os.umask(0o077)
    report = {'checks': [], 'postgres': run(['pg_dump', '--version']).stdout.strip(),
              'gpg': run(['gpg', '--version']).stdout.splitlines()[0]}
    env = dict(os.environ, PGHOST='127.0.0.1', PGUSER='fixture',
               PGPASSWORD=os.environ['POSTGRES_PASSWORD'])

    def sql(database, query):
        return run(['psql', '--no-psqlrc', '--no-password', '--set', 'ON_ERROR_STOP=1',
                    '--tuples-only', '--no-align', '--dbname', database], input=query, env=env).stdout.strip()

    sql('postgres', 'CREATE DATABASE backup_source; CREATE DATABASE backup_restored;')
    sql('backup_source', """
      CREATE SCHEMA evidence;
      CREATE TABLE evidence.tenants(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text UNIQUE NOT NULL);
      INSERT INTO evidence.tenants(name) VALUES ('café 東京'), ('second tenant');
      CREATE TABLE evidence.events(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        tenant_id bigint REFERENCES evidence.tenants(id), payload jsonb NOT NULL,
        raw bytea, created_at timestamptz NOT NULL DEFAULT now());
      INSERT INTO evidence.events(tenant_id,payload,raw)
        SELECT 1+(n%2), jsonb_build_object('n',n,'text',repeat(md5(n::text),32)),
          decode(md5(n::text),'hex') FROM generate_series(1,10000) n;
      CREATE INDEX ON evidence.events(tenant_id,created_at);
      CREATE VIEW evidence.counts AS SELECT tenant_id,count(*) FROM evidence.events GROUP BY tenant_id;
    """)
    fingerprint = """SELECT md5(string_agg(row_to_json(t)::text,E'\n' ORDER BY id)) FROM evidence.events t;
      SELECT md5(string_agg(row_to_json(t)::text,E'\n' ORDER BY id)) FROM evidence.tenants t;
      SELECT * FROM evidence.counts ORDER BY tenant_id;"""
    source = sql('backup_source', fingerprint)
    with tempfile.TemporaryDirectory(prefix='backup-live-') as directory:
        work = Path(directory)
        phrase = secrets.token_urlsafe(48)
        backup_env = dict(env, BACKUP_DATABASE_URL='postgresql://fixture:' + env['PGPASSWORD'] +
                          '@127.0.0.1/backup_source', BACKUP_PASSPHRASE=phrase)
        result = run(['python3', '/fixture/postgres-backup.py', '--output-dir', str(work / 'out')],
                     env=backup_env, timeout=180)
        manifest = json.loads(result.stdout)
        encrypted = Path(manifest['file'])
        assert manifest['decryption_verified'] and manifest['archive_validated']
        assert list((work / 'out').iterdir()) == [encrypted]
        assert encrypted.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == manifest['sha256']
        report['checks'].append('only verified private ciphertext is published')
        home = work / 'gnupg'; home.mkdir(mode=0o700)
        common = ['gpg', '--no-options', '--homedir', str(home), '--batch', '--no-autostart',
                  '--no-symkey-cache', '--pinentry-mode', 'loopback', '--passphrase-fd', '0']
        restored = work / 'restore.dump'
        run(common + ['--output', str(restored), '--decrypt', str(encrypted)], input=phrase+'\n')
        run(['pg_restore', '--no-owner', '--no-privileges', '--single-transaction', '--exit-on-error',
             '--dbname', 'backup_restored', str(restored)], env=env)
        assert sql('backup_restored', fingerprint) == source
        report['checks'].append('10000 rows, Unicode, JSON, binary content and views restore exactly')
        assert sql('backup_restored', "INSERT INTO evidence.tenants(name) VALUES('after restore') RETURNING id;").startswith('3\n')
        report['checks'].append('identity sequence resumes after restored data')
        constraint = subprocess.run(['psql', '--no-psqlrc', '--set', 'ON_ERROR_STOP=1', '--dbname', 'backup_restored'],
            input="INSERT INTO evidence.events(tenant_id,payload) VALUES(999,'{}');", env=env,
            capture_output=True, text=True, timeout=30)
        assert constraint.returncode != 0 and 'foreign key' in constraint.stderr
        report['checks'].append('restored foreign key rejects invalid data')
        wrong = subprocess.run(common + ['--output', str(work / 'wrong.dump'), '--decrypt', str(encrypted)],
                               input='incorrect-passphrase\n', capture_output=True, text=True, timeout=30)
        assert wrong.returncode != 0
        report['checks'].append('incorrect passphrase is rejected')
        damaged = work / 'damaged.gpg'
        data = bytearray(encrypted.read_bytes()); data[len(data)//2] ^= 1; damaged.write_bytes(data)
        tamper = subprocess.run(common + ['--output', str(work / 'damaged.dump'), '--decrypt', str(damaged)],
                                input=phrase+'\n', capture_output=True, text=True, timeout=30)
        assert tamper.returncode != 0
        report['checks'].append('modified ciphertext is rejected')
        report['encrypted_bytes'] = manifest['bytes']
    report['passed'] = True
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--output-dir', type=Path, default=Path('/tmp/agentvisor-backup-results'))
    args = parser.parse_args()

    def cancelled(_signum, _frame):
        # A second cancellation must not interrupt process, temporary-file,
        # or container cleanup while the first one unwinds the stack.
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        raise KeyboardInterrupt

    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, cancelled)
    if args.inside:
        inside()
        return
    os.umask(0o077)
    output = args.output_dir.absolute(); output.mkdir(parents=True, exist_ok=True, mode=0o700)
    token = uuid.uuid4().hex[:12]
    name = 'av-backup-test-' + token
    tag = name + ':local'
    environment = dict(os.environ)
    if environment.get('DOCKER_HOST'):
        environment.pop('DOCKER_CONTEXT', None)

    def docker(*arguments, **kwargs):
        return run(['docker', *arguments], env=environment, **kwargs)

    primary_failure = None
    phase = 'build'
    try:
        with tempfile.TemporaryDirectory(prefix='av-backup-build-') as directory:
            context = Path(directory)
            shutil.copy2(ROOT / 'scripts/postgres-backup.py', context)
            shutil.copy2(__file__, context)
            (context / 'Dockerfile').write_text('FROM ' + IMAGE + '\n'
                'RUN apt-get update && apt-get install -y --no-install-recommends python3 gnupg '
                '&& rm -rf /var/lib/apt/lists/*\nCOPY *.py /fixture/\n')
            built = docker('build', '--label', 'agentvisor.backup-test='+token, '-t', tag, str(context), timeout=300)
            (output / 'build.log').write_text(built.stdout + built.stderr)
            password = secrets.token_hex(24)
            env_file = context / 'fixture.env'
            env_file.write_text('POSTGRES_USER=fixture\nPOSTGRES_PASSWORD='+password+'\n')
            env_file.chmod(0o600)
            phase = 'create'
            docker('create', '--name', name, '--label', 'agentvisor.backup-test='+token,
                   '--memory', '384m', '--cpus', '1', '--security-opt', 'no-new-privileges',
                   '--env-file', str(env_file), tag)
            phase = 'start'
            docker('start', name)
        phase = 'readiness'
        ready = False
        for _ in range(60):
            try:
                # TCP, not the local socket: the image's temporary init
                # server listens only on the socket, so a socket check can
                # pass before the final server accepts 127.0.0.1.
                docker('exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'fixture', '-d', 'postgres', timeout=10)
                ready = True
                break
            except subprocess.CalledProcessError:
                pass
            time.sleep(0.5)
        if not ready:
            raise RuntimeError('Owned PostgreSQL fixture did not become ready')
        phase = 'backup and restore'
        result = docker('exec', '--user', 'postgres', name, 'python3', '/fixture/postgres-backup-test.py', '--inside', timeout=240)
        report = json.loads(result.stdout)
        report['image'] = IMAGE
        (output / 'result.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))
    except BaseException as error:
        primary_failure = error
        failure = {'phase': phase, 'exception': type(error).__name__, 'message': str(error)}
        if isinstance(error, subprocess.SubprocessError):
            failure['command'] = getattr(error, 'cmd', None)
            failure['returncode'] = getattr(error, 'returncode', None)
            chunks = [getattr(error, 'stdout', None), getattr(error, 'stderr', None)]
            diagnostics = ''.join(chunk.decode(errors='replace') if isinstance(chunk, bytes)
                                  else (chunk or '') for chunk in chunks)
            (output / 'failure.log').write_text(diagnostics)
            failure['diagnostics'] = str(output / 'failure.log')
        (output / 'failure.json').write_text(json.dumps(failure, indent=2)+'\n')
        raise
    finally:
        with uninterrupted_cleanup():
            cleanup = {'container': name, 'image': tag, 'errors': []}
            try:
                # The daemon may have accepted create before the client lost
                # its connection. Query our exact name even after a failed
                # create, and distinguish absence from a failed daemon query.
                ids = docker('container', 'ls', '--all', '--filter', 'name=^/'+name+'$',
                             '--format', '{{.ID}}', timeout=30).stdout.split()
                for container_id in ids:
                    label = docker('inspect', '--format',
                                   '{{ index .Config.Labels "agentvisor.backup-test" }}',
                                   container_id, timeout=30).stdout.strip()
                    if label != token:
                        raise RuntimeError('Refusing cleanup of a container without the expected ownership label')
                    docker('rm', '-f', '-v', container_id, timeout=60)
                cleanup['container_removed_or_absent'] = True
            except (subprocess.SubprocessError, OSError, RuntimeError) as error:
                cleanup['errors'].append('Container cleanup failed: ' + str(error))
            try:
                ids = docker('image', 'ls', '--filter', 'reference='+tag,
                             '--format', '{{.ID}}', timeout=30).stdout.split()
                if ids:
                    label = docker('image', 'inspect', '--format',
                                   '{{ index .Config.Labels "agentvisor.backup-test" }}',
                                   tag, timeout=30).stdout.strip()
                    if label != token:
                        raise RuntimeError('Refusing cleanup of an image without the expected ownership label')
                    # Remove only this invocation's tag, not any other tag
                    # that might refer to the same content-addressed image.
                    docker('image', 'rm', tag, timeout=60)
                cleanup['image_removed_or_absent'] = True
            except (subprocess.SubprocessError, OSError, RuntimeError) as error:
                cleanup['errors'].append('Image cleanup failed: ' + str(error))
            (output / 'cleanup.json').write_text(json.dumps(cleanup, indent=2)+'\n')
            if cleanup['errors']:
                if primary_failure is None:
                    raise RuntimeError('; '.join(cleanup['errors']))
                print('Cleanup also failed; see ' + str(output / 'cleanup.json'), file=sys.stderr)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        # This isolated drill uses only synthetic data and credentials.
        # Preserve tool diagnostics so fixture failures can be investigated.
        print('Backup drill failed during ' + str(error.cmd[:2]) + ':\n' +
              (error.stderr or '')[-5000:], file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print('Backup drill interrupted; owned resources were cleaned.', file=sys.stderr)
        raise SystemExit(130)
    except (subprocess.TimeoutExpired, OSError, RuntimeError) as error:
        print('Backup drill failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
