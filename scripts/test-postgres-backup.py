#!/usr/bin/env python3
"""Failure, confidentiality, and cleanup regressions for the backup command."""

import json
import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name('postgres-backup.py')
SPEC = importlib.util.spec_from_file_location('backup', SCRIPT)
BACKUP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BACKUP)
TOOLS = r'''#!/usr/bin/env python3
import base64,json,os,signal,sys,time
from pathlib import Path
kind=Path(sys.argv[0]).name
mode=os.environ.get('BACKUP_TEST_MODE','ok')
with open(os.environ['BACKUP_TEST_LOG'],'a') as log:
 log.write(json.dumps({'kind':kind,'args':sys.argv[1:],
  'database':os.environ.get('PGSERVICEFILE',''),
  'password':bool(os.environ.get('PGPASSWORD')),
  'secret_env':any(k in os.environ for k in ('BACKUP_DATABASE_URL','BACKUP_PASSPHRASE'))})+'\n')
if kind=='pg_dump':
 if mode=='wait':
  child=os.fork()
  if child==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN)
   Path(os.environ['BACKUP_TEST_CHILD']).write_text(str(os.getpid()))
   while True: time.sleep(1)
  Path(os.environ['BACKUP_TEST_STARTED']).write_text(str(os.getpid()))
  while True: time.sleep(1)
 out=Path(sys.argv[sys.argv.index('--file')+1])
 out.write_bytes(b'PGDMP\x00fixture-sensitive-row')
 if mode=='dump_fail':
  print('private-password private-passphrase',file=sys.stderr);sys.exit(4)
elif kind=='pg_restore':
 if mode=='invalid_archive':sys.exit(3)
 if not Path(sys.argv[-1]).read_bytes().startswith(b'PGDMP'):sys.exit(5)
else:
 secret=sys.stdin.buffer.read()
 if secret!=b'private-passphrase\n':sys.exit(6)
 source=Path(sys.argv[-1]);out=Path(sys.argv[sys.argv.index('--output')+1])
 if '--symmetric' in sys.argv:
  out.write_bytes(b'ENCRYPTED:'+base64.b64encode(source.read_bytes()))
  if mode=='encrypt_fail':sys.exit(7)
 else:
  if mode=='decrypt_fail':sys.exit(8)
  data=base64.b64decode(source.read_bytes().split(b':',1)[1])
  out.write_bytes(b'tampered' if mode=='mismatch' else data)
'''


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='av-backup-unit-')
        self.work = Path(self.temporary.name)
        self.tools = self.work / 'tools'
        self.tools.mkdir()
        for tool in ['pg_dump', 'pg_restore', 'gpg']:
            p = self.tools / tool
            p.write_text(TOOLS)
            p.chmod(0o700)
        self.output = self.work / 'out'
        self.env = dict(os.environ, BACKUP_DATABASE_URL='postgresql://fixture:private-password@localhost/fixture',
                        BACKUP_PASSPHRASE='private-passphrase', BACKUP_TEST_LOG=str(self.work / 'tools.jsonl'),
                        BACKUP_TEST_STARTED=str(self.work / 'started'), BACKUP_TEST_CHILD=str(self.work / 'child'))
        self.command = [sys.executable, str(SCRIPT), '--output-dir', str(self.output),
                        '--pg-dump', str(self.tools / 'pg_dump'), '--pg-restore', str(self.tools / 'pg_restore'),
                        '--gpg', str(self.tools / 'gpg'), '--timeout-seconds', '15']

    def tearDown(self):
        self.temporary.cleanup()

    def run_backup(self, mode='ok', **environment):
        return subprocess.run(self.command, env=self.env | {'BACKUP_TEST_MODE': mode} | environment,
                              capture_output=True, text=True, timeout=25)

    def assert_clean_failure(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('private-password', result.stdout + result.stderr)
        self.assertNotIn('private-passphrase', result.stdout + result.stderr)
        self.assertEqual(list(self.output.iterdir()) if self.output.exists() else [], [])

    def test_success_publishes_only_owner_readable_ciphertext(self):
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        files = list(self.output.iterdir())
        self.assertEqual(len(files), 1)
        self.assertEqual(str(files[0]), report['file'])
        self.assertTrue(files[0].name.endswith('.dump.gpg'))
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(report['decryption_verified'] and report['archive_validated'])
        self.assertNotIn(b'fixture-sensitive-row', files[0].read_bytes())

    def test_secrets_never_enter_arguments_and_gpg_cannot_inherit_database_uri(self):
        result = self.run_backup()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.work / 'tools.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls), 4)
        for call in calls:
            self.assertFalse(call['secret_env'])
            self.assertNotIn('private-password', json.dumps(call['args']))
            self.assertNotIn('private-passphrase', json.dumps(call['args']))
            self.assertEqual(bool(call['database']), call['kind'] == 'pg_dump')
            self.assertEqual(call['password'], call['kind'] == 'pg_dump')

    def test_dump_failure_removes_partial_plaintext(self):
        self.assert_clean_failure(self.run_backup('dump_fail'))

    def test_invalid_archive_is_not_encrypted_or_published(self):
        self.assert_clean_failure(self.run_backup('invalid_archive'))

    def test_encryption_failure_removes_plaintext_and_partial_ciphertext(self):
        self.assert_clean_failure(self.run_backup('encrypt_fail'))

    def test_decryption_failure_publishes_nothing(self):
        self.assert_clean_failure(self.run_backup('decrypt_fail'))

    def test_roundtrip_mismatch_publishes_nothing(self):
        self.assert_clean_failure(self.run_backup('mismatch'))

    def test_missing_credentials_are_refused_before_tools_run(self):
        self.assert_clean_failure(self.run_backup(BACKUP_PASSPHRASE=''))
        self.assertFalse((self.work / 'tools.jsonl').exists())

    def test_connection_uri_options_preserve_encoded_and_literal_characters(self):
        service = self.work / 'service'
        password = BACKUP.connection_service(
            'postgresql://user:p%40ss@Example.COM:5433/my%20database?sslmode=require&password=a+b%20c', service)
        self.assertEqual(password, 'a+b c')
        self.assertEqual(service.read_text(), '[agentvisor_backup]\nhost=Example.COM\nport=5433\nuser=user\ndbname=my database\nsslmode=require\n')
        self.assertEqual(service.stat().st_mode & 0o777, 0o600)
        BACKUP.connection_service('postgresql://%2FUsers%2FFixture/database', service)
        self.assertIn('host=/Users/Fixture\n', service.read_text())

    def test_connection_options_cannot_inject_service_file_lines(self):
        for uri in ['postgresql://host/db?host=good%0Apassword=bad',
                    'postgresql://host/db?host=%20trimmed',
                    'postgresql://host/db?host=bad%XY']:
            self.assert_clean_failure(self.run_backup(BACKUP_DATABASE_URL=uri))
        self.assertFalse((self.work / 'tools.jsonl').exists())

    def test_multiline_passphrase_is_refused_without_silent_truncation(self):
        self.assert_clean_failure(self.run_backup(BACKUP_PASSPHRASE='private-passphrase\nsecond-line'))
        self.assertFalse((self.work / 'tools.jsonl').exists())

    def test_existing_insecure_directory_is_not_silently_chmodded(self):
        self.output.mkdir(mode=0o755)
        self.output.chmod(0o755)
        self.assert_clean_failure(self.run_backup())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o755)

    def test_symbolic_output_directory_is_refused(self):
        target = self.work / 'target'
        target.mkdir(mode=0o700)
        self.output.symlink_to(target)
        self.assert_clean_failure(self.run_backup())
        self.assertTrue(self.output.is_symlink())

    def test_multiple_backups_preserve_existing_artifacts(self):
        first = self.run_backup()
        self.assertEqual(first.returncode, 0, first.stderr)
        first_path = Path(json.loads(first.stdout)['file'])
        first_bytes = first_path.read_bytes()
        second = self.run_backup()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(first_path, Path(json.loads(second.stdout)['file']))
        self.assertEqual(first_path.read_bytes(), first_bytes)
        self.assertEqual(len(list(self.output.iterdir())), 2)

    def test_timeout_cleans_plaintext_and_descendants(self):
        # Leave time for the real interpreter and fork on a busy CI host.
        # The blocked command still must be terminated by the helper deadline.
        self.command[-1] = '5'
        result = self.run_backup('wait')
        self.assert_clean_failure(result)
        self.assert_child_stopped()

    def assert_child_stopped(self):
        child_file = self.work / 'child'
        self.assertTrue(child_file.exists())
        pid = child_file.read_text()
        for _ in range(40):
            result = subprocess.run(['ps', '-o', 'stat=', '-p', pid], capture_output=True, text=True)
            if result.returncode or not result.stdout.strip() or result.stdout.strip().startswith('Z'):
                return
            time.sleep(0.05)
        self.fail('The owned child is still running')

    def test_sigterm_cleans_private_files_and_owned_descendants(self):
        self.assert_signal_cleanup(repeated=False)

    def test_repeated_cancellation_does_not_interrupt_cleanup(self):
        self.assert_signal_cleanup(repeated=True)

    def assert_signal_cleanup(self, repeated):
        process = subprocess.Popen(self.command, env=self.env | {'BACKUP_TEST_MODE': 'wait'},
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not (self.work / 'child').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.work / 'child').exists())
            process.send_signal(signal.SIGTERM)
            if repeated:
                time.sleep(0.2)
                process.send_signal(signal.SIGTERM)
                process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=15)
            self.assert_clean_failure(subprocess.CompletedProcess(self.command, process.returncode, stdout, stderr))
            self.assert_child_stopped()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


if __name__ == '__main__':
    unittest.main()
