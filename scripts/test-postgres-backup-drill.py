#!/usr/bin/env python3
"""Exercise cancellation and Docker transport failures without a Docker daemon."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).with_name('postgres-backup-test.py')
FAKE_DOCKER = r'''#!/usr/bin/env python3
import json,os,signal,sys,time
from pathlib import Path
w=Path(os.environ['BACKUP_DRILL_FAKE_DIR'])
args=sys.argv[1:];mode=os.environ.get('BACKUP_DRILL_FAKE_MODE','ok')
with (w/'commands.jsonl').open('a') as f:f.write(json.dumps(args)+'\n')
def value(flag):return args[args.index(flag)+1]
def load(kind):return json.loads((w/kind).read_text())
if args[0]=='build':
 label=value('--label').split('=',1)[1]
 (w/'image').write_text(json.dumps({'tag':value('-t'),'label':label}))
 if mode=='build_fail':sys.exit(3)
elif args[0]=='create':
 label=value('--label').split('=',1)[1]
 if mode=='foreign_container':label='another-owner'
 (w/'container').write_text(json.dumps({'name':value('--name'),'label':label,'id':'fake-container-id'}))
 if mode in ['create_uncertain','foreign_container']:sys.exit(4)
elif args[0]=='start':pass
elif args[0]=='exec':
 if 'pg_isready' in args:sys.exit(0)
 if mode=='wait':
  child=os.fork()
  if child==0:
   signal.signal(signal.SIGTERM,signal.SIG_IGN)
   (w/'child').write_text(str(os.getpid()))
   while True:time.sleep(1)
  (w/'started').write_text(str(os.getpid()))
  while True:time.sleep(1)
 if mode in ['inside_fail','inside_and_cleanup_fail']:
  print('original fixture failure',file=sys.stderr);sys.exit(5)
 print(json.dumps({'passed':True,'checks':['synthetic restore']}))
elif args[:2]==['container','ls']:
 if mode in ['query_fail','inside_and_cleanup_fail']:sys.exit(6)
 if (w/'container').exists():
  c=load('container')
  if value('--filter')!='name=^/'+c['name']+'$':sys.exit(7)
  print(c['id'])
elif args[0]=='inspect':
 c=load('container')
 if args[-1]!=c['id']:sys.exit(8)
 print(c['label'])
elif args[0]=='rm':
 c=load('container')
 if args[-1]!=c['id'] or '-v' not in args:sys.exit(9)
 (w/'container').unlink()
elif args[:2]==['image','ls']:
 if (w/'image').exists():
  i=load('image')
  if value('--filter')!='reference='+i['tag']:sys.exit(10)
  print('fake-image-id')
elif args[:2]==['image','inspect']:
 i=load('image')
 if args[-1]!=i['tag']:sys.exit(11)
 print('another-owner' if mode=='foreign_image' else i['label'])
elif args[:2]==['image','rm']:
 i=load('image')
 if args[-1]!=i['tag']:sys.exit(12)
 (w/'image').unlink()
else:sys.exit(20)
'''


class DrillTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='av-backup-drill-unit-')
        self.work = Path(self.temporary.name)
        tools = self.work / 'bin'
        tools.mkdir()
        docker = tools / 'docker'
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o700)
        self.output = self.work / 'output'
        self.environment = dict(os.environ, PATH=str(tools)+os.pathsep+os.environ['PATH'],
                                BACKUP_DRILL_FAKE_DIR=str(self.work))
        self.command = [sys.executable, str(SCRIPT), '--output-dir', str(self.output)]

    def tearDown(self):
        # A broken cancellation implementation must not leak the test child.
        for marker in ('child', 'started'):
            if (self.work / marker).exists():
                try:
                    os.kill(int((self.work / marker).read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.temporary.cleanup()

    def run_drill(self, mode):
        return subprocess.run(self.command, env=self.environment | {'BACKUP_DRILL_FAKE_MODE': mode},
                              capture_output=True, text=True, timeout=20)

    def assert_clean(self):
        self.assertFalse((self.work / 'container').exists())
        self.assertFalse((self.work / 'image').exists())
        report = json.loads((self.output / 'cleanup.json').read_text())
        self.assertEqual(report['errors'], [])
        self.assertTrue(report['container_removed_or_absent'])
        self.assertTrue(report['image_removed_or_absent'])

    def test_success_cleans_exact_container_and_image(self):
        result = self.run_drill('ok')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_clean()

    def test_failed_create_response_still_cleans_accepted_container(self):
        result = self.run_drill('create_uncertain')
        self.assertNotEqual(result.returncode, 0)
        self.assert_clean()

    def test_failed_build_response_still_cleans_published_image(self):
        result = self.run_drill('build_fail')
        self.assertNotEqual(result.returncode, 0)
        self.assert_clean()

    def test_failed_inside_command_still_cleans(self):
        self.assertNotEqual(self.run_drill('inside_fail').returncode, 0)
        self.assert_clean()

    def test_different_container_owner_is_never_removed(self):
        result = self.run_drill('foreign_container')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.work / 'container').exists())
        self.assertFalse((self.work / 'image').exists())
        self.assertIn('without the expected ownership label',
                      (self.output / 'cleanup.json').read_text())

    def test_different_image_owner_is_never_removed(self):
        result = self.run_drill('foreign_image')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.work / 'container').exists())
        self.assertTrue((self.work / 'image').exists())
        self.assertIn('without the expected ownership label', result.stderr)

    def test_failed_daemon_query_does_not_report_cleanup_success(self):
        result = self.run_drill('query_fail')
        self.assertNotEqual(result.returncode, 0)
        report = json.loads((self.output / 'cleanup.json').read_text())
        self.assertTrue(report['errors'])
        self.assertNotIn('container_removed_or_absent', report)
        self.assertTrue((self.work / 'container').exists())
        self.assertFalse((self.work / 'image').exists())

    def test_cleanup_failure_preserves_original_error_and_diagnostics(self):
        result = self.run_drill('inside_and_cleanup_fail')
        self.assertNotEqual(result.returncode, 0)
        failure = json.loads((self.output / 'failure.json').read_text())
        self.assertEqual(failure['phase'], 'backup and restore')
        self.assertEqual(failure['returncode'], 5)
        self.assertIn('original fixture failure', (self.output / 'failure.log').read_text())
        self.assertIn('original fixture failure', result.stderr)
        self.assertIn('Cleanup also failed', result.stderr)
        self.assertTrue(json.loads((self.output / 'cleanup.json').read_text())['errors'])

    def test_repeated_sigterm_cleans_descendants_and_docker_resources(self):
        process = subprocess.Popen(self.command,
            env=self.environment | {'BACKUP_DRILL_FAKE_MODE': 'wait'},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 8
            while not (self.work / 'child').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.work / 'child').exists())
            process.send_signal(signal.SIGTERM)
            time.sleep(1)
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assert_clean()
            child = (self.work / 'child').read_text()
            for _ in range(40):
                status = subprocess.run(['ps', '-o', 'stat=', '-p', child],
                                        capture_output=True, text=True, timeout=2)
                if status.returncode or not status.stdout.strip() or status.stdout.strip().startswith('Z'):
                    break
                time.sleep(0.05)
            else:
                self.fail('The synthetic Docker descendant is still running')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_command_timeout_terminates_owned_process_group(self):
        spec = importlib.util.spec_from_file_location('backup_drill', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with self.assertRaises(subprocess.TimeoutExpired):
            module.run([sys.executable, '-c', 'import time;time.sleep(60)'], timeout=0.2)


if __name__ == '__main__':
    unittest.main()
