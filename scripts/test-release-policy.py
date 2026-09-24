#!/usr/bin/env python3
"""Release-boundary failure tests: fake OCI artifacts/registry, no publication."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('release_policy',HERE/'release-policy.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
ENV={'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'1234','GITHUB_RUN_ATTEMPT':'2',
     'GITHUB_EVENT_NAME':'push','GITHUB_REF':'refs/heads/main','GITHUB_REPOSITORY_OWNER':'Example'}


def fixture(parent,arch,*,missing_predicate=False,bad_layer=False,unbound=False):
    directory=parent/('console-release-'+arch);directory.mkdir()
    blobs={}
    def add(value,media):
        raw=value if isinstance(value,bytes) else json.dumps(value,separators=(',',':')).encode()
        digest=policy.sha(raw);blobs['blobs/sha256/'+digest[7:]]=raw
        return {'mediaType':media,'size':len(raw),'digest':digest}
    config={'architecture':arch,'os':'linux','rootfs':{'type':'layers','diff_ids':[policy.sha(b'filesystem')]},
            'config':{'User':'65532:65532','Entrypoint':['/nodejs/bin/node'],'Cmd':['container-entrypoint.mjs']}}
    config_d=add(config,'application/vnd.oci.image.config.v1+json')
    layer=add(b'filesystem','application/vnd.oci.image.layer.v1.tar')
    image=add({'schemaVersion':2,'mediaType':policy.MANIFEST,'config':config_d,'layers':[layer]},policy.MANIFEST)
    image['platform']={'os':'linux','architecture':arch}
    statements=[]
    for predicate in (['https://slsa.dev/provenance/v0.2'] if missing_predicate else
                      ['https://slsa.dev/provenance/v0.2','https://spdx.dev/Document']):
        statements.append(add({'_type':'https://in-toto.io/Statement/v0.1','subject':[] if unbound else [{'name':'image',
            'digest':{'sha256':image['digest'][7:]}}],'predicateType':predicate,'predicate':{}},'application/vnd.in-toto+json'))
    att=add({'schemaVersion':2,'mediaType':policy.MANIFEST,'config':add({},'application/vnd.oci.image.config.v1+json'),
             'layers':statements},policy.MANIFEST)
    att.update(platform={'architecture':'unknown','os':'unknown'},annotations={
        'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':image['digest']})
    root=add({'schemaVersion':2,'mediaType':policy.INDEX,'manifests':[image,att]},policy.INDEX)
    blobs['index.json']=json.dumps({'schemaVersion':2,'manifests':[root]}).encode()
    blobs['oci-layout']=b'{"imageLayoutVersion":"1.0.0"}'
    if bad_layer:blobs['blobs/sha256/'+layer['digest'][7:]]=b'corrupted!'
    with tarfile.open(directory/'image.oci.tar','w') as archive:
        for name,raw in blobs.items():
            item=tarfile.TarInfo(name);item.size=len(raw);archive.addfile(item,io.BytesIO(raw))
    runtime={'status':'passed','architecture':arch,'image_id':config_d['digest'],'config_digest':config_d['digest']}
    report={'SchemaVersion':2,'ArtifactType':'container_image','Metadata':{'ImageID':config_d['digest'],
        'ImageConfig':{'architecture':arch}},'Results':[{'Class':'os-pkgs','Type':'debian','Vulnerabilities':[]}]}
    policy.write(directory/'runtime.json',runtime);policy.write(directory/'trivy-full.json',report)
    policy.write(directory/'sbom.spdx.json',{'spdxVersion':'SPDX-2.3','packages':[{'name':'node'}]})
    (directory/'runtime.log').write_text('All runtime checks passed\n')
    (directory/'entrypoint.log').write_text('All entrypoint checks passed\n')
    return directory


class Registry:
    def __init__(self,values):
        self.values=values;self.calls=[];self.raw=json.dumps({'schemaVersion':2,'mediaType':policy.INDEX,
            'manifests':[d for _,i in values for d in i['descriptors']]},separators=(',',':')).encode()
        self.tags={};self.corrupt_copy=False;self.corrupt_index=False
    def __call__(self,args,**_):
        self.calls.append(args)
        if args[:2]==['skopeo','copy']:
            assert '--all' in args and '--preserve-digests' in args
            src,dest=args[-2:];tag=dest.removeprefix('docker://')
            if src.startswith('oci-archive:'):
                folder=Path(src.removeprefix('oci-archive:')).parent
                digest=next(i['root_digest'] for f,i in self.values if f==folder)
            else:
                digest=src.rsplit('@',1)[1];self.tags[tag]=self.raw
            if self.corrupt_copy:digest='sha256:'+'f'*64
            Path(args[args.index('--digestfile')+1]).write_text(digest)
            return b''
        if args[:4]==['docker','buildx','imagetools','create']:
            if '--dry-run' in args:
                return self.raw
            self.tags[args[args.index('--tag')+1]]=self.raw;return b''
        if args[:3]==['skopeo','inspect','--raw']:
            reference=args[-1].removeprefix('docker://')
            if self.corrupt_index:
                value=json.loads(self.raw);value['manifests']=value['manifests'][:-1];return json.dumps(value).encode()
            return self.tags.get(reference,self.raw)
        raise AssertionError(args)
    def deployable(self):
        return [x for x in self.tags if x.endswith((':main',':latest')) or ':sha-' in x]


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for arch in policy.ARCHES:policy.seal(fixture(self.root,arch),arch,ENV)
        self.registry=Registry(policy.verify(self.root,ENV))
    def change_report(self,arch,update):
        p=self.root/('console-release-'+arch)/'trivy-full.json';d=json.loads(p.read_text());update(d);policy.write(p,d)
    def reject_without_write(self,env=ENV):
        with self.assertRaises((ValueError,FileNotFoundError,KeyError)):
            policy.stage(self.root,env,self.registry)
        self.assertEqual(self.registry.calls,[])
    def test_success_preserves_all_architectures_and_attestations(self):
        result=policy.stage(self.root,ENV,self.registry)
        self.assertEqual(self.registry.deployable(),[])
        self.assertEqual(len(json.loads(self.registry.raw)['manifests']),4)
        image=policy.promote(self.root,ENV,self.registry)
        self.assertEqual(image,'ghcr.io/example/agentvisor-api@'+result['digest'])
        self.assertEqual(len(self.registry.deployable()),3)
        self.assertTrue(all(v==self.registry.raw for v in self.registry.tags.values()))
    def test_pr_even_with_both_artifacts_cannot_write(self):
        self.reject_without_write(dict(ENV,GITHUB_EVENT_NAME='pull_request'))
    def test_manual_nonmain_cannot_write(self):
        self.reject_without_write(dict(ENV,GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_REF='refs/heads/topic'))
    def test_incomplete_architecture_cannot_write(self):
        shutil.rmtree(self.root/'console-release-arm64');self.reject_without_write()
    def test_wrong_workflow_attempt_cannot_write(self):
        self.reject_without_write(dict(ENV,GITHUB_RUN_ATTEMPT='3'))
    def test_artifact_replacement_cannot_write(self):
        (self.root/'console-release-arm64/runtime.log').write_text('replaced');self.reject_without_write()
    def test_scan_failure_missing_report_cannot_write(self):
        (self.root/'console-release-arm64/trivy-full.json').unlink();self.reject_without_write()
    def test_fixable_high_cannot_be_sealed_or_staged(self):
        self.change_report('arm64',lambda d:d['Results'][0]['Vulnerabilities'].append(
            {'Severity':'HIGH','FixedVersion':'2.0','VulnerabilityID':'CVE-test'}))
        with self.assertRaises(ValueError):policy.seal(self.root/'console-release-arm64','arm64',ENV)
        self.assertFalse((self.root/'console-release-arm64/validation.json').exists())
        self.reject_without_write()
    def test_unfixed_findings_remain_in_full_report(self):
        self.change_report('arm64',lambda d:d['Results'][0]['Vulnerabilities'].append(
            {'Severity':'CRITICAL','VulnerabilityID':'CVE-unfixed'}))
        policy.seal(self.root/'console-release-arm64','arm64',ENV)
        policy.verify(self.root,ENV)
        self.assertIn('CVE-unfixed',(self.root/'console-release-arm64/trivy-full.json').read_text())
    def test_scan_for_wrong_image_cannot_write(self):
        self.change_report('arm64',lambda d:d['Metadata'].update(ImageID='sha256:'+'0'*64));self.reject_without_write()
    def test_scan_for_wrong_architecture_cannot_write(self):
        self.change_report('arm64',lambda d:d['Metadata']['ImageConfig'].update(architecture='amd64'));self.reject_without_write()
    def test_empty_scan_cannot_write(self):
        self.change_report('arm64',lambda d:d.update(Results=[]));self.reject_without_write()
    def test_runtime_failure_cannot_write(self):
        p=self.root/'console-release-amd64/runtime.json';d=json.loads(p.read_text());d['status']='failed';policy.write(p,d)
        self.reject_without_write()
    def test_unsafe_artifact_symlink_cannot_write(self):
        p=self.root/'console-release-amd64/runtime.log';p.unlink();p.symlink_to('/etc/hosts');self.reject_without_write()
    def test_linked_validation_record_cannot_write(self):
        p=self.root/'console-release-amd64/validation.json';target=self.root/'record.json';p.rename(target);p.symlink_to(target)
        self.reject_without_write()
    def test_invalid_destination_owner_cannot_choose_tags(self):
        with self.assertRaises(ValueError):policy.stage(self.root,dict(ENV,GITHUB_REPOSITORY_OWNER='evil/name:latest'),self.registry)
        self.assertFalse(self.registry.calls)
    def test_changed_copy_digest_never_updates_deployable_tags(self):
        self.registry.corrupt_copy=True
        with self.assertRaises(ValueError):policy.stage(self.root,ENV,self.registry)
        self.assertEqual(self.registry.deployable(),[])
        self.assertFalse((self.root/'staged.json').exists())
    def test_missing_attestation_in_registry_never_promotes(self):
        self.registry.corrupt_index=True
        with self.assertRaises(ValueError):policy.stage(self.root,ENV,self.registry)
        self.assertEqual(self.registry.deployable(),[])
    def test_changed_index_after_attestation_never_promotes(self):
        policy.stage(self.root,ENV,self.registry);self.registry.corrupt_index=True
        with self.assertRaises(ValueError):policy.promote(self.root,ENV,self.registry)
        self.assertEqual(self.registry.deployable(),[])
    def test_unstaged_image_cannot_promote(self):
        with self.assertRaises(FileNotFoundError):policy.promote(self.root,ENV,self.registry)
        self.assertEqual(self.registry.calls,[])
    def test_embedded_sbom_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=fixture(Path(tmp),'amd64',missing_predicate=True)
            with self.assertRaises(ValueError):policy.archive_info(p/'image.oci.tar','amd64')
    def test_layer_content_digest_is_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=fixture(Path(tmp),'amd64',bad_layer=True)
            with self.assertRaises(ValueError):policy.archive_info(p/'image.oci.tar','amd64')
    def test_runtime_architecture_mismatch_stops_before_execution(self):
        values=self.registry.values;folder,info=values[0];calls=[]
        def runner(args,**kwargs):
            calls.append(args)
            if args[:3]==['docker','image','inspect']:
                return json.dumps([{'Architecture':'arm64','Os':'linux'}]).encode()
            return b''
        with self.assertRaises(ValueError):policy.test_runtime(folder,'amd64',runner)
        self.assertEqual(len(calls),2)
        self.assertFalse((folder/'runtime.json').exists())
    def test_import_configuration_or_filesystem_change_stops_before_execution(self):
        folder,info=self.registry.values[0]
        for changed in ('configuration','filesystem'):
            with self.subTest(changed=changed):
                calls=[]
                loaded={'Architecture':'amd64','Os':'linux','Config':copy.deepcopy(info['config']['config']),
                        'RootFS':{'Layers':copy.deepcopy(info['config']['rootfs']['diff_ids'])}}
                if changed=='configuration':loaded['Config']['User']='0'
                else:loaded['RootFS']['Layers']=[policy.sha(b'other filesystem')]
                def runner(args,**kwargs):
                    calls.append(args)
                    return json.dumps([loaded]).encode() if args[:3]==['docker','image','inspect'] else b''
                with self.assertRaises(ValueError):policy.test_runtime(folder,'amd64',runner)
                self.assertEqual(len(calls),2)
                self.assertFalse((folder/'runtime.json').exists())
    def test_imported_docker_identifier_may_differ_from_oci_config(self):
        folder=self.root/'console-release-amd64'
        runtime=json.loads((folder/'runtime.json').read_text())
        runtime['image_id']=policy.sha(b'Docker imported manifest')
        policy.write(folder/'runtime.json',runtime)
        self.change_report('amd64',lambda report:report['Metadata'].update(ImageID=runtime['image_id']))
        policy.seal(folder,'amd64',ENV)
        self.assertEqual(len(policy.verify(self.root,ENV)),2)
    def test_unnamed_buildkit_attestation_cannot_be_sealed(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=fixture(Path(tmp),'arm64',unbound=True)
            with self.assertRaisesRegex(ValueError,'Unbound attestation statement'):
                policy.seal(folder,'arm64',ENV)
            self.assertFalse((folder/'validation.json').exists())
    def test_workflow_permission_and_deployment_contract(self):
        path=HERE.parent/'.github/workflows/deploy.yml'
        workflow=json.loads(subprocess.check_output(['ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.load_file(ARGV[0]))',str(path)],text=True))
        self.assertEqual(workflow['permissions'],{'contents':'read'})
        jobs=workflow['jobs'];validate=jobs['validate'];promote=jobs['promote'];deploy=jobs['deploy-fly']
        self.assertEqual(validate['permissions'],{'contents':'read'})
        build=next(x for x in validate['steps'] if x.get('uses','').startswith('docker/build-push-action@'))
        self.assertIs(build['with']['push'],False)
        self.assertIn('agentvisor-api:build-',build['with']['tags'])
        self.assertIn('type=oci',build['with']['outputs'])
        text=json.dumps(validate)
        self.assertNotIn('login-action',text);self.assertNotIn('secrets.',text);self.assertNotIn('id-token',text)
        self.assertEqual(set(promote['needs']),{'validate','console-checks'});
        self.assertEqual(jobs['console-checks']['uses'],'./.github/workflows/console-api.yml')
        self.assertEqual(jobs['console-checks']['permissions'],{'contents':'read'})
        self.assertNotIn('secrets',jobs['console-checks'])
        reusable=json.loads(subprocess.check_output(['ruby','-ryaml','-rjson','-e',
            'puts JSON.generate(YAML.load_file(ARGV[0]))',str(HERE.parent/'.github/workflows/console-api.yml')],text=True))
        self.assertIn('workflow_call',reusable.get('on',reusable.get('true',{})))
        self.assertIn('github.workflow',reusable['concurrency']['group'])
        self.assertIn("github.ref == 'refs/heads/main'",promote['if'])
        self.assertIn("github.event_name == 'push' || github.event_name == 'workflow_dispatch'",promote['if'])
        self.assertIn('!github.event.repository.fork',promote['if'])
        steps=promote['steps'];index=lambda name:next(i for i,x in enumerate(steps) if x.get('name')==name)
        self.assertLess(index('Verify both archives before registry login'),index('Login for promotion only'))
        self.assertLess(index('Attest the arm64 SPDX inventory'),index('Promote deployable tags without rebuilding'))
        self.assertEqual(deploy['needs'],'promote');self.assertIn("github.event_name == 'push'",deploy['if'])
        fly=next(x for x in deploy['steps'] if x.get('name')=='Fly deploy the exact promoted digest')
        self.assertEqual(fly['env']['IMAGE_REF'],'${{ needs.promote.outputs.image_ref }}')
        self.assertIn('--image "$IMAGE_REF"',fly['run'])


if __name__=='__main__':unittest.main(verbosity=2)
