#!/usr/bin/env python3
"""Verify local console artifacts and promote only their validated OCI bytes.

Build/test jobs have no publication credentials. This helper never rebuilds an
image. Archive filenames, platform set, destinations, and tags come from this
policy, never from downloaded artifact paths or an image's labels.
"""
import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCHES = ('amd64', 'arm64')
INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
DIGEST = re.compile(r'sha256:[0-9a-f]{64}\Z')
FILES = ('image.oci.tar', 'trivy-full.json', 'sbom.spdx.json',
         'runtime.json', 'runtime.log', 'entrypoint.log')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def file_sha(path):
    with path.open('rb') as source:
        return 'sha256:' + hashlib.file_digest(source, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def command(args, **kwargs):
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)
    return subprocess.run(args, check=True, timeout=600, **kwargs).stdout


def archive_info(path, arch):
    """Read, hash and validate an OCI graph without extracting archive entries."""
    require(arch in ARCHES, 'Unsupported architecture')
    with tarfile.open(path, 'r:') as archive:
        members = archive.getmembers()
        names = [x.name for x in members]
        require(len(names) == len(set(names)), 'Duplicate archive member')
        require(all(x.isdir() or x.isfile() for x in members), 'Archive links or special files are forbidden')
        require(all(not x.name.startswith('/') and '..' not in Path(x.name).parts for x in members),
                'Unsafe archive path')
        def read(name, limit=8 * 1024 * 1024):
            member = archive.getmember(name)
            require(member.isfile() and member.size <= limit, 'Invalid OCI metadata member')
            return archive.extractfile(member).read()
        def blob(descriptor, metadata=True):
            digest = descriptor.get('digest', '')
            require(DIGEST.fullmatch(digest), 'Invalid OCI digest')
            member = archive.getmember('blobs/sha256/' + digest[7:])
            require(member.isfile() and member.size == descriptor.get('size'), 'OCI blob size mismatch')
            if metadata:
                raw = read(member.name)
                require(sha(raw) == digest, 'OCI metadata digest mismatch')
                return json.loads(raw)
            with archive.extractfile(member) as stream:
                require('sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest() == digest,
                        'OCI layer digest mismatch')
        require(json.loads(read('oci-layout')) == {'imageLayoutVersion':'1.0.0'}, 'Invalid OCI layout')
        wrapper = json.loads(read('index.json'))
        require(wrapper.get('schemaVersion') == 2 and len(wrapper.get('manifests', [])) == 1,
                'Expected one exported OCI root')
        root = wrapper['manifests'][0]
        require(root.get('mediaType') == INDEX, 'OCI export must preserve its attestation index')
        index = blob(root)
        require(index.get('mediaType') == INDEX and index.get('schemaVersion') == 2, 'Invalid OCI root index')
        descriptors = index.get('manifests', [])
        runtime = [x for x in descriptors if x.get('platform', {}).get('os') == 'linux']
        attestations = [x for x in descriptors if x.get('platform') == {'architecture':'unknown', 'os':'unknown'}]
        require(len(runtime) == 1 and len(attestations) >= 1 and len(descriptors) == 1 + len(attestations),
                'Unexpected runtime or attestation descriptors')
        image = runtime[0]
        require(image['platform'].get('architecture') == arch, 'OCI architecture mismatch')
        require(image.get('mediaType') == MANIFEST, 'Expected OCI image manifest')
        manifest = blob(image)
        config = blob(manifest['config'])
        require(config.get('architecture') == arch and config.get('os') == 'linux', 'Config platform mismatch')
        for layer in manifest['layers']:
            blob(layer, metadata=False)
        predicates = set()
        for attestation in attestations:
            annotation = attestation.get('annotations', {})
            require(attestation.get('mediaType') == MANIFEST and
                    annotation.get('vnd.docker.reference.type') == 'attestation-manifest' and
                    annotation.get('vnd.docker.reference.digest') == image['digest'], 'Unbound attestation descriptor')
            am = blob(attestation)
            blob(am['config'])
            for layer in am['layers']:
                statement = blob(layer)
                require(any(x.get('digest', {}).get('sha256') == image['digest'][7:]
                            for x in statement.get('subject', [])), 'Unbound attestation statement')
                predicates.add(statement.get('predicateType'))
        require('https://spdx.dev/Document' in predicates and
                any(isinstance(x, str) and x.startswith('https://slsa.dev/provenance/') for x in predicates),
                'BuildKit SPDX or provenance attestation missing')
        return {'root_digest':root['digest'], 'config_digest':manifest['config']['digest'],
                'descriptors':descriptors, 'config':config, 'architecture':arch}


def scan_policy(report, runtime):
    require(report.get('SchemaVersion') == 2 and report.get('ArtifactType') == 'container_image',
            'Missing or unsupported full container scan')
    metadata = report.get('Metadata', {})
    require(metadata.get('ImageID') == runtime['image_id'], 'Scan is for a different tested image')
    require(metadata.get('ImageConfig', {}).get('architecture') == runtime['architecture'],
            'Scan architecture mismatch')
    results = report.get('Results')
    require(isinstance(results, list) and any(x.get('Class') == 'os-pkgs' for x in results),
            'Scan has no OS inventory')
    for result in results:
        require(not result.get('MisconfSummary', {}).get('Failures'), 'Unexpected scan failure')
        for item in result.get('Vulnerabilities') or []:
            require(item.get('Severity') in ('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'), 'Malformed vulnerability severity')
            if item['Severity'] in ('HIGH','CRITICAL') and item.get('FixedVersion'):
                raise ValueError('Fixable HIGH/CRITICAL vulnerability: ' + item.get('VulnerabilityID', 'unknown'))


def test_runtime(directory, arch, run=command):
    (directory/'runtime.json').unlink(missing_ok=True)
    info = archive_info(directory / 'image.oci.tar', arch)
    tag = 'agentvisor-api:release-test-' + arch
    # The Docker daemon needs only the runnable platform. The original archive,
    # including attestations, is kept unchanged for registry promotion.
    run(['skopeo','--override-os','linux','--override-arch',arch,'copy',
         'oci-archive:' + str(directory / 'image.oci.tar'), 'docker-daemon:' + tag])
    loaded = json.loads(run(['docker','image','inspect',tag]))[0]
    config = info['config']
    require(loaded['Architecture'] == arch and loaded['Os'] == 'linux', 'Loaded image platform mismatch')
    require(loaded['RootFS']['Layers'] == config['rootfs']['diff_ids'], 'Loaded image filesystem mismatch')
    require(all(loaded['Config'].get(k) == v for k,v in config['config'].items()), 'Loaded image configuration mismatch')
    for name, args in [('runtime.log', ['python3',str(ROOT/'scripts/container-smoke.py'),'--console-image',tag]),
                       ('entrypoint.log', ['docker','run','--rm','--network','none','--read-only',
                        '--tmpfs','/tmp:uid=65532,gid=65532,mode=0700','--cap-drop','ALL',
                        '--security-opt','no-new-privileges','--mount',
                        'type=bind,src='+str(ROOT/'server/ci')+',dst=/app/ci,readonly',
                        tag,'--test','/app/ci/container-entrypoint.test.mjs'])]:
        try:
            output = run(args, stderr=subprocess.STDOUT)
            (directory/name).write_bytes(output)
        except subprocess.CalledProcessError as error:
            (directory/name).write_bytes(error.output or b'')
            raise
    write(directory/'runtime.json', {'status':'passed','architecture':arch,
          'image_id':loaded['Id'],'config_digest':info['config_digest']})


def validate_files(directory, arch):
    require(directory.is_dir() and not directory.is_symlink(), 'Invalid artifact directory')
    for name in FILES:
        require((directory/name).is_file() and not (directory/name).is_symlink(), 'Missing or linked artifact: '+name)
    info = archive_info(directory/'image.oci.tar', arch)
    runtime = json.loads((directory/'runtime.json').read_text())
    require(runtime.get('status') == 'passed' and runtime.get('architecture') == arch and
            runtime.get('config_digest') == info['config_digest'], 'Runtime validation missing or mismatched')
    scan_policy(json.loads((directory/'trivy-full.json').read_text()), runtime)
    sbom = json.loads((directory/'sbom.spdx.json').read_text())
    require(str(sbom.get('spdxVersion','')).startswith('SPDX-2.') and sbom.get('packages'), 'SPDX inventory missing')
    return info, {name:file_sha(directory/name) for name in FILES}


def identity(env):
    revision, run_id, attempt = (env.get(x, '') for x in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'))
    require(re.fullmatch('[0-9a-f]{40}', revision) and run_id.isdigit() and attempt.isdigit(), 'Invalid workflow identity')
    return {'revision':revision,'run_id':run_id,'run_attempt':attempt}


def seal(directory, arch, env):
    (directory/'validation.json').unlink(missing_ok=True)
    info, hashes = validate_files(directory, arch)
    record = dict(identity(env), architecture=arch, files=hashes, root_digest=info['root_digest'])
    write(directory/'validation.json', record)


def authorize(env):
    require(env.get('GITHUB_EVENT_NAME') in ('push','workflow_dispatch') and
            env.get('GITHUB_REF') == 'refs/heads/main', 'Publication is restricted to main push/manual runs')
    return identity(env)


def verify(directory, env):
    expected = authorize(env)
    values = []
    for arch in ARCHES:
        folder = directory/('console-release-' + arch)
        require(folder.is_dir() and not folder.is_symlink() and
                (folder/'validation.json').is_file() and not (folder/'validation.json').is_symlink(),
                'Missing or linked validation record')
        record = json.loads((folder/'validation.json').read_text())
        require(all(record.get(k) == v for k,v in expected.items()), 'Artifact belongs to a different revision or run')
        require(record.get('architecture') == arch, 'Artifact architecture mismatch')
        info, hashes = validate_files(folder, arch)
        require(record.get('files') == hashes and record.get('root_digest') == info['root_digest'], 'Artifact checksum mismatch')
        values.append((folder, info))
    return values


def repository(env):
    owner = env.get('GITHUB_REPOSITORY_OWNER', '').lower()
    require(re.fullmatch('[a-z0-9][a-z0-9-]*', owner), 'Invalid registry owner')
    return 'ghcr.io/' + owner + '/agentvisor-api'


def check_index(raw, values):
    index = json.loads(raw)
    require(index.get('schemaVersion') == 2 and index.get('mediaType') == INDEX, 'Invalid promoted OCI index')
    normalize = lambda x: json.dumps(x, sort_keys=True, separators=(',',':'))
    expected = collections.Counter(normalize(x) for _,i in values for x in i['descriptors'])
    actual = collections.Counter(normalize(x) for x in index.get('manifests', []))
    require(actual == expected, 'Registry index dropped, replaced or added a runtime/attestation descriptor')
    return sha(raw)


def stage(directory, env, run=command):
    (directory/'staged.json').unlink(missing_ok=True)
    values = verify(directory, env)  # Every platform is checked before any write.
    image = repository(env); ident = identity(env)
    suffix = ident['run_id'] + '-' + ident['run_attempt']
    sources = []
    for folder, info in values:
        digestfile = directory/('copied-' + info['architecture'] + '.digest')
        run(['skopeo','copy','--all','--preserve-digests','--digestfile',str(digestfile),
             'oci-archive:'+str(folder/'image.oci.tar'),
             'docker://'+image+':validated-'+suffix+'-'+info['architecture']])
        require(digestfile.read_text().strip() == info['root_digest'], 'Registry copy changed the validated digest')
        sources.append(image+'@'+info['root_digest'])
    candidate = image+':validated-'+suffix
    # Check the complete platform/attestation set before creating the index.
    check_index(run(['docker','buildx','imagetools','create','--dry-run',*sources]), values)
    run(['docker','buildx','imagetools','create','--tag',candidate,*sources])
    raw = run(['skopeo','inspect','--raw','docker://'+candidate])
    digest = check_index(raw, values)
    # An immutable lookup must return those exact bytes before attestation/tagging.
    require(run(['skopeo','inspect','--raw','docker://'+image+'@'+digest]) == raw, 'Registry digest lookup mismatch')
    record = dict(ident, image=image, digest=digest,
                  platforms={info['architecture']:info['root_digest'] for _,info in values})
    write(directory/'staged.json', record)
    return record


def promote(directory, env, run=command):
    values = verify(directory, env)
    record = json.loads((directory/'staged.json').read_text())
    expected = identity(env); image=repository(env)
    require(all(record.get(k)==v for k,v in expected.items()) and record.get('image')==image and
            DIGEST.fullmatch(record.get('digest','')), 'Invalid staged release')
    digest=record['digest']
    raw=run(['skopeo','inspect','--raw','docker://'+image+'@'+digest])
    require(check_index(raw,values)==digest, 'Staged registry index changed')
    # Registry tag updates are separate operations, not a transaction. Every
    # target nevertheless receives only the already checked immutable index.
    for tag in ('sha-'+expected['revision'],'main','latest'):
        digestfile=directory/('promoted-'+tag+'.digest')
        run(['skopeo','copy','--all','--preserve-digests','--digestfile',str(digestfile),
             'docker://'+image+'@'+digest,'docker://'+image+':'+tag])
        require(digestfile.read_text().strip()==digest and
                run(['skopeo','inspect','--raw','docker://'+image+':'+tag])==raw, 'Promoted tag digest mismatch')
    return image+'@'+digest


def outputs(values):
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'],'a') as target:
            for key,value in values.items():
                require('\n' not in value and '\r' not in value, 'Unsafe output')
                target.write(key+'='+value+'\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('runtime','seal','verify','stage','promote'))
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--arch',choices=ARCHES)
    args=parser.parse_args()
    if args.operation in ('runtime','seal'):
        require(args.arch is not None,'Architecture is required')
        (test_runtime if args.operation=='runtime' else seal)(args.directory,args.arch,**({'env':os.environ} if args.operation=='seal' else {}))
    elif args.operation=='verify': verify(args.directory,os.environ)
    elif args.operation=='stage':
        value=stage(args.directory,os.environ)
        outputs({'image':value['image'],'digest':value['digest'],**{a+'_digest':d for a,d in value['platforms'].items()}})
    else: outputs({'image_ref':promote(args.directory,os.environ)})


if __name__=='__main__':
    main()
