"""Prebuilt test runner image manifest computation, verification, and execution."""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import tomllib
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

IMAGE_NAME = 'ghcr.io/candlelightner/dirigentenstab'


def find_root(path: Path | None = None) -> Path:
    if path:
        return path.resolve()
    cwd = Path.cwd().resolve()
    if (cwd / 'pyproject.toml').exists():
        return cwd
    script_parent = Path(__file__).resolve().parent
    if (script_parent / 'pyproject.toml').exists():
        return script_parent
    if (script_parent.parent / 'pyproject.toml').exists():
        return script_parent.parent
    if Path('/opt/test-runner/pyproject.toml').exists():
        return Path('/opt/test-runner')
    return cwd


def compute_manifest(root: Path) -> dict[str, str]:
    dockerfile_path = root / 'Dockerfile.test-runner'
    dockerfile_text = dockerfile_path.read_text(encoding='utf-8')
    dockerfile_sha256 = hashlib.sha256(dockerfile_text.replace('\r\n', '\n').encode('utf-8')).hexdigest()

    match = re.search(r'FROM\s+python:([0-9]+\.[0-9]+)-slim-bookworm@sha256:[a-f0-9]{64}', dockerfile_text)
    if not match:
        raise ValueError(f'Could not find python base image with sha256 in {dockerfile_path}')
    python_version = match.group(1)

    pyproject_text = (root / 'pyproject.toml').read_text(encoding='utf-8')
    pyproject_data = tomllib.loads(pyproject_text)
    requires_python = pyproject_data.get('project', {}).get('requires-python', '')
    if requires_python and not SpecifierSet(requires_python).contains(python_version):
        raise ValueError(f'Base image Python {python_version} violates requires-python {requires_python}')

    optional = pyproject_data.get('project', {}).get('optional-dependencies', {})
    browser_deps = optional.get('browser', [])
    pw_version = None
    for dep in browser_deps:
        if dep.startswith('playwright=='):
            pw_version = dep.partition('==')[2].strip()
            break
    if not pw_version:
        raise ValueError('Could not find playwright==<version> in optional-dependencies.browser')

    req_lines = [line.strip() for line in (root / 'requirements.lock').read_text(encoding='utf-8').splitlines()]
    normalized_reqs = '\n'.join(line for line in req_lines if line and not line.startswith('#')) + '\n'
    requirements_sha256 = hashlib.sha256(normalized_reqs.encode('utf-8')).hexdigest()

    project = pyproject_data.get('project', {})
    deps_dict = {
        'build-system': pyproject_data.get('build-system', {}),
        'dependencies': project.get('dependencies', []),
        'optional-dependencies': project.get('optional-dependencies', {}),
        'requires-python': project.get('requires-python', ''),
    }
    pyproject_deps_sha256 = hashlib.sha256(
        json.dumps(deps_dict, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()

    runner_script_sha256 = hashlib.sha256((root / 'scripts/test_runner.py').read_bytes()).hexdigest()
    canonical_inputs = {
        'dockerfile_sha256': dockerfile_sha256,
        'playwright_version': pw_version,
        'pyproject_deps_sha256': pyproject_deps_sha256,
        'python_version': python_version,
        'requirements_sha256': requirements_sha256,
        'runner_script_sha256': runner_script_sha256,
    }
    manifest_sha256 = hashlib.sha256(
        json.dumps(canonical_inputs, sort_keys=True, separators=(',', ':')).encode('utf-8')
    ).hexdigest()

    tag = f'test-runner-py{python_version}-pw{pw_version}-{manifest_sha256[:16]}'
    return {
        'cache_scope': tag,
        'dockerfile_sha256': dockerfile_sha256,
        'image': IMAGE_NAME,
        'manifest_sha256': manifest_sha256,
        'playwright_version': pw_version,
        'pyproject_deps_sha256': pyproject_deps_sha256,
        'python_version': python_version,
        'requirements_sha256': requirements_sha256,
        'runner_script_sha256': runner_script_sha256,
        'tag': tag,
    }


def extras_requirements(root: Path, dest: Path) -> None:
    data = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    optional = data.get('project', {}).get('optional-dependencies', {})
    lines = list(optional.get('test', [])) + list(optional.get('browser', []))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_manifest(root: Path, dest: Path) -> None:
    manifest = compute_manifest(root)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def github_output(root: Path) -> None:
    manifest = compute_manifest(root)
    lines = [f'{key}={manifest[key]}' for key in ('image', 'tag', 'manifest_sha256', 'cache_scope')]
    for line in lines:
        print(line)
    output_file = os.environ.get('GITHUB_OUTPUT')
    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            for line in lines:
                f.write(line + '\n')


def validate(root: Path, manifest_path: Path, check_workflows: bool | None) -> None:
    if not manifest_path.exists():
        raise RuntimeError(f'Manifest file not found: {manifest_path}')
    stored = json.loads(manifest_path.read_text(encoding='utf-8'))
    current = compute_manifest(root)

    mismatches = []
    for key in (
        'python_version',
        'playwright_version',
        'requirements_sha256',
        'runner_script_sha256',
        'pyproject_deps_sha256',
        'dockerfile_sha256',
        'manifest_sha256',
        'tag',
    ):
        if stored.get(key) != current.get(key):
            mismatches.append(f'{key}: stored={stored.get(key)!r} vs current={current.get(key)!r}')
    if mismatches:
        raise RuntimeError('Manifest validation failed:\n  ' + '\n  '.join(mismatches))

    expected_py = tuple(int(x) for x in current['python_version'].split('.'))
    if sys.version_info[:2] != expected_py:
        raise RuntimeError(f'Python version {sys.version_info[:2]} does not match expected {expected_py}')

    for line in (root / 'requirements.lock').read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        pkg_name, _, expected_ver = line.partition('==')
        pkg_name = pkg_name.strip()
        expected_ver = expected_ver.strip()
        try:
            installed_ver = importlib.metadata.version(pkg_name)
        except importlib.metadata.PackageNotFoundError:
            raise RuntimeError(f'Locked package {pkg_name} is not installed') from None
        if installed_ver != expected_ver:
            raise RuntimeError(
                f'Locked package {pkg_name} mismatch: installed={installed_ver}, expected={expected_ver}'
            )

    pyproject_data = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
    req_strings = list(pyproject_data.get('project', {}).get('dependencies', []))
    optional = pyproject_data.get('project', {}).get('optional-dependencies', {})
    req_strings.extend(optional.get('test', []))
    req_strings.extend(optional.get('browser', []))
    for req_str in req_strings:
        req = Requirement(req_str)
        try:
            installed_ver = importlib.metadata.version(req.name)
        except importlib.metadata.PackageNotFoundError:
            raise RuntimeError(f'Required package {req.name} ({req_str}) is not installed') from None
        if not req.specifier.contains(installed_ver, prereleases=True):
            raise RuntimeError(f'Installed package {req.name}=={installed_ver} does not satisfy {req_str}')

    ci_yaml = root / '.github/workflows/ci.yaml'
    browser_yaml = root / '.github/workflows/browser.yaml'
    should_check = check_workflows
    if should_check is None:
        should_check = any(
            wf.exists() and 'test-runner-' in wf.read_text(encoding='utf-8')
            for wf in (ci_yaml, browser_yaml)
        )
    if should_check:
        tag = current['tag']
        pattern = re.compile(rf'ghcr\.io/candlelightner/dirigentenstab:{re.escape(tag)}@sha256:[a-f0-9]{{64}}')
        for wf in (ci_yaml, browser_yaml):
            if not wf.exists():
                raise RuntimeError(f'Workflow file not found: {wf}')
            content = wf.read_text(encoding='utf-8')
            if not pattern.search(content):
                raise RuntimeError(
                    f'{wf.name} does not pin ghcr.io/candlelightner/dirigentenstab:{tag}@sha256:<digest>'
                )
            if 'playwright install' in content:
                raise RuntimeError(f'{wf.name} contains redundant playwright install')
            if 'pip install -r' in content:
                raise RuntimeError(f'{wf.name} contains redundant pip install -r')
            if 'packages: write' in content:
                raise RuntimeError(f'{wf.name} contains unauthorized packages: write')
            if 'timeout-minutes:' not in content:
                raise RuntimeError(f'{wf.name} missing timeout-minutes')
            if wf.name == 'browser.yaml' and ('docker compose' in content or 'build-push-action' in content):
                raise RuntimeError(f'{wf.name} must not contain docker steps')
            if wf.name == 'ci.yaml':
                test_job, sep, container_job = content.partition('\n  container:')
                if not sep:
                    raise RuntimeError(f'{wf.name} missing container job')
                if 'docker compose' in test_job or 'build-push-action' in test_job:
                    raise RuntimeError(f'{wf.name} test job must not run docker commands')
                if 'docker compose' not in container_job or 'build-push-action' not in container_job:
                    raise RuntimeError(f'{wf.name} container job missing required docker checks')

    print(f'Validation passed ({current["tag"]})')


def prepare(root: Path, manifest_path: Path, check_workflows: bool | None) -> None:
    start = time.monotonic()
    validate(root, manifest_path, check_workflows)
    subprocess.run(
        [sys.executable, '-m', 'pip', 'install', '--no-deps', '--no-build-isolation', '--no-index', '-e', '.'],
        cwd=root,
        check=True,
    )
    subprocess.run([sys.executable, '-m', 'pip', 'check'], check=True)
    elapsed = time.monotonic() - start
    print(f'Preparation time: {elapsed:.2f}s')
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as f:
            f.write(f'- **Preparation time**: `{elapsed:.2f}s`\n')


def run_command(name: str, command: list[str]) -> None:
    if not command:
        raise ValueError('No command provided to run')
    start = time.monotonic()
    exit_code = 1
    try:
        proc = subprocess.run(command)
        exit_code = proc.returncode
    finally:
        elapsed = time.monotonic() - start
        print(f'Test time ({name}): {elapsed:.2f}s')
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a', encoding='utf-8') as f:
                f.write(f'- **Test time ({name})**: `{elapsed:.2f}s`\n')
    sys.exit(exit_code)


def main() -> None:
    root_parser = argparse.ArgumentParser(add_help=False)
    root_parser.add_argument('--root', type=Path, default=None, help='Project root directory')

    sub_root_parser = argparse.ArgumentParser(add_help=False)
    sub_root_parser.add_argument('--root', type=Path, default=argparse.SUPPRESS, help='Project root directory')

    parser = argparse.ArgumentParser(parents=[root_parser], description=__doc__)
    subparsers = parser.add_subparsers(dest='subcommand', required=True)

    subparsers.add_parser('manifest', parents=[sub_root_parser], help='Print canonical JSON manifest')
    subparsers.add_parser('tag', parents=[sub_root_parser], help='Print manifest tag')
    subparsers.add_parser(
        'github-output',
        parents=[sub_root_parser],
        help='Write manifest variables to GITHUB_OUTPUT and stdout',
    )

    wm_parser = subparsers.add_parser(
        'write-manifest', parents=[sub_root_parser], help='Write manifest JSON to destination'
    )
    wm_parser.add_argument('dest', type=Path, help='Destination path for manifest.json')

    er_parser = subparsers.add_parser(
        'extras-requirements', parents=[sub_root_parser], help='Write test/browser requirements to file'
    )
    er_parser.add_argument('dest', type=Path, help='Destination path for extras.txt')

    def add_validation_args(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            '--manifest-path',
            type=Path,
            default=Path('/opt/test-runner/manifest.json'),
            help='Path to stored manifest.json',
        )
        group = p.add_mutually_exclusive_group()
        group.add_argument(
            '--check-workflows',
            dest='check_workflows',
            action='store_true',
            default=None,
            help='Verify that CI workflows pin this exact image tag and digest',
        )
        group.add_argument(
            '--no-check-workflows',
            dest='check_workflows',
            action='store_false',
            help='Skip workflow pinning check',
        )

    val_parser = subparsers.add_parser(
        'validate', parents=[sub_root_parser], help='Validate environment and manifest'
    )
    add_validation_args(val_parser)

    prep_parser = subparsers.add_parser(
        'prepare', parents=[sub_root_parser], help='Prepare container for test execution'
    )
    add_validation_args(prep_parser)

    run_parser = subparsers.add_parser(
        'run',
        parents=[sub_root_parser],
        help='Execute test command with timing and status propagation',
    )
    run_parser.add_argument('name', help='Name of the test step')
    run_parser.add_argument('command', nargs=argparse.REMAINDER, help='Command and arguments to execute')

    args = parser.parse_args()
    root = find_root(args.root)

    if args.subcommand == 'manifest':
        manifest = compute_manifest(root)
        print(json.dumps(manifest, sort_keys=True, separators=(',', ':')))
    elif args.subcommand == 'tag':
        manifest = compute_manifest(root)
        print(manifest['tag'])
    elif args.subcommand == 'github-output':
        github_output(root)
    elif args.subcommand == 'write-manifest':
        write_manifest(root, args.dest)
    elif args.subcommand == 'extras-requirements':
        extras_requirements(root, args.dest)
    elif args.subcommand == 'validate':
        validate(root, args.manifest_path, args.check_workflows)
    elif args.subcommand == 'prepare':
        prepare(root, args.manifest_path, args.check_workflows)
    elif args.subcommand == 'run':
        cmd = list(args.command)
        if cmd and cmd[0] == '--':
            cmd = cmd[1:]
        run_command(args.name, cmd)


if __name__ == '__main__':
    main()
