"""Agent shell images: a structured per-agent spec the hub renders into a Dockerfile from a fixed template.

Agents never write Dockerfile text. Every value is validated against a strict shape and shell-quoted when rendered.
Fields in APPROVAL_FIELDS reach outside the Ubuntu archive and the fixed catalog, so additions need owner approval.
"""

import hashlib
import re
import shlex
from urllib.parse import urlparse

BASE_IMAGE = 'dirigentenstab-shell:latest'
# Exact install commands live here; nothing in a spec chooses how a harness is installed.
HARNESSES = {'gemini': ('npm', '@google/gemini-cli'), 'qwen': ('npm', '@qwen-code/qwen-code'), 'aider': ('pipx', 'aider-chat')}
FIELDS = ('harnesses', 'apt', 'apt_repos', 'npm', 'pip', 'urls')
APPROVAL_FIELDS = ('apt_repos', 'npm', 'pip', 'urls')
LIMITS = {'harnesses': len(HARNESSES), 'apt': 50, 'apt_repos': 5, 'npm': 20, 'pip': 20, 'urls': 10}
APT = re.compile(r'[a-z0-9][a-z0-9+.-]{0,62}')
REPO_NAME = re.compile(r'[a-z0-9][a-z0-9-]{0,30}')
SUITE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,60}')
COMPONENT = re.compile(r'[a-z0-9][a-z0-9-]{0,30}')
NPM = re.compile(r'(@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,63}(@[A-Za-z0-9][A-Za-z0-9._-]{0,39})?')
PIP = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,99}(==[A-Za-z0-9][A-Za-z0-9._+!-]{0,39})?')
SHA256 = re.compile(r'[0-9a-f]{64}')
URL_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}')
HTTPS = re.compile(r'https://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?(/[A-Za-z0-9._~%/+=:@,-]*)?(\?[A-Za-z0-9._~%/+=:@,&-]*)?')
MAX_URL = 500


def _list(value, field):
    if not isinstance(value, list) or len(value) > LIMITS[field] * 2:
        raise ValueError(f'{field} must be a list of at most {LIMITS[field]} entries')
    return value


def _https(value, what):
    if not isinstance(value, str) or len(value) > MAX_URL or not HTTPS.fullmatch(value):
        raise ValueError(f'{what} must be a plain https URL')
    if not urlparse(value).hostname:
        raise ValueError(f'{what} must be a plain https URL')
    return value


def _item(value, pattern, what):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f'Invalid {what}: {str(value)[:60]!r}')
    return value


def _mapping(value, keys, what):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ValueError(f'Each {what} needs exactly: ' + ', '.join(keys))
    return value


def normalize(raw):
    """Validate a spec and return its canonical form (sorted, deduplicated, empty fields dropped)."""
    if not isinstance(raw, dict) or set(raw) - set(FIELDS):
        raise ValueError('Unknown shell image field; use: ' + ', '.join(FIELDS))
    spec = {}
    for field in FIELDS:
        if field not in raw or raw[field] is None:
            continue
        items = _list(raw[field], field)
        if field == 'harnesses':
            out = sorted({_item(i, re.compile('|'.join(HARNESSES)), 'harness (catalog: ' + ', '.join(HARNESSES) + ')') for i in items})
        elif field == 'apt':
            out = sorted({_item(i, APT, 'apt package name') for i in items})
        elif field == 'npm':
            out = sorted({_item(i, NPM, 'npm package') for i in items})
        elif field == 'pip':
            out = sorted({_item(i, PIP, 'pip package') for i in items})
        elif field == 'apt_repos':
            repos = {}
            for repo in items:
                _mapping(repo, ('name', 'uri', 'suite', 'components', 'key_url'), 'apt repository')
                components = repo['components']
                if not isinstance(components, list) or not 1 <= len(components) <= 6:
                    raise ValueError('apt repository components must list 1-6 names')
                repos[_item(repo['name'], REPO_NAME, 'apt repository name')] = {
                    'name': repo['name'], 'uri': _https(repo['uri'], 'apt repository uri'),
                    'suite': _item(repo['suite'], SUITE, 'apt suite'),
                    'components': sorted({_item(c, COMPONENT, 'apt component') for c in components}),
                    'key_url': _https(repo['key_url'], 'apt signing key URL')}
            out = [repos[name] for name in sorted(repos)]
        else:
            files = {}
            for entry in items:
                _mapping(entry, ('name', 'url', 'sha256'), 'url download')
                files[_item(entry['name'], URL_NAME, 'download file name')] = {
                    'name': entry['name'], 'url': _https(entry['url'], 'download url'),
                    'sha256': _item(entry['sha256'], SHA256, 'sha256 (64 lowercase hex characters)')}
            out = [files[name] for name in sorted(files)]
        if len(out) > LIMITS[field]:
            raise ValueError(f'{field} allows at most {LIMITS[field]} entries')
        if out:
            spec[field] = out
    return spec


def key(item):
    return item['name'] if isinstance(item, dict) else item


def missing(wanted, base):
    """Per approval field: entries of `wanted` that `base` does not contain yet (what needs owner approval)."""
    return {field: [i for i in wanted.get(field, []) if i not in base.get(field, [])]
            for field in APPROVAL_FIELDS if [i for i in wanted.get(field, []) if i not in base.get(field, [])]}


def merge(base, additions):
    """Union of `additions` into `base` (the owner-approved merge); the result is normalized again."""
    return normalize({field: [*base.get(field, []), *(additions or {}).get(field, [])] for field in FIELDS})


def _run(*parts):
    return 'RUN ' + ' '.join(parts)


def steps(spec, implicit=True):
    """The Dockerfile instructions between USER root and USER dev. `implicit` adds packages the installers themselves need."""
    spec = normalize(spec)
    npm = [*spec.get('npm', []), *(p for kind, p in (HARNESSES[h] for h in spec.get('harnesses', [])) if kind == 'npm')]
    pipx = [*spec.get('pip', []), *(p for kind, p in (HARNESSES[h] for h in spec.get('harnesses', [])) if kind == 'pipx')]
    apt = list(spec.get('apt', []))
    if implicit and pipx:
        apt += ['pipx', 'python3-venv']
    lines = []
    for repo in spec.get('apt_repos', []):
        path = f"/etc/apt/keyrings/{repo['name']}.asc"
        deb = f"deb [signed-by={path}] {repo['uri']} {repo['suite']} {' '.join(repo['components'])}"
        lines.append(_run('install -d -m 755 /etc/apt/keyrings', '&&', 'curl -fsSL', shlex.quote(repo['key_url']), '-o', shlex.quote(path),
                          '&&', 'printf', "'%s\\n'", shlex.quote(deb), '>', shlex.quote(f"/etc/apt/sources.list.d/{repo['name']}.list")))
    if apt or spec.get('apt_repos'):
        install = ['&&', 'apt-get install -y --no-install-recommends', *map(shlex.quote, sorted(set(apt)))] if apt else []
        lines.append(_run('apt-get update', *install, '&&', 'rm -rf /var/lib/apt/lists/*'))
    if npm:
        lines.append(_run('npm install -g', *map(shlex.quote, sorted(set(npm))), '&&', 'npm cache clean --force'))
    for package in sorted(set(pipx)):  # pipx keeps each tool in its own venv under /opt/pipx and links its commands into PATH
        lines.append(_run('PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install', shlex.quote(package), '&&', 'chmod -R a+rX /opt/pipx'))
    for entry in spec.get('urls', []):
        target = shlex.quote('/opt/extra/' + entry['name'])
        lines.append(_run('install -d -m 755 /opt/extra', '&&', 'curl -fsSL', shlex.quote(entry['url']), '-o', target,
                          '&&', 'echo', shlex.quote(f"{entry['sha256']}  /opt/extra/{entry['name']}"), '| sha256sum -c -', '&&', 'chmod 755', target))
    assert not any('\n' in line or '\r' in line for line in lines)
    return lines


def render(spec):
    """The Dockerfile for a spec; '' for the empty spec (the base image is used as is)."""
    spec = normalize(spec)
    if not spec:
        return ''
    return '\n'.join([f'FROM {BASE_IMAGE}', 'USER root', 'ENV DEBIAN_FRONTEND=noninteractive', *steps(spec), 'USER dev', ''])


def tag(agent_id, dockerfile, base_id):
    """`dirigentenstab-shell-<agent>:<12 hex>`; the hash covers the Dockerfile and the base image id, so a base rebuild invalidates it."""
    digest = hashlib.sha256(f'{base_id}\n{dockerfile}'.encode()).hexdigest()[:12]
    return f'dirigentenstab-shell-{agent_id.lower()}:{digest}'


def describe(additions):
    """A one-line summary of approval-needed additions for the escalation queue."""
    parts = []
    for field, items in additions.items():
        parts.append(f"{field.replace('_', ' ')}: " + ', '.join(key(i) + (' sha256 ' + i['sha256'] if field == 'urls' else '') for i in items))
    return '; '.join(parts)


def to_text(spec):
    """Spec fields as one-entry-per-line text for the owner's editor."""
    return {'apt': '\n'.join(spec.get('apt', [])), 'npm': '\n'.join(spec.get('npm', [])), 'pip': '\n'.join(spec.get('pip', [])),
            'apt_repos': '\n'.join(f"{r['name']} {r['uri']} {r['suite']} {','.join(r['components'])} {r['key_url']}" for r in spec.get('apt_repos', [])),
            'urls': '\n'.join(f"{u['name']} {u['url']} {u['sha256']}" for u in spec.get('urls', []))}


def from_text(harnesses, texts):
    """Inverse of to_text; raises ValueError for malformed lines."""
    rows = {field: [line.split() for line in (texts.get(field) or '').splitlines() if line.strip()] for field in FIELDS}
    if any(len(r) != 1 for f in ('apt', 'npm', 'pip') for r in rows[f]):
        raise ValueError('apt, npm and pip take one package per line')
    if any(len(r) != 5 for r in rows['apt_repos']) or any(len(r) != 3 for r in rows['urls']):
        raise ValueError('apt repositories: "name uri suite comp1,comp2 key_url"; urls: "name url sha256"')
    return normalize({
        'harnesses': list(harnesses or []), **{f: [r[0] for r in rows[f]] for f in ('apt', 'npm', 'pip')},
        'apt_repos': [dict(zip(('name', 'uri', 'suite', 'components', 'key_url'), (*r[:3], r[3].split(','), r[4]), strict=True)) for r in rows['apt_repos']],
        'urls': [{'name': r[0], 'url': r[1], 'sha256': r[2]} for r in rows['urls']]})
