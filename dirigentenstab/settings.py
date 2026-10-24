import os
from dataclasses import dataclass
from urllib.parse import urlsplit

from dotenv import load_dotenv


def endpoint(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP(S) URL without embedded credentials')
    if parsed.query or parsed.fragment or any(c in url for c in '\r\n'):
        raise ValueError('Endpoint URLs cannot contain queries, fragments or newlines')
    return url.rstrip('/')


@dataclass
class Settings:
    cloudstack_url: str
    origin: str
    database: str = '/data/dirigentenstab.db'
    key_file: str = '/run/secrets/master_key'
    cmk: str = '/usr/local/bin/cmk'
    workspace: str = '/data/transfers'
    session_seconds: int = 3600
    max_output: int = 65536
    ssh_networks: str = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'

    @classmethod
    def load(cls):
        load_dotenv()
        origin = endpoint(os.environ['PUBLIC_ORIGIN'])
        if urlsplit(origin).scheme != 'https':
            raise ValueError('PUBLIC_ORIGIN must use HTTPS for Secure session cookies')
        return cls(endpoint(os.environ['CLOUDSTACK_URL']), origin,
                   database=os.getenv('DATABASE', '/data/dirigentenstab.db'),
                   key_file=os.getenv('MASTER_KEY_FILE', '/run/secrets/master_key'),
                   cmk=os.getenv('CMK_BINARY', '/usr/local/bin/cmk'),
                   workspace=os.getenv('TRANSFER_WORKSPACE', '/data/transfers'),
                   ssh_networks=os.getenv('SSH_NETWORKS', '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'))
