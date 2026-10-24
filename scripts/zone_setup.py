#!/usr/bin/env python3
"""Resume-safe private real KVM zone setup; no host SSH or libvirt security changes."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import grp
import hashlib
import hmac
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from native_setup import ADDRESS, BRIDGE, STATE, properties, run, save

API = f'http://{ADDRESS}:8080/client/api'
ZONE, POD, CLUSTER = 'Dirigentenstab', 'Dirigentenstab-private', 'Dirigentenstab-KVM'
GUEST_TEMPLATE_NAME = 'Ubuntu-24.04-20261017'
GUEST_TEMPLATE_URL = 'https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img'
GUEST_TEMPLATE_SHA256 = '04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94'


class Cloud:
    def __init__(self):
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        self.session = None
        self.credentials = None

    def call(self, command, **params):
        params = {'command': command, 'response': 'json', **params}
        if self.credentials:
            params['apiKey'] = self.credentials['apikey']
            params['signatureversion'] = '3'
            params['expires'] = (datetime.now(timezone.utc) + timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
            canonical = '&'.join(f'{key.lower()}={urllib.parse.quote(str(value), safe="-_.~").lower()}'
                                 for key, value in sorted(params.items(), key=lambda item: item[0].lower()))
            params['signature'] = base64.b64encode(hmac.new(self.credentials['secretkey'].encode(),
                                                          canonical.encode(), hashlib.sha1).digest()).decode()
        elif self.session:
            params['sessionkey'] = self.session
        request = urllib.request.Request(API, data=urllib.parse.urlencode(params).encode())
        try:
            with self.opener.open(request, timeout=180) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            detail = 'inspect private CloudStack Events'
            if exc.code not in {401, 403} and command in {'createNetwork', 'createZone', 'createPod', 'addCluster', 'addImageStore', 'registerTemplate'}:
                try:
                    detail = next(iter(json.load(exc).values())).get('errortext', detail)
                    for value in [params.get('apiKey'), params.get('signature')]:
                        if value:
                            detail = detail.replace(value, '[redacted]')
                except (ValueError, StopIteration, AttributeError):
                    pass
            raise RuntimeError(f'{command}: HTTP {exc.code}; {detail}') from None
        result = next(iter(body.values()))
        if result.get('errorcode'):
            raise RuntimeError(f'{command}: CloudStack error {result["errorcode"]}')
        return result

    def job(self, command, **params):
        result = self.call(command, **params)
        if 'jobid' not in result:
            return result
        for _ in range(180):
            poll = self.call('queryAsyncJobResult', jobid=result['jobid'])
            if poll['jobstatus'] == 1:
                return poll.get('jobresult', {})
            if poll['jobstatus'] == 2:
                raise RuntimeError(f'{command}: asynchronous job failed; inspect CloudStack Events')
            time.sleep(2)
        raise RuntimeError(f'{command}: job {result["jobid"]} remains pending; inspect it before retrying')


def bootstrap(cloud):
    ready, pending = STATE / 'cloudstack-admin.json', STATE / 'initial-admin.json'
    if ready.exists():
        cloud.credentials = json.loads(ready.read_text())
        cloud.call('listCapabilities')
        return
    if not pending.exists():
        save(pending, json.dumps({'username': 'admin', 'password': secrets.token_urlsafe(32)}), 0o600)
    initial = json.loads(pending.read_text())
    try:
        login = cloud.call('login', username='admin', password=initial['password'], domain='/')
    except RuntimeError:
        login = cloud.call('login', username='admin', password='password', domain='/')
        cloud.session = login['sessionkey']
        cloud.call('updateUser', id=login['userid'], password=initial['password'])
        cloud.session = None
        login = cloud.call('login', username='admin', password=initial['password'], domain='/')
    cloud.session = login['sessionkey']
    keys = cloud.call('registerUserKeys', id=login['userid'], name='Dirigentenstab installation')
    keys = keys.get('userkeys', keys)
    save(ready, json.dumps({'url': API, 'apikey': keys['apikey'], 'secretkey': keys['secretkey'],
                          'user_id': login['userid'], 'username': 'admin'}), 0o600)
    cloud.credentials, cloud.session = json.loads(ready.read_text()), None
    cloud.call('listCapabilities')
    print(f'Default admin password replaced; initial identity and bootstrap keys are root-private in {STATE}.')


def ensure(cloud, listing, item, creation, *, match, **params):
    existing = cloud.call(listing).get(item, [])
    found = next((entry for entry in existing if all(entry.get(key) == value for key, value in match.items())), None)
    if found:
        return found
    result = cloud.job(creation, **params)
    if item in result:
        value = result[item]
        return value[0] if isinstance(value, list) else value
    found = next((entry for entry in cloud.call(listing).get(item, [])
                  if all(entry.get(key) == value for key, value in match.items())), None)
    if not found:
        raise RuntimeError(f'{creation} did not return a discoverable {item}')
    return found


def configure_storage():
    try:
        group = grp.getgrnam('ds-secondary')
    except KeyError:
        run('groupadd', '--system', 'ds-secondary')
        group = grp.getgrnam('ds-secondary')
    directory = Path('/var/lib/dirigentenstab/secondary')
    directory.mkdir(parents=True, exist_ok=True)
    directory.parent.chmod(0o711)
    os.chown(directory, 65534, group.gr_gid)
    directory.chmod(0o2770)
    # Only CloudStack system-VM management IPs can mount this dedicated directory.
    # Ordinary guest allocation is .100-.220, outside this export ACL.
    options = f'rw,sync,no_subtree_check,root_squash,anonuid=65534,anongid={group.gr_gid}'
    save('/etc/exports.d/dirigentenstab.exports',
         f'{directory} 10.253.80.1({options}) 10.253.80.16/28({options}) 10.253.80.32/28({options})\n')
    save('/etc/nfs.conf.d/dirigentenstab.conf', '[nfsd]\nhost=10.253.80.1\nvers3=n\nvers4=y\n')
    run('systemctl', 'unmask', 'nfs-server', 'rpcbind', 'rpcbind.socket')
    run('exportfs', '-ra')
    run('systemctl', 'restart', 'nfs-kernel-server')


def import_system_cas(path):
    marker = STATE / 'agent-system-cas.done'
    if marker.exists():
        return
    run('keytool', '-importkeystore', '-noprompt', '-srckeystore', '/etc/ssl/certs/java/cacerts',
        '-srcstorepass', 'changeit', '-destkeystore', str(path / 'cloud.jks'),
        '-deststorepass:file', str(STATE / 'agent-keystore-password'))
    marker.touch(mode=0o600)


def agent_certificate(cloud):
    path = Path('/etc/cloudstack/agent')
    if (path / 'cloud.jks').exists():
        import_system_cas(path)
        return
    certificate = cloud.job('issueCertificate', domain='homeserver,dirigentenstab.internal',
                             ipaddress=ADDRESS, duration=365)
    certificate = certificate.get('certificates', certificate)
    if not isinstance(certificate, dict):
        raise RuntimeError('Unexpected issueCertificate response; certificate import stopped safely.')
    for filename, key in [('cloud.crt', 'certificate'), ('cloud.key', 'privatekey'), ('cloud.ca.crt', 'cacertificates')]:
        save(path / filename, certificate[key], 0o600)
    password = secrets.token_urlsafe(24)
    save(STATE / 'agent-keystore-password', password, 0o600)
    properties(path / 'agent.properties', {'keystore.passphrase': password})
    (path / 'agent.properties').chmod(0o600)
    run('openssl', 'pkcs12', '-export', '-name', 'cloud', '-in', str(path / 'cloud.crt'),
        '-inkey', str(path / 'cloud.key'), '-certfile', str(path / 'cloud.ca.crt'),
        '-out', str(path / 'cloud.p12'), '-passout', f'file:{STATE}/agent-keystore-password')
    run('keytool', '-importkeystore', '-noprompt', '-srckeystore', str(path / 'cloud.p12'),
        '-srcstoretype', 'PKCS12', '-srcstorepass:file', str(STATE / 'agent-keystore-password'),
        '-destkeystore', str(path / 'cloud.jks'), '-deststoretype', 'JKS',
        '-deststorepass:file', str(STATE / 'agent-keystore-password'))
    run('keytool', '-importcert', '-noprompt', '-alias', 'cloud-ca', '-file', str(path / 'cloud.ca.crt'),
        '-keystore', str(path / 'cloud.jks'), '-storepass:file', str(STATE / 'agent-keystore-password'))
    (path / 'cloud.p12').unlink()
    (path / 'cloud.jks').chmod(0o600)
    import_system_cas(path)


def guest_template(cloud, zone_id):
    templates = cloud.call('listTemplates', templatefilter='all', zoneid=zone_id).get('template', [])
    existing = next((entry for entry in templates if entry['name'] == GUEST_TEMPLATE_NAME), None)
    if existing:
        return existing['id']
    systems = cloud.call('listOsTypes', keyword='Ubuntu').get('ostype', [])
    ubuntu = next((entry for entry in systems if entry['description'] == 'Ubuntu 24.04 LTS'), None)
    if not ubuntu:
        raise RuntimeError('Pinned CloudStack release has no Ubuntu 24.04 guest OS mapping.')
    template = cloud.call('registerTemplate', name=GUEST_TEMPLATE_NAME, displaytext='Ubuntu 24.04 LTS managed Linux',
                          url=GUEST_TEMPLATE_URL, checksum='{SHA-256}' + GUEST_TEMPLATE_SHA256,
                          zoneid=zone_id, ostypeid=ubuntu['id'], format='QCOW2', hypervisor='KVM',
                          arch='x86_64', bits=64, ispublic='true', isextractable='false',
                          passwordenabled='false', directdownload='true')
    return template['template'][0]['id']


def zone(cloud):
    cloud.call('updateConfiguration', name='system.vm.use.local.storage', value='true')
    management = cloud.call('listConfigurations', name='management.network.cidr').get('configuration', [])
    if management and management[0].get('value') != '10.253.80.0/24':
        cloud.call('updateConfiguration', name='management.network.cidr', value='10.253.80.0/24')
        run('systemctl', 'restart', 'cloudstack-management')
        for _ in range(120):
            try:
                cloud.call('listCapabilities')
                break
            except (OSError, RuntimeError):
                time.sleep(2)
        else:
            raise RuntimeError('Private management network restart did not become ready.')
    configure_storage()
    zone = ensure(cloud, 'listZones', 'zone', 'createZone', match={'name': ZONE},
                  name=ZONE, dns1='1.1.1.1', internaldns1='1.1.1.1', networktype='Basic',
                  localstorageenabled='true', securitygroupenabled='true')
    pod = ensure(cloud, 'listPods', 'pod', 'createPod', match={'name': POD}, name=POD,
                 zoneid=zone['id'], gateway=ADDRESS, netmask='255.255.255.0',
                 startip='10.253.80.20', endip='10.253.80.40')
    cluster = ensure(cloud, 'listClusters', 'cluster', 'addCluster', match={'name': CLUSTER},
                     clustername=CLUSTER, zoneid=zone['id'], podid=pod['id'],
                     hypervisor='KVM', clustertype='CloudManaged')
    networks = cloud.call('listPhysicalNetworks', zoneid=zone['id']).get('physicalnetwork', [])
    physical = networks[0] if networks else cloud.job('createPhysicalNetwork', zoneid=zone['id'],
                                                    name='Dirigentenstab-private')['physicalnetwork']
    traffic = cloud.call('listTrafficTypes', physicalnetworkid=physical['id']).get('traffictype', [])
    for kind in ['Management', 'Guest']:
        if not any(entry['traffictype'] == kind for entry in traffic):
            cloud.call('addTrafficType', physicalnetworkid=physical['id'], traffictype=kind, kvmnetworklabel=BRIDGE)
    cloud.call('updatePhysicalNetwork', id=physical['id'], state='Enabled')
    providers = cloud.call('listNetworkServiceProviders', physicalnetworkid=physical['id']).get('networkserviceprovider', [])
    for provider in providers:
        if provider['name'] == 'VirtualRouter':
            vr = cloud.call('listVirtualRouterElements', nspid=provider['id']).get('virtualrouterelement', [])
            if vr:
                cloud.call('configureVirtualRouterElement', id=vr[0]['id'], enabled='true')
        if provider['name'] in {'VirtualRouter', 'SecurityGroupProvider'} and provider['state'] != 'Enabled':
            cloud.call('updateNetworkServiceProvider', id=provider['id'], state='Enabled')
    agent_certificate(cloud)
    guid = STATE / 'agent-guid'
    if not guid.exists():
        save(guid, str(uuid.uuid4()), 0o600)
    properties('/etc/cloudstack/agent/agent.properties',
               {'zone': ZONE, 'pod': POD, 'cluster': CLUSTER, 'guid': guid.read_text().strip()})
    run('systemctl', 'unmask', 'cloudstack-agent')
    run('systemctl', 'enable', '--now', 'cloudstack-agent')
    for _ in range(400):
        hosts = cloud.call('listHosts', type='Routing', zoneid=zone['id']).get('host', [])
        if any(host['state'] == 'Up' for host in hosts):
            break
        time.sleep(3)
    else:
        raise RuntimeError('KVM agent did not register; inspect journalctl -u cloudstack-agent and management logs.')
    stores = cloud.call('listImageStores', zoneid=zone['id']).get('imagestore', [])
    if not stores:
        cloud.call('addImageStore', zoneid=zone['id'], name='Dirigentenstab-secondary',
                   provider='NFS', url=f'nfs://{ADDRESS}/var/lib/dirigentenstab/secondary')
    networks = cloud.call('listNetworks', zoneid=zone['id'], listall='true').get('network', [])
    if not any(network.get('name') == 'Dirigentenstab-guests' for network in networks):
        offerings = cloud.call('listNetworkOfferings', name='DefaultSharedNetworkOfferingWithSGService').get('networkoffering', [])
        if not offerings:
            raise RuntimeError('Required basic-zone security group network offering is missing.')
        cloud.call('createNetwork', zoneid=zone['id'], physicalnetworkid=physical['id'],
                   name='Dirigentenstab-guests', displaytext='Private managed guest network',
                   networkofferingid=offerings[0]['id'], acltype='Domain', subdomainaccess='true')
    guest = next(entry for entry in cloud.call('listNetworks', zoneid=zone['id'], listall='true').get('network', [])
                 if entry.get('name') == 'Dirigentenstab-guests')
    ranges = cloud.call('listVlanIpRanges', zoneid=zone['id'], networkid=guest['id']).get('vlaniprange', [])
    if not ranges:
        cloud.call('createVlanIpRange', zoneid=zone['id'], podid=pod['id'], networkid=guest['id'],
                   forvirtualnetwork='false', gateway=ADDRESS, netmask='255.255.255.0',
                   startip='10.253.80.100', endip='10.253.80.220', vlan='untagged')
    cloud.call('updateZone', id=zone['id'], allocationstate='Enabled')
    template_id = guest_template(cloud, zone['id'])
    offerings = cloud.call('listServiceOfferings', name='Dirigentenstab-small').get('serviceoffering', [])
    offering = offerings[0] if offerings else cloud.call('createServiceOffering',
        name='Dirigentenstab-small', displaytext='1 CPU, 1 GiB, local primary storage',
        cpunumber=1, cpuspeed=1000, memory=1024, storagetype='local')['serviceoffering']
    save(STATE / 'zone.json', json.dumps({'zone_id': zone['id'], 'pod_id': pod['id'], 'cluster_id': cluster['id'],
                                        'template_id': template_id, 'template_url': GUEST_TEMPLATE_URL,
                                        'template_sha256': GUEST_TEMPLATE_SHA256,
                                        'network_id': guest['id'], 'service_offering_id': offering['id']}), 0o600)
    print('Real KVM host registered; private zone, guest security groups and restricted secondary storage configured.')


def verify(cloud):
    selected = next((entry for entry in cloud.call('listZones').get('zone', []) if entry['name'] == ZONE), None)
    if not selected:
        raise RuntimeError('Managed CloudStack zone is missing.')
    hosts = cloud.call('listHosts', zoneid=selected['id'], type='Routing').get('host', [])
    if not any(host['state'] == 'Up' and host['hypervisor'] == 'KVM' for host in hosts):
        raise RuntimeError('No live real KVM host is registered in the managed zone.')
    print(f'CloudStack API verified; zone={ZONE}; KVM host=Up; backend=real KVM.')
    print('System VMs:', [(entry['systemvmtype'], entry['state']) for entry in
                          cloud.call('listSystemVms', zoneid=selected['id']).get('systemvm', [])])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verify', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run through sudo ./setup.sh')
    os.umask(0o077)
    cloud = Cloud()
    bootstrap(cloud)
    if not args.verify:
        zone(cloud)
    verify(cloud)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
