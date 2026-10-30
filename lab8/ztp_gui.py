"""Small local GUI adapter around Lab 8; no work occurs on import.

Privileged changes go through the installed, root-owned allowlisted helper.
Job files contain only public identities/status, never passwords or hashes.
"""
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import threading
import time

import yaml
from netmiko import ConnectHandler

import config_changes
from lab8 import day0
from save_golden_configs import validate_running_config
from security import credential_provider
from security.setup_recovery_accounts import quiet_transport

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = day0.RUNTIME
INVENTORY = ROOT / 'inventory/devices.yml'
TOPOLOGY = ROOT / 'nettopo.clab.yml'
HELPER = '/usr/local/libexec/netpilot-ztp-helper'
NETWORK = ipaddress.IPv4Network('172.20.20.0/24')
_LOCK = threading.Lock()
_ACTIVE = set()


class ZtpError(RuntimeError):
    pass


def validate_hostname(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z](?:[A-Za-z0-9-]{0,30}[A-Za-z0-9])?', name)
            or name.casefold() in {'add', 'ztp'}):
        raise ZtpError('Use 1–32 letters, numbers or hyphens, starting with a letter and ending with a letter or number.')
    return name


def _load(path):
    if path.is_symlink() or not path.is_file():
        raise ZtpError('The inventory or topology is unavailable or unsafe.')
    return yaml.load(path.read_bytes(), Loader=config_changes._InventoryLoader)


def helper(action, target=None):
    payload = {'action': action, **(target or {})}
    try:
        result = subprocess.run(['/usr/bin/sudo', '-n', HELPER],
                                input=json.dumps(payload), capture_output=True, text=True,
                                check=False, timeout=420 if action == 'deploy' else 300, shell=False)
        response = json.loads(result.stdout)
        if isinstance(response, dict) and response.get('error') == 'Refusing a plan that changes an existing node or endpoint.':
            raise ZtpError('Unsafe deployment plan: an existing node or endpoint would change. No deployment was performed.')
        if result.returncode or not isinstance(response, dict) or response.get('ok') is not True:
            raise ValueError
        return response
    except ZtpError:
        raise
    except Exception:
        raise ZtpError('The restricted ZTP helper rejected the operation or is unavailable. Check its one-time setup and deployment safety plan.') from None


def inspect_target(hostname, inventory, topology, snapshot):
    """Allocate from independent NSOT, topology and fresh Docker evidence."""
    validate_hostname(hostname)
    try:
        if (snapshot['network'] != str(NETWORK) or topology['name'] != 'pilot-network'
                or topology['mgmt']['network'] != 'clab'
                or topology['mgmt']['ipv4-subnet'] != str(NETWORK)):
            raise ValueError
        names = set()
        used = {NETWORK.network_address, NETWORK.broadcast_address,
                ipaddress.IPv4Address('172.20.20.1')}
        for address in [snapshot['gateway'], *snapshot['addresses']]:
            used.add(ipaddress.IPv4Interface(address).ip)
        for name in snapshot['names']:
            names.add(name.casefold())
            names.add(name.removeprefix('clab-pilot-network-').casefold())
        for name, device in inventory['devices'].items():
            names.update((name.casefold(), device.get('hostname', name).casefold()))
            management = device.get('management', {})
            for key in ('ipv4', 'ipv4_prefix'):
                value = management.get(key)
                if value is not None:
                    if not isinstance(value, str):
                        raise ValueError
                    used.add(ipaddress.IPv4Interface(value).ip)
        for name, device in topology['topology']['nodes'].items():
            names.add(name.casefold())
            for key in ('mgmt-ipv4',):
                if key in device:
                    used.add(ipaddress.IPv4Interface(device[key]).ip)
        if hostname.casefold() in names or ('clab-pilot-network-' + hostname).casefold() in names:
            raise ZtpError('That hostname already exists in inventory, topology, or Docker. Existing devices are never replaced.')
        for address in NETWORK.hosts():
            if address not in used:
                return str(address)
        raise ZtpError('No unused management IPv4 address is available.')
    except ZtpError:
        raise
    except Exception:
        raise ZtpError('Management allocation evidence is missing or malformed; no address was assigned.') from None


def build_record(target):
    name = validate_hostname(target['hostname'])
    address = str(ipaddress.IPv4Address(target['management_ip']))
    return {
        'hostname': name, 'role': 'onboarding_router', 'vendor': 'Arista', 'platform': 'cEOSLab',
        'management': {'interface': 'Management0', 'ipv4': address, 'ipv4_prefix': address + '/24'},
        'template': 'templates/arista_day0.j2',
        'onboarding': {'status': 'pending', 'management_verified': True, 'management_network': 'clab',
                       'bootstrap_mac': target['bootstrap_mac'], 'job_id': target['job_id']},
        'interfaces': {}, 'routing': {name: {'enabled': False} for name in ('ospfv2', 'ospfv3', 'ripv2', 'bgp')},
        'redistribution': [], 'policy': {'prefix_lists': {'ipv4': {}, 'ipv6': {}}, 'route_maps': {}}, 'vlans': {},
    }


def topology_updated(original, hostname, address, mac, host_interface, job_id=None):
    """Insert two blocks using YAML source marks; retain every original byte."""
    validate_hostname(hostname)
    source = original.decode('utf-8')
    parsed = yaml.load(source, Loader=config_changes._InventoryLoader)
    root = yaml.compose(source)
    def child(node, key):
        return next(value for name, value in node.value if name.value == key)
    topology = child(root, 'topology')
    nodes, links = child(topology, 'nodes'), child(topology, 'links')
    if nodes.flow_style or links.flow_style or not nodes.value or not isinstance(links, yaml.SequenceNode):
        raise ZtpError('This topology layout cannot be safely extended.')
    if hostname.casefold() in {name.casefold() for name in parsed['topology']['nodes']}:
        raise ZtpError('That topology node already exists.')
    node = {'kind': 'ceos', 'image': 'ceos:4.36.2F', 'image-pull-policy': 'Never', 'mgmt-ipv4': address, 'suppress-startup-config': True}
    if job_id is not None:
        node['labels'] = {'netpilot-ztp-job-id': job_id}
    link = {'type': 'host', 'endpoint': {'node': hostname, 'interface': 'eth1', 'mac': mac},
            'host-interface': host_interface}
    newline = '\r\n' if '\r\n' in source else '\n'
    insertions = []
    for position, snippet, indent in (
            (nodes.end_mark.index, yaml.safe_dump({hostname: node}, sort_keys=False), nodes.start_mark.column),
            (links.end_mark.index, yaml.safe_dump([link], sort_keys=False), links.start_mark.column)):
        # end_mark may include indentation belonging to the following key.
        if position < len(source):
            position = source.rfind('\n', 0, position) + 1
        block = ''.join(' ' * indent + line + newline for line in snippet.splitlines())
        if position and not source[:position].endswith('\n'):
            block = newline + block
        insertions.append((position, block))
    updated = source
    for position, block in sorted(insertions, reverse=True):
        updated = updated[:position] + block + updated[position:]
    expected = deepcopy(parsed)
    expected['topology']['nodes'][hostname] = node
    expected['topology']['links'].append(link)
    if yaml.load(updated, Loader=config_changes._InventoryLoader) != expected:
        raise ZtpError('The topology addition did not preserve existing definitions.')
    return updated.encode('utf-8')


def _job_directory():
    day0._directories(RUNTIME)
    directory = RUNTIME / 'jobs'
    directory.mkdir(mode=0o700, exist_ok=True)
    mode = directory.lstat()
    if directory.is_symlink() or mode.st_uid != os.geteuid() or mode.st_mode & 0o077:
        raise ZtpError('The protected ZTP job directory is unsafe.')
    return directory


def _job_path(job_id):
    if not isinstance(job_id, str) or not re.fullmatch(r'[0-9a-f]{32}', job_id):
        raise ZtpError('Invalid onboarding job.')
    return _job_directory() / (job_id + '.json')


def _save(job):
    job['updated_at'] = datetime.now(timezone.utc).isoformat()
    config_changes._atomic_write(_job_path(job['job_id']), (json.dumps(job) + '\n').encode(), mode=0o600)


def status(job_id):
    try:
        job = json.loads(day0._read_private(_job_path(job_id)))
        if job['job_id'] != job_id:
            raise ValueError
        if (job.get('started') and job['state'] not in {'Ready', 'Failed'} and job_id not in _ACTIVE):
            descriptor = os.open(_job_directory() / '.operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'r+') as lock:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    pass
                else:
                    job.update(state='Failed', message='The worker was interrupted. Retry checks only this attempt; it never resets the device.')
                    _save(job)
        return job
    except Exception:
        raise ZtpError('Onboarding status is unavailable.') from None


def recent_jobs():
    try:
        return all_jobs()[:10]
    except Exception:
        return []


def all_jobs():
    directory = RUNTIME / 'jobs'
    if not directory.exists():
        return []
    return [status(path.stem) for path in sorted(_job_directory().glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)]


def registration_conflict(hostname, address, exempt_job_id=None):
    """Inventory-only registration must not take an in-progress reservation."""
    for job in all_jobs():
        if job['job_id'] != exempt_job_id and job['state'] != 'Ready' and (
                job['hostname'].casefold() == hostname.casefold() or job['management_ip'] == address):
            return True
    return False


def preview(hostname, platform='cEOSLab'):
    with config_changes._directory_lock(INVENTORY.parent, threading.Lock()):
        return _preview(hostname, platform)


def _preview(hostname, platform):
    if platform != 'cEOSLab':
        raise ZtpError('ZTP supports Arista cEOS only.')
    name = validate_hostname(hostname)
    inventory, topology = _load(INVENTORY), _load(TOPOLOGY)
    snapshot = helper('snapshot')
    if snapshot.get('server_ready') is not True:
        raise ZtpError('The ZTP server requires the GUI image, expiring HTTP mount, DHCP files and bootstrap bridge setup.')
    address = inspect_target(name, inventory, topology, snapshot)
    for job in all_jobs():
        if job['hostname'].casefold() == name.casefold() and job['state'] != 'Ready':
            raise ZtpError('An onboarding attempt already exists for this hostname. Open its status and use Retry.')
        if job['state'] != 'Ready':
            snapshot['addresses'].append(job['management_ip'])
    address = inspect_target(name, inventory, topology, snapshot)
    digest = hashlib.sha256(name.casefold().encode()).hexdigest()
    target = {'hostname': name, 'management_ip': address,
              'bootstrap_mac': '02:08:' + ':'.join(digest[i:i+2] for i in range(0, 8, 2)),
              'host_interface': 'npztp-' + digest[:8], 'job_id': secrets.token_hex(16)}
    macs = {str(value).casefold() for value in snapshot.get('macs', [])}
    for link in topology['topology']['links']:
        if link.get('endpoint', {}).get('mac', '').casefold() == target['bootstrap_mac'] or link.get('host-interface') == target['host_interface']:
            raise ZtpError('The derived bootstrap identity is already in use.')
    if target['bootstrap_mac'] in macs:
        raise ZtpError('The derived bootstrap MAC is already in use.')
    helper('preview', target)
    job = {**target, 'state': 'Preparing', 'started': False, 'message': 'Review the assigned address before provisioning.',
           'topology_digest': hashlib.sha256(TOPOLOGY.read_bytes()).hexdigest()}
    _save(job)
    return job


def _request(job):
    return {key: job[key] for key in ('hostname', 'management_ip', 'bootstrap_mac', 'host_interface', 'job_id')}


def _commit_topology(job):
    # Coordinate with other writers and refuse editor changes since preview.
    with config_changes._directory_lock(TOPOLOGY.parent, threading.Lock()):
        original = TOPOLOGY.read_bytes()
        if TOPOLOGY.is_symlink():
            raise ZtpError('The topology path is unsafe.')
        topology = _load(TOPOLOGY)
        node = topology['topology']['nodes'].get(job['hostname'])
        if node is not None:
            expected = {'kind': 'ceos', 'image': 'ceos:4.36.2F', 'image-pull-policy': 'Never', 'mgmt-ipv4': job['management_ip'], 'suppress-startup-config': True, 'labels': {'netpilot-ztp-job-id': job['job_id']}}
            expected_link = {'type': 'host', 'endpoint': {'node': job['hostname'], 'interface': 'eth1', 'mac': job['bootstrap_mac']}, 'host-interface': job['host_interface']}
            if not job.get('topology_added') or node != expected or expected_link not in topology['topology']['links']:
                raise ZtpError('The pending topology node no longer matches this onboarding attempt.')
            return
        if hashlib.sha256(original).hexdigest() != job['topology_digest']:
            raise ZtpError('The topology changed after review. No deployment was performed.')
        updated = topology_updated(original, job['hostname'], job['management_ip'], job['bootstrap_mac'], job['host_interface'], job['job_id'])
        # Durable owned-attempt metadata before the atomic commit enables safe retry.
        job['topology_added'] = True
        _save(job)
        config_changes._atomic_write(TOPOLOGY, updated, mode=TOPOLOGY.stat().st_mode & 0o777)


def verify_device(record):
    """Read running/startup identity and Management0 using administrative SSH."""
    connection = None
    try:
        with quiet_transport():
            username, password = credential_provider.get_credentials()
            if username != 'admin':
                return False
            connection = ConnectHandler(device_type='arista_eos', host=record['management']['ipv4'],
                                        username=username, password=password, secret=password,
                                        conn_timeout=5, auth_timeout=5, banner_timeout=5, fast_cli=False,
                                        use_keys=False, allow_agent=False, ssh_strict=False, session_log=None)
            if not connection.check_enable_mode():
                connection.enable()
            if not connection.check_enable_mode():
                return False
            for command in ('show running-config', 'show startup-config'):
                output = connection.send_command(command, read_timeout=8)
                validate_running_config('Onboarding target', output, expected_hostname=record['hostname'])
                if output.rstrip().splitlines()[-1].strip() != 'end':
                    return False
                # Literal banner/comment bodies are not configuration evidence.
                output = re.sub(r'(?ms)^(?:banner (?:login|motd)|comment)\s*\n.*?^EOF\s*$', '', output)
                match = re.search(r'(?m)^interface Management0\s*\n((?:[ \t]+[^\n]*\n)*)', output)
                if not match or ('ip address ' + record['management']['ipv4_prefix']) not in [line.strip() for line in match[1].splitlines()]:
                    return False
                for account in ('admin', 'netpilot-recovery'):
                    if not re.search(r'(?m)^username ' + account + r' privilege 15 role network-admin secret sha512 \$6\$', output):
                        return False
            return True
    except Exception:
        return False
    finally:
        if connection is not None:
            try:
                with quiet_transport():
                    connection.disconnect()
            except Exception:
                pass


def _work(job, password_holder, register, lock_file):
    recovery_password = password_holder.pop()
    target = _request(job)
    prepared = False
    try:
        inventory = _load(INVENTORY)
        if any(job['hostname'].casefold() in {name.casefold(), value.get('hostname', name).casefold()}
               for name, value in inventory['devices'].items()):
            raise ZtpError('The device has already been registered. Existing records are never overwritten.')
        for value in inventory['devices'].values():
            for field in ('ipv4', 'ipv4_prefix'):
                address = value.get('management', {}).get(field)
                if address is not None and str(ipaddress.IPv4Interface(address).ip) == job['management_ip']:
                    raise ZtpError('The reviewed management IP is now assigned in inventory. No deployment was performed.')
        # Helper rechecks Docker identity, IP ownership and the exact safety plan.
        helper('preview', target)
        record = build_record(target)
        if job.get('attempts', 0) > 1:
            day0.clear_one(job['hostname'], runtime=RUNTIME)
        day0.render_one(record, recovery_password, runtime=RUNTIME)
        prepared = True
        recovery_password = None
        helper('reload-dhcp', target)
        _commit_topology(job)
        job.update(state='Deploying', message='Deploying only the new node and its bootstrap link.')
        _save(job)
        helper('deploy', target)
        # Preserve the short HTTP lease for ZTP, rather than container creation.
        day0.publish_one(job['hostname'], runtime=RUNTIME, seconds=300)
        helper('attach', target)
        job.update(state='Waiting for ZTP', message='Waiting for saved startup configuration and verified admin SSH.')
        _save(job)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            if verify_device(record):
                # Register only after both running/startup evidence and login succeed.
                record['onboarding'].update(ztp_status='ready', verified_at=datetime.now(timezone.utc).isoformat())
                register(record)
                job.update(state='Ready', message='ZTP and admin SSH verified. Registered pending explicit fleet enrollment.')
                break
            time.sleep(5)
        else:
            raise ZtpError('ZTP or admin SSH verification timed out. The device remains pending; Retry never resets it.')
    except (Exception, KeyboardInterrupt) as error:
        job.update(state='Failed', message=str(error) if isinstance(error, ZtpError) else 'Onboarding failed safely. Check helper setup, credentials and the new device; existing devices were not replaced.')
    finally:
        recovery_password = None
        if prepared:
            try:
                day0.clear_one(job['hostname'], runtime=RUNTIME)
            except Exception:
                job.update(state='Failed', message='Sensitive publication cleanup failed; the HTTP lease will expire. Inspect runtime permissions.')
        try:
            _save(job)
        finally:
            _ACTIVE.discard(job['job_id'])
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
            _LOCK.release()


def start(job_id, recovery_password, register):
    if not isinstance(recovery_password, str) or not recovery_password.strip():
        raise ZtpError('Enter the existing recovery password in the masked field.')
    if not _LOCK.acquire(blocking=False):
        raise ZtpError('Another onboarding operation is running.')
    lock_file = None
    try:
        job = status(job_id)
        if job['state'] == 'Ready' or job_id in _ACTIVE:
            raise ZtpError('This operation has already completed or is running.')
        descriptor = os.open(_job_directory() / '.operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_file = os.fdopen(descriptor, 'r+')
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        job.update(state='Preparing', started=True, attempts=job.get('attempts', 0) + 1, message='Preparing the reviewed device.')
        _save(job)
        _ACTIVE.add(job_id)
        worker = threading.Thread(target=_work, args=(job, [recovery_password], register, lock_file), daemon=True)
        worker.start()
        return job
    except Exception:
        if lock_file is not None:
            lock_file.close()
        _ACTIVE.discard(job_id)
        _LOCK.release()
        raise ZtpError('Cannot start onboarding; another attempt may be active or its state is unavailable.') from None
