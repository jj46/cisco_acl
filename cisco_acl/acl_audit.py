"""
Audit an ACL, checking for the following:
* Invalid ACEs (syntax errors)
* Networking errors (invalid IP/subnets)
* Invalid ports

Supported ACL formats:
* IOS extended
* ASA extended
"""
import logging
import os.path
import re
from ipaddress import ip_network, ip_address
from cisco_acl.regexes import ace_match, ip_address_rx, subnet_rx, dnsname_rx, keyword_rx
from cisco_acl.port_translations import translate_port

logging.getLogger(__name__)


class AclAuditor:
    def __init__(self, **kwargs):
        self.acl = kwargs.get('acl')
        self.acl_format = kwargs.get('format', 'ios')
        self.supported_formats = [
            'ios-extended',
            'asa-extended'
        ]
        self.aces = {}
        """
        aces = {
            # line_num: ace
            1: 'permit tcp any any eq 80'
        }
        """
        self.permissions = {}
        """
        permissions = {
            # line_num: perm
            1: {
            'action': 'permit',
            'destination': 'any',
            'destination_ports': 'eq 80',
            'keyword': None,
            'name': None,
            'protocol': 'tcp',
            'sequence': None,
            'source': 'any',
            'source_ports': None},
        }
        """
        self.errors = {}
        """
        errors = {
            # line_num: error
            5: 'Invalid subnet 1.1.5.5/28: Host bits set',
            10: 'Invalid ACE syntax',
        }
        """
        self._parse()
        self._run_audit()

    def _parse(self):
        acl = os.path.abspath(self.acl)
        if not os.path.isfile(acl):
            raise FileNotFoundError

        with open(acl, mode='rt', errors='ignore', encoding='utf-8') as f:
            for i, line in enumerate(f.readlines(), start=1):
                line = line.strip()
                if line == '':  # Skip blank lines
                    continue

                if line.startswith('!'):  # Skip comments
                    continue

                if line.startswith('remark'):
                    self.aces[i] = line
                    continue
                ace = ace_match(line)
                if not ace:
                    self.errors[i] = 'Invalid ACE: ' + line
                else:
                    self.permissions[i] = ace
                    self.aces[i] = line

    def _run_audit(self):
        logging.info('Processing networking errors ...')
        for i, perm in self.permissions.items():
            self._audit_networks({i: perm})
            self._audit_ports({i: perm})

    def _audit_networks(self, permission):
        for i, perm in permission.items():
            for net in [perm['source'], perm['destination']]:
                if net == 'any':
                    continue

                if net.startswith('object-group') or net.startswith('addrgroup'):
                    og = net.split()[1]
                    if not re.match(dnsname_rx, og):
                        self.errors[i] = 'Invalid object-group: ' + og
                    else:
                        continue

                if net.startswith('host'):
                    host = net.split()[1]

                    if re.match(ip_address_rx, host):
                        try:
                            ip = ip_address(host)
                        except ValueError:
                            self.errors[i] = 'Invalid host IP: ' + host
                    else:
                        if re.match('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', host):
                            self.errors[i] = 'Invalid host IP: ' + host
                        elif not re.match(dnsname_rx, host):
                            self.errors[i] = 'Invalid host: ' + host

                elif re.match(subnet_rx, net):
                    try:
                        network = ip_network('/'.join(net.split()))
                    except ValueError as e:
                        self.errors[i] = 'Invalid subnet "{0}": {1}'.format(net, e)

                else:
                    self.errors[i] = 'Invalid host/network: {0}'.format(net)

    def _audit_ports(self, permission):
        for i, perm in permission.items():
            if perm['protocol'].lower() not in ['tcp', 'udp']:
                continue
            for ports in [perm['source_ports'], perm['destination_ports']]:
                if ports is None:
                    continue
                for p in ports.split()[1:]:
                    if not re.match('\d+$', p):
                        if re.match(keyword_rx, p):
                            continue
                        port_num = translate_port('ios', perm['protocol'], [p], 'to_number')[0]
                        if p == port_num:
                            self.errors[i] = 'Invalid port: {0} - {1} {2}'.format(self.acl_format, perm['protocol'], p)
