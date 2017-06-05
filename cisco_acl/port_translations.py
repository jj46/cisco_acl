"""
  This library is meant to assist with translating port numbers to port names (and vice versa)
in Cisco IOS and ASA formatted access-lists

Port types that require translations
* eq           Match only packets on a given port number
* gt           Match only packets with a greater port number
* ge           Match only packets with a greater or equal port number
* lt           Match only packets with a lower port number
* le           Match only packets with an equal or lower port number
* neq          Match only packets not on a given port number
* range        Match only packets in the range of port numbers

Examples:

# Import the library:
# from cisco_acl.port_translations import PortTranslator

# Translate an IOS ACE from port numbers to port names
>>> ace = 'permit tcp any any eq 80'
>>> PortTranslator(ace).translate_ace(acl_format='ios', conversion_type='to_name')
'permit tcp any any eq www'

# Translate an IOS ACE from port names to port numbers
>>> ace = 'permit tcp any any range ftp-data ftp'
>>> PortTranslator(ace).translate_ace(acl_format='ios', conversion_type='to_number')
'permit tcp any any range 20 21'

# Translate an ASA ACE from port names to numbers
>>> ace = 'access-list test extended permit tcp any host 64.104.140.141 eq ssh'
>>> PortTranslator(ace).translate_ace(acl_format='asa', conversion_type='to_number')
'access-list test extended permit tcp any host 64.104.140.141 eq 22'

# Translate ASA ACE from port numbers to names
>>> ace = 'access-list test extended permit tcp any any range 80 81'
>>> PortTranslator(ace).translate_ace(acl_format='asa', conversion_type='to_name')
'access-list test extended permit tcp any any range www 81'
"""
import re
import json
import os
import logging
from cisco_acl.regexes import ace_match

logging.getLogger(__name__)

translation_file = os.path.join(os.path.dirname(__file__), 'port_translations.json')
with open(translation_file, mode='rt') as f:
    translation_groups = json.loads(f.read())


def translate_port(acl_format, protocol, ports, conversion_type):
    """
    Translate a port from name to number or vice versa 

    Args:
        acl_format (str): 'ios' or 'asa' 
        protocol (str): protocol from ACE
        ports (str): ports from ace (ex. '80', '80 443')
        conversion_type (str): 'to_name' or 'to_number'

    Returns:
        list: translated ports
    """

    def translate(port):
        if conversion_type == 'to_name':
            for port_name, num in translation_groups[acl_format][protocol].items():
                try:
                    if int(num) == int(port):
                        return port_name
                except:
                    return port

        elif conversion_type == 'to_number':
            logging.debug(list(translation_groups[acl_format][protocol].keys()))
            if port in translation_groups[acl_format][protocol]:
                return translation_groups[acl_format][protocol][port]

        return port

    translated_ports = [translate(port) for port in ports]

    if not translated_ports:
        return ports
    else:
        return translated_ports


class PortTranslator:
    def __init__(self, ace):
        self.ace = ace
        self.formats = ['ios', 'asa']
        self.permission = dict()
        self._parse_ace()

    def _parse_ace(self):
        """
        Parse an ACE using the cisco_acl.regexes library
        """
        permission = ace_match(self.ace)
        if not permission:
            raise SyntaxError('Invalid ACE: {0}'.format(self.ace))
        self.permission = permission

    def translate_ace(self, acl_format='ios', conversion_type='to_name'):
        """
        Translate ports in an ACE between names and numbers
        
        Args:
            acl_format (str): 'ios' or 'asa' 
            conversion_type (str): 'to_name' or 'to_number' 

        Returns:
            str: ace with ports translated
        """
        if self.permission['protocol'].lower() not in ['tcp', 'udp']:
            return self.ace

        if acl_format not in translation_groups:
            raise ValueError('ACL format "{0}" not in {1}'.format(acl_format, list(translation_groups.keys())))

        conversion_types = ['to_name', 'to_number']
        if conversion_type not in conversion_types:
            raise ValueError('Unknown conversion type: {0} Acceptable types: {1}'.format(
                conversion_type, conversion_types))

        # We have two possible conversions to make (source ports, destination ports)
        ports = [self.permission['source_ports'], self.permission['destination_ports']]

        line = self.ace

        for port in ports:
            if port is None:
                continue

            if re.match('^object-group', port, flags=re.I):
                continue

            port = port.lower()
            _ports = port.split()[1:]
            _translated_ports = translate_port(
                acl_format, self.permission['protocol'].lower(), _ports, conversion_type
            )
            if len(_translated_ports) > 1:
                _translated_ports = ' '.join(_translated_ports)
            else:
                _translated_ports = _translated_ports[0]

            if port.startswith('e'):  # eq
                line = re.sub(port, 'eq {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('gt'):  # gt
                line = re.sub(port, 'gt {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('ge'):  # ge
                line = re.sub(port, 'ge {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('lt'):  # lt
                line = re.sub(port, 'lt {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('le'):  # le
                line = re.sub(port, 'le {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('n'):  # neq
                line = re.sub(port, 'neq {}'.format(_translated_ports), line, flags=re.I)
            elif port.startswith('r'):  # range
                line = re.sub(port, 'range {}'.format(_translated_ports), line, flags=re.I)
            else:
                raise ValueError('Invalid Port: {0} in ACE: {1}'.format(port, self.ace))

        logging.debug('ACE "{0}" translated to "{1}"'.format(self.ace, line))
        return line
