"""
Cisco ACL regex helper library for parsing IOS/ASA ACLs

Examples:
    >>> re.match(ip_address_rx, '1.1.1.1')
    <_sre.SRE_Match object; span=(0, 7), match='1.1.1.1'>
    >>> re.match(ip_address_rx, '2001:420:210d::a')
    <_sre.SRE_Match object; span=(0, 16), match='2001:420:210d::a'>
    >>> ace_match('permit tcp any host 1.1.1.1 eq 80')['destination']
    'host 1.1.1.1'
    >>> ace_match('permit tcp any host 2001:420:210d::a eq 80')['destination']
    'host 2001:420:210d::a'
    >>> ace_match('permit tcp any host www.cisco.com eq 80')['destination']
    'host www.cisco.com'
    >>> re.match(host_or_network_rx, 'host 1.1.1.1')
    <_sre.SRE_Match object; span=(0, 12), match='host 1.1.1.1'>
    >>> re.match(host_or_network_rx, 'host 2001:420:210d::a')
    <_sre.SRE_Match object; span=(0, 21), match='host 2001:420:210d::a'>
"""
import re

# Regular expressions for parsing IPv4/6 addresses
ipv4_address_rx = (
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
)
ipv6_address_rx = (
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){6}'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|\:\:'
    r'(?:[0-9A-Fa-f]{1,4}\:){5}(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:[0-9A-Fa-f]{1,4})?\:\:(?:[0-9A-Fa-f]{1,4}\:){4}'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4})?\:\:'
    r'(?:[0-9A-Fa-f]{1,4}\:){3}'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){,2}[0-9A-Fa-f]{1,4})?\:\:'
    r'(?:[0-9A-Fa-f]{1,4}\:){2}(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){,3}[0-9A-Fa-f]{1,4})?\:\:[0-9A-Fa-f]{1,4}\:'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){,4}[0-9A-Fa-f]{1,4})?\:\:'
    r'(?:[0-9A-Fa-f]{1,4}\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}'
    r'(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){,5}[0-9A-Fa-f]{1,4})?\:\:[0-9A-Fa-f]{1,4}|'
    r'(?:'
    r'(?:[0-9A-Fa-f]{1,4}\:){,6}[0-9A-Fa-f]{1,4})?\:\:)'
)

ip_address_rx = r'({0}|{1})'.format(ipv4_address_rx, ipv6_address_rx)
subnet_rx = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

# Regular expressions for processing Cisco ACL data
# DNS names using the 'host' keyword
dnsname_rx = r'[A-Za-z0-9\-\.\_]+'
# Remarks in Cisco ASA
asa_remark = r'(^access-list\s+([A-Za-z0-9\-_]+)\s+(?:\s+line\s+\d+\s+)?extended\s+remark)'

# ACE protocol
protocol_rx = (
    r'(?:ahp|eigrp|esp|gre|icmp|igmp|ip|object-group|ospf|pcp|pim|tcp|udp|\d{1,3})'
    r'|'
    r'(?:object-group\s+[A-Za-z0-9\-\.\_\:]+)'
)

# ACE source/destination network
host_or_network_rx = (
    r'(?:host\s+({ip_rx}|[A-Za-z0-9\-\.]+))'
    r'|'
    r'(?:({net_rx}))'
    r'|'
    r'(?:any|any4)'
    r'|'
    r'(?:object-group\s+[A-Za-z0-9\-\.\_\:]+)'
    r'|'
    r'(?:addrgroup\s+[A-Za-z0-9\-\.\_]+)'
    r'|'.format(ip_rx=ip_address_rx, net_rx=subnet_rx)
)

# ACE source/destination ports
ports_rx = (
    r'(?:(?:e(?:q)?|gt|lt|ne|le|ge)\s+(?:\d{1,5}|[A-Za-z0-9\-](?:\s+)?)+)'
    r'|'
    r'(?:r(a|an|ang|ange)?\s+(?:[A-Za-z0-9\-]+)\s+(?:[A-Za-z0-9\-]+))'
    r'|'
    r'(?:object-group\s+[A-Za-z0-9\-\.\_]+)'
    r'|'
    r'(?:port-group\s+[A-Za-z0-9\-\.\_]+)'
)

# ACE keywords
keyword_rx = (
    r'(?:established|echo(?:-reply)?|time-exceeded|unreachable|log)'
)

# Full ACE regex
cisco_acl_regex = (
    r'((?P<sequence>\d+)\s+)?'
    r'(?:access-list\s+(?P<name>[A-Za-z0-9\-\_]+)\s+(?:\s+line\s+\d+\s+)?extended\s+)?'
    r'(?P<action>permit|deny)'  # action
    r'\s+'
    r'(?P<protocol>{pro_rx})'  # protocol
    r'\s+'
    r'(?P<source>{net_rx})'  # source network
    r'(?:\s+(?P<source_ports>{prt_rx}))?'  # source ports
    r'\s+'
    r'(?P<destination>{net_rx})'  # destination network
    r'(?:\s+)?'
    r'(?:\s+(?P<destination_ports>{prt_rx}))?'  # destination ports
    r'(?:\s+(?P<keyword>{key_rx}))?'  # keywords (ex. established)
    r'(?:\(hitcnt=\d+\)\s+[A-Za-z0-9]+)?'  # (hitcnt=0) 0x0540b3cb
    r'$'.format(
        pro_rx=protocol_rx,
        net_rx=host_or_network_rx,
        prt_rx=ports_rx,
        key_rx=keyword_rx
    )
)


# Simple function for checking if an ACE matches our regexes above
def ace_match(ace):
    """
    Check if an ACE matches our ACE regex

    Args:
        ace (str): Access control entry

    Returns:
        permission (dict): dictionary of permission details, false otherwise

    Examples:
        >>> from pprint import pprint
        >>> pprint(ace_match('permit tcp any any eq 443'))
        {'action': 'permit',
         'destination': 'any',
         'destination_ports': 'eq 443',
         'keyword': None,
         'name': None,
         'protocol': 'tcp',
         'sequence': None,
         'source': 'any',
         'source_ports': None}
    """
    re_obj = re.compile(cisco_acl_regex, re.I)
    match = re_obj.match(ace.lower())
    if match:
        return match.groupdict()
    else:
        return False
