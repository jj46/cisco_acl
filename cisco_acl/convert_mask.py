import ipaddress
import re
from cisco_acl.regexes import ace_match


def translate_mask(acl_lines, from_type, to_type):
    """ Translate between various mask definitions in ACEs
    
    Args:
        acl_lines: list of ACEs
        from_type: "wc" or "subnet"
        to_type: "wc", "subnet", or "cidr"

    Returns:
        list of ACEs with subnet masks translated
        
    Examples:
        >>> acl_lines = ['permit tcp 10.0.1.0 0.0.0.255 any eq 443']
        >>> translate_mask(acl_lines, 'wc', 'subnet')
        ['permit tcp 10.0.1.0 255.255.255.0 any eq 443']
        >>> translate_mask(acl_lines, 'wc', 'cidr')
        ['permit tcp 10.0.1.0/24 any eq 443']
        >>> acl_lines = ['permit tcp 172.16.1.0 255.255.255.0 any eq 80']
        >>> translate_mask(acl_lines, 'subnet', 'wc')
        ['permit tcp 172.16.1.0 0.0.0.255 any eq 80']
        >>> translate_mask(acl_lines, 'subnet', 'cidr')
        ['permit tcp 172.16.1.0/24 any eq 80']
    """

    output_lines = []
    types = ['wc', 'subnet', 'cidr']
    if from_type not in types or to_type not in types:
        raise TypeError

    # determine if we have a subnet in the ACL line
    subnet_regex = '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    subnets_to_process = {}

    for acl_line in acl_lines:
        output_line = acl_line
        m = ace_match(acl_line.strip())
        if m:
            source_host = m['source']
            destination_host = m['destination']

            for network in [source_host, destination_host]:
                if re.match(subnet_regex, network):
                    try:
                        ip_object = ipaddress.ip_network('/'.join(network.split()))
                        subnets_to_process[network] = ip_object
                    except ValueError as e:
                        continue

        for subnet in subnets_to_process:
            if from_type == 'wc' and to_type == 'cidr':
                output_line = re.sub(subnet, subnets_to_process[subnet].with_prefixlen, output_line)
            elif from_type == 'wc' and to_type == 'subnet':
                output_line = re.sub(subnet, ' '.join(subnets_to_process[subnet].with_netmask.split('/')), output_line)
            elif from_type == 'subnet' and to_type == 'wc':
                output_line = re.sub(subnet, ' '.join(subnets_to_process[subnet].with_hostmask.split('/')), output_line)
            elif from_type == 'subnet' and to_type == 'cidr':
                output_line = re.sub(subnet, subnets_to_process[subnet].with_prefixlen, output_line)

        output_lines.append(output_line)
    return output_lines
