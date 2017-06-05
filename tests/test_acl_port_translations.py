from cisco_acl.port_translations import PortTranslator


def test_port_translator():
    line = 'permit tcp any any eq 80 443'
    translated = 'permit tcp any any eq www 443'
    assert PortTranslator(line).translate_ace(acl_format='ios', conversion_type='to_name') == translated

    line = 'permit tcp any any range ftp-data ftp'
    translated = 'permit tcp any any range 20 21'
    assert PortTranslator(line).translate_ace(acl_format='ios', conversion_type='to_number') == translated

    line = 'access-list firewall_outbound_acl extended permit tcp any host 1.1.1.1 eq ssh'
    translated = 'access-list firewall_outbound_acl extended permit tcp any host 1.1.1.1 eq 22'
    assert PortTranslator(line).translate_ace(acl_format='asa', conversion_type='to_number') == translated

    line = 'access-list test extended permit tcp any any eq 443'
    translated = 'access-list test extended permit tcp any any eq https'
    assert PortTranslator(line).translate_ace(acl_format='asa', conversion_type='to_name') == translated
