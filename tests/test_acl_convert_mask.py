from cisco_acl.convert_mask import translate_mask


def test_convert_mask():
    aces_with_wildcard = [
        'permit tcp 172.30.1.0 0.0.0.255 any eq 443',
    ]

    aces_with_hostmask = [
        'permit tcp 172.30.1.0 255.255.255.0 any eq 443',
    ]

    aces_with_cidr = [
        'permit tcp 172.30.1.0/24 any eq 443'
    ]

    assert translate_mask(aces_with_wildcard, 'wc', 'cidr')[0] == aces_with_cidr[0]
    assert translate_mask(aces_with_wildcard, 'wc', 'subnet')[0] == aces_with_hostmask[0]
    assert translate_mask(aces_with_hostmask, 'subnet', 'cidr')[0] == aces_with_cidr[0]
    assert translate_mask(aces_with_hostmask, 'subnet', 'wc')[0] == aces_with_wildcard[0]
