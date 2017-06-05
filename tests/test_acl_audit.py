import os.path
from cisco_acl.acl_audit import AclAuditor


def test_acl_audit():
    aclfile = os.path.join(os.path.dirname(__file__), 'data/acl2')
    a = AclAuditor(acl=aclfile)
    assert a.errors[9].startswith('Invalid ACE')
    assert a.errors[11].startswith('Invalid subnet')
    assert a.errors[12].startswith('Invalid host IP')
    assert a.errors[13].startswith('Invalid port')

