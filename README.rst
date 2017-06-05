=========
cisco_acl
=========
Python module for working with Cisco ACLs

* Free software: MIT license

Features
--------
* acl_audit.py - A library to quickly perform a syntax and error check on Cisco ACLs
* convert_mask.py - A library for converting between mask types in Cisco ACLs (wildcard mask, subnet mask, cidr mask)
* port_translations.py - A library for converting port numbers in ACLs to/from name/numbers
* regexes.py - Regular expressions for parsing Cisco ACLs


Installation
------------

::

    git clone https://github.com/jj46/cisco_acl.git
    cd cisco_acl
    python3 -m pip install -e .

::

Usage
-----
ACL audit library

::

    $ cat testacl
    permit tcp any any eq 80
    permit tcp any host eq 22

    # Notice the 2nd line in the ACL above is invalid syntax

    $ python
    Python 3.6.1 (v3.6.1:69c0db5050, Mar 21 2017, 01:21:04)
    >>> from cisco_acl.acl_audit import AclAuditor
    >>> a = AclAuditor(acl='testacl')
    >>> for line_num, error in sorted(a.errors.items()):
    ...     print(line_num, error)
    ...
    2 Invalid ACE: permit tcp any host eq 22

::

ACL mask conversions library

::
    # Convert from wildcard to subnet mask
    >>> from cisco_acl import convert_mask
    >>> translate_mask(['permit tcp any 10.0.0.0 0.0.0.255'], 'wc', 'subnet')
    ['permit tcp any 10.0.0.0 255.255.255.0']

::

ACL port translations library

::

    >>> from cisco_acl.port_translations import PortTranslator
    >>> PortTranslator('permit tcp any any eq 80 443').translate_ace(acl_format='ios', conversion_type='to_name')
    'permit tcp any any eq www 443'

::

ACL regexes library

::

    >>> from cisco_acl.regexes import ace_match
    >>> from pprint import pprint
    >>> pprint(ace_match('permit tcp any any eq 80'))
    {'action': 'permit',
     'destination': 'any',
     'destination_ports': 'eq 80',
     'keyword': None,
     'name': None,
     'protocol': 'tcp',
     'sequence': None,
     'source': 'any',
     'source_ports': None}

    >>> ace_match('permit tcp host any eq 80')  # A bad ACE
    False

::

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage
