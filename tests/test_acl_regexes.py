#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_acl_regexes
----------------------------------

Tests for `regexes` module.
"""

import os
from cisco_acl.regexes import ace_match


def test_acl_regexes():
    acl_file = os.path.join(os.path.dirname(__file__), 'data/acl1')

    with open(acl_file) as f:
        acl_lines = f.readlines()

    for line in acl_lines:
        # allow for comments
        if line.startswith('#') or line.startswith('!'):
            continue
        assert ace_match(line)


def test_bad_ace():
    ace = 'permit tcp any host eq 80'
    assert ace_match(ace) is False
