import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest


def _ingress_rule(protocol, from_port, to_port, cidr='0.0.0.0/0', ipv6_cidr=None):
    rule = {
        'IpProtocol': str(protocol),
        'FromPort': from_port,
        'ToPort': to_port,
        'IpRanges': [{'CidrIp': cidr}] if cidr else [],
        'Ipv6Ranges': [],
    }
    if ipv6_cidr:
        rule['Ipv6Ranges'] = [{'CidrIpv6': ipv6_cidr}]
    return rule


@pytest.fixture
def make_sg_rules():
    def _factory(sg_id, ingress_list, egress_list=None):
        return {sg_id: {'ingress': ingress_list, 'egress': egress_list or []}}
    return _factory


@pytest.fixture
def ingress_rule():
    return _ingress_rule


@pytest.fixture
def egress_rule():
    return _ingress_rule
