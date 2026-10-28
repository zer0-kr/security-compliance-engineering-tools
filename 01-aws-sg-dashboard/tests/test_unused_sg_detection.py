import subprocess

import pytest
import extract_and_visualize_v2
from extract_and_visualize_v2 import generate_nodes_and_edges, get_network_interfaces, ResourceData


def _sg_info(*sg_ids):
    return {
        sg_id: {
            'name': sg_id, 'vpc_id': 'vpc-1', 'account_id': '111',
            'region': 'ap-northeast-2', 'description': '', 'tags': {},
        }
        for sg_id in sg_ids
    }


def _sg_ref_rule(ref_sg_id):
    return {'IpProtocol': '-1', 'IpRanges': [], 'Ipv6Ranges': [],
            'UserIdGroupPairs': [{'GroupId': ref_sg_id}]}


def _sg_nodes(nodes):
    return {n['id']: n for n in nodes if n['group'] == 'sg'}


class TestUnusedSgDetection:

    def test_unattached_sgs_referencing_each_other_are_unused(self):
        sg_info = _sg_info('sg-orphan-referrer', 'sg-orphan-ref')
        sg_rules = {
            'sg-orphan-referrer': {'ingress': [_sg_ref_rule('sg-orphan-ref')], 'egress': []},
            'sg-orphan-ref': {'ingress': [], 'egress': []},
        }

        nodes, edges = generate_nodes_and_edges([], sg_info, sg_rules)
        sgs = _sg_nodes(nodes)

        assert sgs['sg-orphan-referrer']['is_unused'] is True
        assert sgs['sg-orphan-ref']['is_unused'] is True
        assert sgs['sg-orphan-ref']['referenced_by'] == ['sg-orphan-referrer']
        assert sgs['sg-orphan-referrer']['referenced_by'] == []
        # The SG-to-SG edge is still drawn
        assert {'from': 'sg-orphan-ref', 'to': 'sg-orphan-referrer',
                'label': 'ingress', 'dashes': True} in edges

    def test_egress_reference_recorded_in_referenced_by(self):
        sg_info = _sg_info('sg-a', 'sg-b', 'sg-c')
        sg_rules = {
            'sg-a': {'ingress': [], 'egress': [_sg_ref_rule('sg-c')]},
            'sg-b': {'ingress': [_sg_ref_rule('sg-c')], 'egress': []},
            'sg-c': {'ingress': [], 'egress': []},
        }

        nodes, _ = generate_nodes_and_edges([], sg_info, sg_rules)

        assert _sg_nodes(nodes)['sg-c']['referenced_by'] == ['sg-a', 'sg-b']

    def test_attached_via_resource_is_used(self):
        sg_info = _sg_info('sg-web')
        sg_rules = {'sg-web': {'ingress': [], 'egress': []}}
        resources = [ResourceData('ec2', {'i-1': {'name': 'web', 'vpc_id': 'vpc-1'}},
                                  {'i-1': ['sg-web']})]

        nodes, edges = generate_nodes_and_edges(resources, sg_info, sg_rules)

        assert _sg_nodes(nodes)['sg-web']['is_unused'] is False
        assert {'from': 'i-1', 'to': 'sg-web', 'label': 'uses'} in edges

    def test_attached_via_eni_is_used(self):
        sg_info = _sg_info('sg-eni', 'sg-idle')
        sg_rules = {'sg-eni': {'ingress': [], 'egress': []},
                    'sg-idle': {'ingress': [], 'egress': []}}

        nodes, _ = generate_nodes_and_edges([], sg_info, sg_rules, extra_used_sgs={'sg-eni'})
        sgs = _sg_nodes(nodes)

        assert sgs['sg-eni']['is_unused'] is False
        assert sgs['sg-idle']['is_unused'] is True

    def test_used_sg_referencing_unattached_sg_does_not_mark_it_used(self):
        sg_info = _sg_info('sg-app', 'sg-old-lb')
        sg_rules = {
            'sg-app': {'ingress': [_sg_ref_rule('sg-old-lb')], 'egress': []},
            'sg-old-lb': {'ingress': [], 'egress': []},
        }

        nodes, _ = generate_nodes_and_edges([], sg_info, sg_rules, extra_used_sgs={'sg-app'})
        sgs = _sg_nodes(nodes)

        assert sgs['sg-app']['is_unused'] is False
        assert sgs['sg-old-lb']['is_unused'] is True
        assert sgs['sg-old-lb']['referenced_by'] == ['sg-app']

    def test_self_reference_excluded(self):
        sg_info = _sg_info('sg-self')
        sg_rules = {'sg-self': {'ingress': [_sg_ref_rule('sg-self')],
                                'egress': [_sg_ref_rule('sg-self')]}}

        nodes, _ = generate_nodes_and_edges([], sg_info, sg_rules)
        node = _sg_nodes(nodes)['sg-self']

        assert node['referenced_by'] == []
        assert node['is_unused'] is True

    def test_precomputed_referenced_by_map_is_used(self):
        # collect_multi_account_data builds the map over all accounts, so a
        # reference from another account's SG shows up here
        sg_info = _sg_info('sg-shared')
        sg_rules = {'sg-shared': {'ingress': [], 'egress': []}}

        nodes, _ = generate_nodes_and_edges([], sg_info, sg_rules,
                                            referenced_by_map={'sg-shared': ['sg-other-acct']})

        assert _sg_nodes(nodes)['sg-shared']['referenced_by'] == ['sg-other-acct']

    def test_sg_node_carries_region(self):
        sg_info = _sg_info('sg-r')
        nodes, _ = generate_nodes_and_edges([], sg_info, {'sg-r': {'ingress': [], 'egress': []}})

        assert _sg_nodes(nodes)['sg-r']['region'] == 'ap-northeast-2'


class TestGetNetworkInterfaces:

    def test_returns_every_eni(self, monkeypatch):
        rows = [
            {'network_interface_id': 'eni-nat', 'account_id': '111',
             'groups': [{'GroupId': 'sg-nat'}]},
            {'network_interface_id': 'eni-ec2-secondary', 'account_id': '111',
             'groups': [{'GroupId': 'sg-secondary'}, {'GroupId': 'sg-other'}]},
            {'network_interface_id': 'eni-other-vpc', 'account_id': '222',
             'groups': [{'GroupId': 'sg-x'}]},
        ]
        monkeypatch.setattr(extract_and_visualize_v2, 'run_steampipe_query',
                            lambda query: {'rows': rows})

        eni_sg_map = get_network_interfaces()

        assert eni_sg_map == {'eni-nat': ['sg-nat'],
                              'eni-ec2-secondary': ['sg-secondary', 'sg-other'],
                              'eni-other-vpc': ['sg-x']}

    def test_query_failure_propagates(self, monkeypatch):
        def _fail(query):
            raise subprocess.CalledProcessError(1, 'steampipe')
        monkeypatch.setattr(extract_and_visualize_v2, 'run_steampipe_query', _fail)

        with pytest.raises(subprocess.CalledProcessError):
            get_network_interfaces()
