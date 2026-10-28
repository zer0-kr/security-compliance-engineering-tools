import pytest
import extract_and_visualize_v2 as m


_EMPTY_RESOURCE_GETTERS = (
    'get_ec2_instances', 'get_rds_instances', 'get_load_balancers', 'get_vpc_endpoints',
    'get_lambda_functions', 'get_elasticache_clusters', 'get_elasticache_replication_groups',
    'get_ecs_services', 'get_redshift_clusters', 'get_opensearch_domains', 'get_docdb_clusters',
    'get_neptune_clusters', 'get_memorydb_clusters', 'get_eks_clusters', 'get_efs_mount_targets',
)

_ACCOUNTS = {
    '111': {'profile_name': 'a', 'account_id': '111', 'account_name': 'a'},
    '222': {'profile_name': 'b', 'account_id': '222', 'account_name': 'b'},
    '333': {'profile_name': 'c', 'account_id': '333', 'account_name': 'c'},
}


def _sg(acct):
    return {'name': 'x', 'vpc_id': 'vpc-1', 'account_id': acct, 'region': 'r',
            'description': '', 'tags': {}}


@pytest.fixture
def stub_collection(monkeypatch):
    """Replace every AWS / Steampipe call with in-memory data."""
    monkeypatch.setattr(m, 'get_aws_profiles', lambda: ['a', 'b', 'c'])
    monkeypatch.setattr(m, 'check_aws_cli_auth', lambda p, region=None: list(p))
    monkeypatch.setattr(m, 'setup_aggregator_config', lambda *a, **k: None)
    monkeypatch.setattr(m, 'reload_steampipe_service', lambda: None)
    # The aggregator (e.g. an existing config with --skip-config) returns all three accounts
    monkeypatch.setattr(m, 'get_all_account_identities',
                        lambda p: {k: dict(v) for k, v in _ACCOUNTS.items()})
    monkeypatch.setattr(m, 'get_vpc_info', lambda: {})
    for name in _EMPTY_RESOURCE_GETTERS:
        monkeypatch.setattr(m, name, lambda *a, **k: ({}, {}))
    monkeypatch.setattr(m, '_fetch_elasticache_shared_data', lambda p: ({}, {}))
    monkeypatch.setattr(m, '_run_query_with_connection_fallback', lambda q, p: {'rows': []})
    monkeypatch.setattr(m, 'get_security_groups_and_rules', lambda v: (
        {'sg-a1': _sg('111'), 'sg-a2-shared': _sg('111'), 'sg-a3-idle': _sg('111'),
         'sg-b1': _sg('222'), 'sg-c1': _sg('333')},
        {'sg-b1': {'ingress': [{'IpProtocol': '-1', 'IpRanges': [], 'Ipv6Ranges': [],
                                'UserIdGroupPairs': [{'GroupId': 'sg-a3-idle'}]}],
                   'egress': []}},
    ))
    # eni-b lives in account 222 but uses sg-a2-shared, owned by 111 (VPC sharing)
    monkeypatch.setattr(m, 'get_network_interfaces', lambda: {
        'eni-a': ['sg-a1'], 'eni-b': ['sg-b1', 'sg-a2-shared']})
    return monkeypatch


def _sg_nodes(data):
    return {n['id']: n for n in data['nodes'] if n['group'] == 'sg'}


class TestCollectMultiAccountData:

    def test_sg_used_only_by_other_accounts_eni_is_in_use(self, stub_collection):
        data = m.collect_multi_account_data(m.parse_args([]))
        sgs = _sg_nodes(data)

        assert sgs['a:sg-a2-shared']['is_unused'] is False
        assert sgs['a:sg-a1']['is_unused'] is False
        assert sgs['a:sg-a3-idle']['is_unused'] is True
        assert sgs['c:sg-c1']['is_unused'] is True

    def test_referenced_by_includes_other_accounts(self, stub_collection):
        data = m.collect_multi_account_data(m.parse_args([]))

        assert _sg_nodes(data)['a:sg-a3-idle']['referenced_by'] == ['sg-b1']

    def test_skip_config_respects_profiles_filter(self, stub_collection):
        data = m.collect_multi_account_data(m.parse_args(['--profiles', 'a', '--skip-config']))

        assert set(data['account_info']) == {'a'}
        assert {n['profile_name'] for n in data['nodes']} == {'a'}

    def test_skip_config_respects_exclude_profiles(self, stub_collection):
        data = m.collect_multi_account_data(
            m.parse_args(['--exclude-profiles', 'b', '--skip-config']))

        assert set(data['account_info']) == {'a', 'c'}

    def test_eni_query_failure_aborts(self, stub_collection):
        def _fail():
            raise RuntimeError('steampipe error')
        stub_collection.setattr(m, 'get_network_interfaces', _fail)

        with pytest.raises(SystemExit) as exc:
            m.collect_multi_account_data(m.parse_args([]))
        assert exc.value.code == 1

    def test_unknown_requested_profile_aborts(self, stub_collection):
        with pytest.raises(SystemExit) as exc:
            m.collect_multi_account_data(m.parse_args(['--profiles', 'a', 'nope']))
        assert exc.value.code == 1

    def test_unknown_excluded_profile_warns(self, stub_collection, caplog):
        with caplog.at_level('WARNING', logger=m.logger.name):
            m.collect_multi_account_data(m.parse_args(['--exclude-profiles', 'nope']))

        assert any('nope' in r.getMessage() for r in caplog.records)
