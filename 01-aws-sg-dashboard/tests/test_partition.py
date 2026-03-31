import pytest
from extract_and_visualize_v2 import _partition_by_account


class TestPartitionByAccount:

    def test_simple_prefix_split(self):
        info_dict = {
            '123456||my-rds': {'account_id': '123456', 'name': 'my-rds'},
        }
        sg_map = {
            '123456||my-rds': ['sg-aaa'],
        }
        result = _partition_by_account(info_dict, sg_map)

        assert '123456' in result
        acct_info, acct_sg = result['123456']
        assert 'my-rds' in acct_info
        assert 'my-rds' in acct_sg
        assert acct_sg['my-rds'] == ['sg-aaa']

    def test_arn_with_colons_preserved(self):
        arn = 'arn:aws:lambda:ap-northeast-2:123456789012:function:myFunc'
        prefixed = '123456789012||' + arn
        info_dict = {
            prefixed: {'account_id': '123456789012', 'name': 'myFunc'},
        }
        sg_map = {
            prefixed: ['sg-lamb'],
        }
        result = _partition_by_account(info_dict, sg_map)

        acct_info, acct_sg = result['123456789012']
        assert arn in acct_info
        assert arn in acct_sg

    def test_no_prefix(self):
        info_dict = {
            'sg-abc123': {'account_id': '111111', 'name': 'test-sg'},
        }
        sg_map = {}
        result = _partition_by_account(info_dict, sg_map)

        assert '111111' in result
        acct_info, _ = result['111111']
        assert 'sg-abc123' in acct_info

    def test_multiple_accounts(self):
        info_dict = {
            '111||res-a': {'account_id': '111', 'name': 'a'},
            '222||res-b': {'account_id': '222', 'name': 'b'},
        }
        sg_map = {
            '111||res-a': ['sg-1'],
            '222||res-b': ['sg-2'],
        }
        result = _partition_by_account(info_dict, sg_map)

        assert len(result) == 2
        assert '111' in result
        assert '222' in result
        assert 'res-a' in result['111'][0]
        assert 'res-b' in result['222'][0]

    def test_empty_input(self):
        result = _partition_by_account({}, {})
        assert result == {}
