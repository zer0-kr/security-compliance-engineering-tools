import pytest
from extract_and_visualize_v2 import get_aws_profiles, filter_profiles


@pytest.fixture
def aws_files(tmp_path, monkeypatch):
    credentials = tmp_path / 'credentials'
    config = tmp_path / 'config'
    monkeypatch.setenv('AWS_SHARED_CREDENTIALS_FILE', str(credentials))
    monkeypatch.setenv('AWS_CONFIG_FILE', str(config))
    return credentials, config


class TestGetAwsProfiles:

    def test_config_only_sso(self, aws_files):
        _, config = aws_files
        config.write_text(
            '[default]\n'
            'region = ap-northeast-2\n'
            '\n'
            '[sso-session corp]\n'
            'sso_start_url = https://example.awsapps.com/start\n'
            '\n'
            '[profile prod]\n'
            'sso_session = corp\n'
            '\n'
            '[profile dev]\n'
            'sso_session = corp\n'
        )

        assert get_aws_profiles() == ['default', 'prod', 'dev']

    def test_credentials_only(self, aws_files):
        credentials, _ = aws_files
        credentials.write_text(
            '[default]\n'
            'aws_access_key_id = x\n'
            '[staging]\n'
            'aws_access_key_id = y\n'
        )

        assert get_aws_profiles() == ['default', 'staging']

    def test_both_files_deduped_in_order(self, aws_files):
        credentials, config = aws_files
        credentials.write_text('[default]\n[prod]\n')
        config.write_text('[default]\n[profile prod]\n[profile dev]\n')

        assert get_aws_profiles() == ['default', 'prod', 'dev']

    def test_ignores_non_profile_config_sections(self, aws_files):
        _, config = aws_files
        config.write_text('[sso-session corp]\n[services local]\n[profile prod]\n')

        assert get_aws_profiles() == ['prod']

    def test_no_files(self, aws_files):
        assert get_aws_profiles() == []


class TestFilterProfiles:

    def test_no_filters(self):
        assert filter_profiles(['a', 'b']) == (['a', 'b'], [])

    def test_include_keeps_discovery_order(self):
        assert filter_profiles(['a', 'b', 'c'], include=['c', 'a']) == (['a', 'c'], [])

    def test_include_reports_missing(self):
        selected, missing = filter_profiles(['a', 'b'], include=['a', 'zzz'])
        assert selected == ['a']
        assert missing == ['zzz']

    def test_exclude(self):
        assert filter_profiles(['a', 'b', 'c'], exclude=['b']) == (['a', 'c'], [])

    def test_include_and_exclude(self):
        assert filter_profiles(['a', 'b', 'c'], include=['a', 'b'], exclude=['b']) == (['a'], [])
