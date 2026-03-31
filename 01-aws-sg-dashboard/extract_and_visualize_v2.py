#!/usr/bin/env python3
"""
Security Group Review Dashboard - Multi-Account Template-based Generator
멀티 어카운트 환경에서 모든 AWS 프로파일의 SG 정보를 한번에 수집
"""

import subprocess
import json
import sys
import re
import os
import time
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# 취약 정책 탐지 상수
SAFE_PUBLIC_PORTS = {80, 443}

SENSITIVE_PORTS = {
    22: ('SSH', 'critical'), 3389: ('RDP', 'critical'),
    3306: ('MySQL', 'critical'), 5432: ('PostgreSQL', 'critical'),
    1433: ('MSSQL', 'critical'), 1521: ('Oracle', 'critical'),
    6379: ('Redis', 'critical'), 27017: ('MongoDB', 'critical'),
    9200: ('Elasticsearch', 'high'), 5601: ('Kibana', 'high'),
    8080: ('HTTP-Alt', 'high'), 8443: ('HTTPS-Alt', 'high'),
    21: ('FTP', 'high'), 23: ('Telnet', 'critical'),
    445: ('SMB', 'critical'), 135: ('RPC', 'critical')
}


ResourceData = namedtuple('ResourceData', ['type', 'info', 'sg_map'])

# 리소스별 추가 필드 (제네릭 루프에서 노드에 복사)
_PASSTHROUGH_KEYS = ('lb_type', 'engine', 'instance_state')

def detect_sg_vulnerabilities(sg_rules):
    """각 SG의 ingress 규칙을 분석하여 취약점 목록 반환.
    Returns: {sg_id: [{'port': str, 'protocol': str, 'service': str, 'source': str, 'severity': str}, ...]}
    """
    vulnerabilities = {}

    for sg_id, rules in sg_rules.items():
        sg_vulns = []

        for rule in rules.get('ingress', []):
            protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')

            # 공개 소스 확인 (0.0.0.0/0 또는 ::/0)
            open_sources = []
            for r in (rule.get('IpRanges') or []):
                if r.get('CidrIp') == '0.0.0.0/0':
                    open_sources.append('0.0.0.0/0')
            for r in (rule.get('Ipv6Ranges') or []):
                if r.get('CidrIpv6') == '::/0':
                    open_sources.append('::/0')

            if not open_sources:
                continue

            source = open_sources[0]

            # All Traffic (IpProtocol == -1)
            if str(protocol) == '-1':
                for src in open_sources:
                    sg_vulns.append({
                        'port': 'ALL', 'protocol': 'ALL',
                        'service': 'All Traffic', 'source': src,
                        'severity': 'critical'
                    })
                continue

            # 포트 범위가 없는 경우 (ICMP 등) 건너뜀
            if from_port is None or to_port is None:
                continue

            from_port = int(from_port)
            to_port = int(to_port)

            # 안전한 포트만 열린 경우 건너뜀
            if from_port == to_port and from_port in SAFE_PUBLIC_PORTS:
                continue

            # 민감 포트 탐지
            for port, (service, severity) in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    proto_str = 'TCP' if str(protocol) == '6' else str(protocol).upper()
                    for src in open_sources:
                        sg_vulns.append({
                            'port': str(port), 'protocol': proto_str,
                            'service': service, 'source': src,
                            'severity': severity
                        })

            # 넓은 범위 (0-65535 등)에서 안전 포트만 제외하고도 민감 포트가 없으면
            # 넓은 범위 자체가 위험 — 위에서 이미 민감 포트 매칭했으므로 추가 불필요

        if sg_vulns:
            vulnerabilities[sg_id] = sg_vulns

    return vulnerabilities


# ElastiCache Replication Group 쿼리
RG_QUERY = """
    SELECT replication_group_id, description, cache_node_type, member_clusters, account_id
    FROM aws_elasticache_replication_group
"""

def get_aws_profiles():
    """~/.aws/credentials에서 모든 AWS 프로파일 발견"""
    credentials_path = os.path.expanduser('~/.aws/credentials')

    if not os.path.exists(credentials_path):
        print(f"⚠️  ~/.aws/credentials 파일을 찾을 수 없습니다")
        return []

    profiles = []
    with open(credentials_path, 'r') as f:
        for line in f:
            match = re.match(r'^\[([^\]]+)\]', line.strip())
            if match:
                profile_name = match.group(1)
                # 'default' 프로파일은 이름 없이 사용됨
                if profile_name == 'default':
                    profiles.append('default')
                else:
                    profiles.append(profile_name)

    return profiles

def setup_aggregator_config(profiles):
    """Steampipe AWS aggregator 설정 생성 (모든 프로파일을 1개 aggregator로 통합)"""
    config_path = os.path.expanduser('~/.steampipe/config/aws.spc')

    config_parts = []
    for profile in profiles:
        conn_name = f"aws_{profile}"
        config_parts.append(f'''connection "{conn_name}" {{
  plugin  = "aws"
  profile = "{profile}"
  regions = ["ap-northeast-2"]
}}''')

    # Aggregator connection named "aws" — uses default search path
    config_parts.append('''connection "aws" {
  plugin      = "aws"
  type        = "aggregator"
  connections = ["aws_*"]
}''')

    config_content = '\n\n'.join(config_parts) + '\n'

    with open(config_path, 'w') as f:
        f.write(config_content)

    print(f"   ✓ Steampipe aggregator 설정 완료: {', '.join(profiles)} → aws (aggregator)")

def reload_steampipe_service():
    """Steampipe 서비스 stop+start로 새 설정 적용 (unknown state 대응 포함)"""
    # 1차: stop --force
    subprocess.run(
        ['steampipe', 'service', 'stop', '--force'],
        capture_output=True, check=False
    )
    time.sleep(2)

    # 2차: start 시도
    result = subprocess.run(
        ['steampipe', 'service', 'start'],
        capture_output=True, text=True
    )

    if result.returncode != 0:
        # unknown state → 프로세스 직접 kill 후 재시도
        if 'unknown state' in result.stderr or 'unknown state' in result.stdout:
            print(f"   ⚠️  Steampipe unknown state 감지, 프로세스 강제 종료 중...")
            subprocess.run(['pkill', '-9', '-f', 'steampipe'], capture_output=True, check=False)
            time.sleep(2)
            subprocess.run(
                ['steampipe', 'service', 'start'],
                capture_output=True, check=True
            )
        else:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

    time.sleep(3)
    print(f"   ✓ Steampipe 서비스 재시작 완료")

def run_steampipe_query(query):
    """Steampipe 쿼리 실행"""
    try:
        result = subprocess.run(
            ['steampipe', 'query', query, '--output', 'json'],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"   ❌ 쿼리 실행 실패: {e.stderr}")
        raise
    except json.JSONDecodeError as e:
        print(f"   ❌ JSON 파싱 실패: {e}")
        raise

def check_aws_cli_auth(profiles):
    """AWS CLI 인증 확인 (프로파일별). 인증 성공한 프로파일 목록 반환."""
    print(f"\n   🔍 AWS CLI 인증 확인 중...")
    auth_ok = []
    for profile in profiles:
        try:
            result = subprocess.run(
                ['aws', 'sts', 'get-caller-identity', '--profile', profile, '--region', 'ap-northeast-2'],
                capture_output=True, text=True, check=True, timeout=30
            )
            identity = json.loads(result.stdout)
            print(f"   ✓ {profile}: {identity.get('Account')}")
            auth_ok.append(profile)
        except subprocess.TimeoutExpired:
            print(f"   ❌ {profile}: 타임아웃")
        except subprocess.CalledProcessError as e:
            print(f"   ❌ {profile}: 인증 실패 - {e.stderr.strip()}")
        except json.JSONDecodeError:
            print(f"   ❌ {profile}: 응답 파싱 실패")
    return auth_ok

def get_all_account_identities(auth_ok_profiles):
    """Aggregator로 계정 메타데이터 일괄 조회.
    Returns: {account_id: {profile_name, account_id, account_name}}
    """
    print(f"\n   🔍 Steampipe aggregator로 계정 정보 조회 중...")
    try:
        account_query = """
            SELECT account_id, account_aliases,
                   _ctx ->> 'connection_name' as connection_name
            FROM aws_account
        """
        account_result = run_steampipe_query(account_query)

        accounts = {}
        for row in account_result.get('rows', []):
            account_id = row['account_id']
            connection_name = row.get('connection_name', '')

            # connection_name에서 profile 추출: 'aws_damoa' → 'damoa'
            profile_name = connection_name.replace('aws_', '', 1) if connection_name.startswith('aws_') else connection_name

            account_aliases = row.get('account_aliases')
            if account_aliases and len(account_aliases) > 0:
                account_name = account_aliases[0]
            else:
                account_name = profile_name

            if not account_name or account_name.strip() == '':
                account_name = profile_name

            accounts[account_id] = {
                'profile_name': profile_name,
                'account_id': account_id,
                'account_name': account_name
            }
            print(f"   ✓ 계정 확인: {account_name} ({account_id}) [connection: {connection_name}]")

        # 부분 실패 감지
        if len(accounts) < len(auth_ok_profiles):
            found_profiles = {a['profile_name'] for a in accounts.values()}
            missing = [p for p in auth_ok_profiles if p not in found_profiles]
            if missing:
                print(f"   ⚠️  누락된 프로파일: {', '.join(missing)}")

        return accounts

    except Exception as e:
        print(f"   ❌ Steampipe 계정 조회 실패: {e}")
        return {}

def get_vpc_info():
    """VPC 정보 가져오기 (aggregator: 모든 계정 동시 조회).
    Returns: {account_id: {vpc_id: {name, color}}}
    """
    # 1개 쿼리: VPC 발견 (EC2 + SG의 VPC를 UNION으로 한번에) + account_id
    vpc_discovery_query = """
        SELECT DISTINCT vpc_id, account_id FROM aws_ec2_instance WHERE vpc_id IS NOT NULL
        UNION
        SELECT DISTINCT vpc_id, account_id FROM aws_vpc_security_group WHERE vpc_id IS NOT NULL
    """
    result = run_steampipe_query(vpc_discovery_query)

    # account_id별로 vpc_id 그룹핑
    vpcs_by_account = defaultdict(set)
    for row in result.get('rows', []):
        vpcs_by_account[row['account_id']].add(row['vpc_id'])

    # 1개 쿼리: 전체 VPC 이름 (N+1 제거) + account_id
    vpc_names_query = "SELECT vpc_id, account_id, tags ->> 'Name' as vpc_name FROM aws_vpc"
    vpc_names_result = run_steampipe_query(vpc_names_query)
    vpc_names = {(row['account_id'], row['vpc_id']): row.get('vpc_name') or row['vpc_id']
                 for row in vpc_names_result.get('rows', [])}

    # 계정별 VPC 색상 할당 (per-account 독립적 — 기존 per-profile 동작 유지)
    colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2']
    all_vpc_info = {}
    for account_id, vpc_ids in vpcs_by_account.items():
        account_vpcs = {}
        for idx, vpc_id in enumerate(sorted(vpc_ids)):
            account_vpcs[vpc_id] = {
                'name': vpc_names.get((account_id, vpc_id), vpc_id),
                'color': colors[idx % len(colors)]
            }
        all_vpc_info[account_id] = account_vpcs

    return all_vpc_info

def get_ec2_instances(all_vpc_info):
    """EC2 인스턴스 정보 가져오기 (aggregator)"""
    query = """
    SELECT
        instance_id,
        tags ->> 'Name' as instance_name,
        instance_state,
        vpc_id,
        account_id,
        jsonb_array_elements(security_groups) ->> 'GroupId' as sg_id
    FROM aws_ec2_instance
    WHERE instance_state IN ('running', 'stopped')
    """
    result = run_steampipe_query(query)

    ec2_sg_map = defaultdict(list)
    ec2_info = {}

    for row in result.get('rows', []):
        instance_id = row['instance_id']
        sg_id = row['sg_id']
        vpc_id = row['vpc_id']
        account_id = row['account_id']
        vpc_info = all_vpc_info.get(account_id, {})

        if instance_id not in ec2_info:
            ec2_info[instance_id] = {
                'name': row.get('instance_name') or instance_id,
                'instance_state': row.get('instance_state', 'running'),
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
            }

        ec2_sg_map[instance_id].append(sg_id)

    return ec2_info, ec2_sg_map

def get_rds_instances(all_vpc_info):
    """RDS 인스턴스 정보 가져오기 (aggregator, ID prefix로 충돌 방지)"""
    query = """
    SELECT
        db_instance_identifier,
        tags ->> 'Name' as db_name,
        vpc_id,
        account_id,
        jsonb_array_elements(vpc_security_groups) ->> 'VpcSecurityGroupId' as sg_id
    FROM aws_rds_db_instance
    WHERE status = 'available'
    """
    result = run_steampipe_query(query)

    rds_sg_map = defaultdict(list)
    rds_info = {}

    for row in result.get('rows', []):
        db_instance_id = row['db_instance_identifier']
        sg_id = row['sg_id']
        vpc_id = row['vpc_id']
        account_id = row['account_id']
        vpc_info = all_vpc_info.get(account_id, {})

        # RDS ID는 사용자 지정이므로 account_id prefix로 충돌 방지
        prefixed_id = f"{account_id}:{db_instance_id}"

        if prefixed_id not in rds_info:
            rds_info[prefixed_id] = {
                'name': row.get('db_name') or db_instance_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
            }

        rds_sg_map[prefixed_id].append(sg_id)

    return rds_info, rds_sg_map

def get_load_balancers(all_vpc_info):
    """Load Balancer (ALB/NLB) 정보 가져오기 (aggregator)"""
    lb_sg_map = defaultdict(list)
    lb_info = {}

    lb_configs = [
        {
            'type': 'ALB',
            'query': """
                SELECT arn, name, tags ->> 'Name' as name_tag, vpc_id, account_id,
                       jsonb_array_elements_text(security_groups) as sg_id
                FROM aws_ec2_application_load_balancer
            """
        },
        {
            'type': 'NLB',
            'query': """
                SELECT arn, name, tags ->> 'Name' as name_tag, vpc_id, account_id,
                       jsonb_array_elements_text(security_groups) as sg_id
                FROM aws_ec2_network_load_balancer
                WHERE jsonb_array_length(security_groups) > 0
            """
        }
    ]

    for cfg in lb_configs:
        try:
            result = run_steampipe_query(cfg['query'])
            for row in result.get('rows', []):
                lb_arn = row['arn']
                sg_id = row['sg_id']
                vpc_id = row['vpc_id']
                account_id = row['account_id']
                vpc_info = all_vpc_info.get(account_id, {})

                if lb_arn not in lb_info:
                    display_name = row.get('name_tag') or row['name']
                    lb_info[lb_arn] = {
                        'name': display_name,
                        'vpc_id': vpc_id,
                        'account_id': account_id,
                        'lb_type': cfg['type'],
                        'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
                    }

                lb_sg_map[lb_arn].append(sg_id)
        except Exception as e:
            print(f"   ⚠️  {cfg['type']} 조회 중 오류: {e}")

    return lb_info, lb_sg_map

def get_vpc_endpoints(all_vpc_info):
    """VPC Endpoint 정보 가져오기 (aggregator)"""
    endpoint_sg_map = defaultdict(list)
    endpoint_info = {}

    endpoint_query = """
    SELECT
        vpc_endpoint_id,
        tags ->> 'Name' as name_tag,
        vpc_id,
        account_id,
        g ->> 'GroupId' as sg_id
    FROM aws_vpc_endpoint,
         jsonb_array_elements(groups) as g
    WHERE g ->> 'GroupId' IS NOT NULL
    """

    try:
        result = run_steampipe_query(endpoint_query)
        for row in result.get('rows', []):
            endpoint_id = row['vpc_endpoint_id']
            sg_id = row['sg_id']
            vpc_id = row['vpc_id']
            account_id = row['account_id']
            vpc_info = all_vpc_info.get(account_id, {})

            if endpoint_id not in endpoint_info:
                display_name = row.get('name_tag') or endpoint_id
                endpoint_info[endpoint_id] = {
                    'name': display_name,
                    'vpc_id': vpc_id,
                    'account_id': account_id,
                    'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
                }

            endpoint_sg_map[endpoint_id].append(sg_id)
    except Exception as e:
        print(f"   ⚠️  VPC Endpoint 조회 중 오류: {e}")

    return endpoint_info, endpoint_sg_map

def get_lambda_functions(all_vpc_info):
    """VPC Lambda 함수 정보 가져오기 (aggregator)"""
    query = """
    SELECT
        name,
        arn,
        vpc_id,
        account_id,
        vpc_security_group_ids,
        vpc_subnet_ids
    FROM aws_lambda_function
    WHERE vpc_id IS NOT NULL
    """
    result = run_steampipe_query(query)

    lambda_info = {}
    lambda_sg_map = {}

    try:
        for row in result.get('rows', []):
            function_name = row.get('name')
            arn = row.get('arn')
            vpc_id = row.get('vpc_id')
            account_id = row.get('account_id')
            security_group_ids = row.get('vpc_security_group_ids', [])
            vpc_info = all_vpc_info.get(account_id, {})

            if not function_name or not vpc_id:
                continue

            if vpc_id not in vpc_info:
                continue

            lambda_id = arn  # ARN은 계정별 고유
            lambda_info[lambda_id] = {
                'name': function_name,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
            }

            lambda_sg_map[lambda_id] = []

            if security_group_ids:
                for sg_id in security_group_ids:
                    if sg_id:
                        lambda_sg_map[lambda_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  Lambda 함수 조회 중 오류: {e}")

    return lambda_info, lambda_sg_map

def _run_query_with_connection_fallback(query, auth_ok_profiles):
    """Aggregator 쿼리 실행. AccessDenied 실패 시 개별 connection으로 fallback."""
    try:
        return run_steampipe_query(query)
    except Exception as e:
        error_text = str(e) + getattr(e, 'stderr', '') + getattr(e, 'stdout', '')
        if 'AccessDenied' not in error_text and 'not authorized' not in error_text:
            raise
        # AccessDenied → 개별 connection별로 재시도하여 성공한 결과만 합침
        print(f"   ⚠️  Aggregator 권한 오류, 개별 connection으로 재시도...")
        all_rows = []
        for profile in auth_ok_profiles:
            conn_name = f"aws_{profile}"
            try:
                result = subprocess.run(
                    ['steampipe', 'query', query,
                     '--search-path-prefix', conn_name,
                     '--output', 'json'],
                    capture_output=True, text=True, check=True
                )
                data = json.loads(result.stdout)
                all_rows.extend(data.get('rows', []))
            except Exception as e:
                print(f"   ⚠️  connection {conn_name} 조회 건너뜀: {e}")
        return {'rows': all_rows}

def _fetch_elasticache_shared_data(auth_ok_profiles):
    """ElastiCache 공유 데이터 1회 조회 (aggregator, AccessDenied fallback)"""
    cluster_query = """
        SELECT cache_cluster_id, cache_node_type, engine,
               cache_subnet_group_name, security_groups, account_id
        FROM aws_elasticache_cluster
    """
    clusters = _run_query_with_connection_fallback(cluster_query, auth_ok_profiles)

    subnet_group_query = """
        SELECT cache_subnet_group_name, vpc_id, account_id
        FROM aws_elasticache_subnet_group
    """
    subnet_groups = _run_query_with_connection_fallback(subnet_group_query, auth_ok_profiles)
    return clusters, subnet_groups

def get_elasticache_clusters(all_vpc_info, clusters_result, subnet_groups_result):
    """ElastiCache 클러스터 정보 가져오기 (aggregator, ID prefix로 충돌 방지)"""
    elasticache_info = {}
    elasticache_sg_map = {}

    try:
        # subnet_to_vpc: (account_id, subnet_group_name) → vpc_id (cross-account 충돌 방지)
        subnet_to_vpc = {(sg['account_id'], sg['cache_subnet_group_name']): sg['vpc_id']
                        for sg in subnet_groups_result.get('rows', [])
                        if sg.get('cache_subnet_group_name') and sg.get('vpc_id')}

        for row in clusters_result.get('rows', []):
            cluster_id = row.get('cache_cluster_id')
            engine = row.get('engine', 'unknown')
            subnet_group = row.get('cache_subnet_group_name')
            security_groups = row.get('security_groups', [])
            account_id = row.get('account_id')

            if not cluster_id or not subnet_group or not account_id:
                continue

            vpc_id = subnet_to_vpc.get((account_id, subnet_group))
            vpc_info = all_vpc_info.get(account_id, {})
            if not vpc_id or vpc_id not in vpc_info:
                continue

            prefixed_id = f"{account_id}:{cluster_id}"
            elasticache_info[prefixed_id] = {
                'name': cluster_id,
                'engine': engine,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
            }

            elasticache_sg_map[prefixed_id] = []

            for sg in security_groups:
                sg_id = sg.get('SecurityGroupId')
                if sg_id:
                    elasticache_sg_map[prefixed_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  ElastiCache 클러스터 조회 중 오류: {e}")

    return elasticache_info, elasticache_sg_map

def get_elasticache_replication_groups(all_vpc_info, clusters_result, subnet_groups_result, rg_result):
    """ElastiCache 복제 그룹 정보 가져오기 (aggregator, ID prefix로 충돌 방지)"""
    replication_group_info = {}
    replication_group_sg_map = {}

    try:
        cluster_rows = clusters_result.get('rows', []) if isinstance(clusters_result, dict) else clusters_result
        # (account_id, cluster_id) → subnet_group
        cluster_to_subnet = {(c['account_id'], c['cache_cluster_id']): c.get('cache_subnet_group_name')
                            for c in cluster_rows if c.get('cache_cluster_id') and c.get('account_id')}
        cluster_to_sgs = {(c['account_id'], c['cache_cluster_id']): c.get('security_groups', [])
                         for c in cluster_rows if c.get('cache_cluster_id') and c.get('account_id')}

        # (account_id, subnet_group_name) → vpc_id
        subnet_to_vpc = {(sg['account_id'], sg['cache_subnet_group_name']): sg['vpc_id']
                        for sg in subnet_groups_result.get('rows', [])
                        if sg.get('cache_subnet_group_name') and sg.get('vpc_id')}

        for row in rg_result.get('rows', []):
            group_id = row.get('replication_group_id')
            member_clusters = row.get('member_clusters', [])
            account_id = row.get('account_id')

            if not group_id or not account_id:
                continue

            # member cluster를 통해 VPC 찾기
            vpc_id = None
            for cluster_id in member_clusters:
                subnet_group = cluster_to_subnet.get((account_id, cluster_id))
                if subnet_group:
                    vpc_id = subnet_to_vpc.get((account_id, subnet_group))
                    if vpc_id:
                        break

            vpc_info = all_vpc_info.get(account_id, {})
            if not vpc_id or vpc_id not in vpc_info:
                continue

            prefixed_id = f"{account_id}:{group_id}"
            replication_group_info[prefixed_id] = {
                'name': group_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
            }

            replication_group_sg_map[prefixed_id] = []

            for cluster_id in member_clusters:
                for sg in cluster_to_sgs.get((account_id, cluster_id), []) or []:
                    sg_id = sg.get('SecurityGroupId') if isinstance(sg, dict) else None
                    if sg_id and sg_id not in replication_group_sg_map[prefixed_id]:
                        replication_group_sg_map[prefixed_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  ElastiCache 복제 그룹 조회 중 오류: {e}")

    return replication_group_info, replication_group_sg_map

def get_network_interfaces(all_vpc_info, known_ec2_ids=None):
    """네트워크 인터페이스 SG 정보 가져오기 (aggregator, 안전망)"""
    query = """
    SELECT
        network_interface_id,
        vpc_id,
        account_id,
        groups,
        description,
        attached_instance_id,
        interface_type
    FROM aws_ec2_network_interface
    WHERE groups IS NOT NULL
    """
    result = run_steampipe_query(query)

    eni_info = {}
    eni_sg_map = {}

    try:
        for row in result.get('rows', []):
            eni_id = row.get('network_interface_id')
            vpc_id = row.get('vpc_id')
            account_id = row.get('account_id')
            groups = row.get('groups', [])
            description = row.get('description', '')
            attached_instance_id = row.get('attached_instance_id')
            interface_type = row.get('interface_type', '')
            vpc_info = all_vpc_info.get(account_id, {})

            if not eni_id or not vpc_id:
                continue

            if vpc_id not in vpc_info:
                continue

            if interface_type in ['nat_gateway', 'vpc_endpoint', 'gateway_load_balancer_endpoint']:
                continue

            if description and ('NAT Gateway' in description or 'VPC Endpoint' in description):
                continue

            if attached_instance_id and known_ec2_ids and attached_instance_id in known_ec2_ids:
                continue

            eni_info[eni_id] = {'account_id': account_id}
            eni_sg_map[eni_id] = []

            for group in groups:
                if isinstance(group, dict):
                    sg_id = group.get('GroupId')
                    if sg_id:
                        eni_sg_map[eni_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  네트워크 인터페이스 조회 중 오류: {e}")

    return eni_info, eni_sg_map

def _resolve_vpc_from_sg(sg_id_list, sg_info):
    """SG의 vpc_id를 역참조하여 리소스의 vpc_id를 결정"""
    for sg_id in sg_id_list:
        sg = sg_info.get(sg_id)
        if sg and sg.get('vpc_id'):
            return sg['vpc_id']
    return None

def get_ecs_services(all_vpc_info, sg_info):
    """ECS Fargate 서비스 정보 가져오기 (aggregator)"""
    query = """
    SELECT service_name, cluster_arn, account_id,
           network_configuration
    FROM aws_ecs_service
    WHERE network_configuration IS NOT NULL
    """
    ecs_info = {}
    ecs_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            service_name = row.get('service_name')
            account_id = row.get('account_id')
            net_config = row.get('network_configuration', {})

            if not service_name or not account_id or not net_config:
                continue

            # Handle both PascalCase and camelCase (Steampipe schema varies)
            awsvpc = (net_config.get('AwsvpcConfiguration') or
                      net_config.get('awsvpcConfiguration') or {})
            sg_ids = (awsvpc.get('SecurityGroups') or
                      awsvpc.get('securityGroups') or [])

            if not sg_ids:
                continue

            prefixed_id = f"{account_id}:{service_name}"
            vpc_id = _resolve_vpc_from_sg(sg_ids, sg_info)
            vpc_info = all_vpc_info.get(account_id, {})

            ecs_info[prefixed_id] = {
                'name': service_name,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }

            for sg_id in sg_ids:
                if sg_id:
                    ecs_sg_map[prefixed_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  ECS 서비스 조회 중 오류 (건너뜀): {e}")

    return ecs_info, dict(ecs_sg_map)

def get_redshift_clusters(all_vpc_info):
    """Redshift 클러스터 정보 가져오기 (aggregator)"""
    query = """
    SELECT cluster_identifier,
           COALESCE(tags ->> 'Name', cluster_identifier) as cluster_name,
           vpc_id, account_id,
           vpc_security_groups
    FROM aws_redshift_cluster
    """
    redshift_info = {}
    redshift_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            cluster_id = row.get('cluster_identifier')
            account_id = row.get('account_id')
            vpc_id = row.get('vpc_id')
            vpc_sgs = row.get('vpc_security_groups', [])

            if not cluster_id or not account_id:
                continue

            prefixed_id = f"{account_id}:{cluster_id}"
            vpc_info = all_vpc_info.get(account_id, {})

            redshift_info[prefixed_id] = {
                'name': row.get('cluster_name') or cluster_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }

            for sg in (vpc_sgs or []):
                sg_id = sg.get('VpcSecurityGroupId') if isinstance(sg, dict) else None
                if sg_id:
                    redshift_sg_map[prefixed_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  Redshift 클러스터 조회 중 오류 (건너뜀): {e}")

    return redshift_info, dict(redshift_sg_map)

def get_opensearch_domains(all_vpc_info):
    """OpenSearch 도메인 정보 가져오기 (aggregator)"""
    query = """
    SELECT domain_name, arn, account_id,
           vpc_options
    FROM aws_opensearch_domain
    WHERE vpc_options IS NOT NULL
    """
    opensearch_info = {}
    opensearch_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            domain_name = row.get('domain_name')
            account_id = row.get('account_id')
            vpc_options = row.get('vpc_options', {})

            if not domain_name or not account_id or not vpc_options:
                continue

            vpc_id = vpc_options.get('VPCId') or vpc_options.get('vpc_id')
            sg_ids = vpc_options.get('SecurityGroupIds') or vpc_options.get('security_group_ids') or []

            if not sg_ids:
                continue

            prefixed_id = f"{account_id}:{domain_name}"
            vpc_info = all_vpc_info.get(account_id, {})

            opensearch_info[prefixed_id] = {
                'name': domain_name,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }

            for sg_id in sg_ids:
                if sg_id:
                    opensearch_sg_map[prefixed_id].append(sg_id)

    except Exception as e:
        print(f"   ⚠️  OpenSearch 도메인 조회 중 오류 (건너뜀): {e}")

    return opensearch_info, dict(opensearch_sg_map)

def get_docdb_clusters(all_vpc_info, sg_info):
    """DocumentDB 클러스터 정보 가져오기 (aggregator)"""
    query = """
    SELECT db_cluster_identifier,
           COALESCE(tags ->> 'Name', db_cluster_identifier) as name,
           account_id,
           vpc_security_groups
    FROM aws_docdb_cluster
    """
    docdb_info = {}
    docdb_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            cluster_id = row.get('db_cluster_identifier')
            account_id = row.get('account_id')
            vpc_sgs = row.get('vpc_security_groups', [])

            if not cluster_id or not account_id:
                continue

            sg_ids = []
            for sg in (vpc_sgs or []):
                sg_id = sg.get('VpcSecurityGroupId') if isinstance(sg, dict) else None
                if sg_id:
                    sg_ids.append(sg_id)

            if not sg_ids:
                continue

            prefixed_id = f"{account_id}:{cluster_id}"
            vpc_id = _resolve_vpc_from_sg(sg_ids, sg_info)
            vpc_info = all_vpc_info.get(account_id, {})

            docdb_info[prefixed_id] = {
                'name': row.get('name') or cluster_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }
            docdb_sg_map[prefixed_id] = sg_ids

    except Exception as e:
        print(f"   ⚠️  DocumentDB 조회 중 오류 (건너뜀): {e}")

    return docdb_info, dict(docdb_sg_map)

def get_neptune_clusters(all_vpc_info, sg_info):
    """Neptune 클러스터 정보 가져오기 (aggregator)"""
    query = """
    SELECT db_cluster_identifier,
           COALESCE(tags ->> 'Name', db_cluster_identifier) as name,
           account_id,
           vpc_security_groups
    FROM aws_neptune_db_cluster
    """
    neptune_info = {}
    neptune_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            cluster_id = row.get('db_cluster_identifier')
            account_id = row.get('account_id')
            vpc_sgs = row.get('vpc_security_groups', [])

            if not cluster_id or not account_id:
                continue

            sg_ids = []
            for sg in (vpc_sgs or []):
                sg_id = sg.get('VpcSecurityGroupId') if isinstance(sg, dict) else None
                if sg_id:
                    sg_ids.append(sg_id)

            if not sg_ids:
                continue

            prefixed_id = f"{account_id}:{cluster_id}"
            vpc_id = _resolve_vpc_from_sg(sg_ids, sg_info)
            vpc_info = all_vpc_info.get(account_id, {})

            neptune_info[prefixed_id] = {
                'name': row.get('name') or cluster_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }
            neptune_sg_map[prefixed_id] = sg_ids

    except Exception as e:
        print(f"   ⚠️  Neptune 조회 중 오류 (건너뜀): {e}")

    return neptune_info, dict(neptune_sg_map)

def get_memorydb_clusters(all_vpc_info, sg_info):
    """MemoryDB 클러스터 정보 가져오기 (aggregator)"""
    query = """
    SELECT name, account_id,
           security_groups
    FROM aws_memorydb_cluster
    """
    memorydb_info = {}
    memorydb_sg_map = defaultdict(list)

    try:
        result = run_steampipe_query(query)
        for row in result.get('rows', []):
            cluster_name = row.get('name')
            account_id = row.get('account_id')
            security_groups = row.get('security_groups', [])

            if not cluster_name or not account_id:
                continue

            sg_ids = []
            for sg in (security_groups or []):
                sg_id = sg.get('SecurityGroupId') if isinstance(sg, dict) else None
                if sg_id:
                    sg_ids.append(sg_id)

            if not sg_ids:
                continue

            prefixed_id = f"{account_id}:{cluster_name}"
            vpc_id = _resolve_vpc_from_sg(sg_ids, sg_info)
            vpc_info = all_vpc_info.get(account_id, {})

            memorydb_info[prefixed_id] = {
                'name': cluster_name,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999'
            }
            memorydb_sg_map[prefixed_id] = sg_ids

    except Exception as e:
        print(f"   ⚠️  MemoryDB 조회 중 오류 (건너뜀): {e}")

    return memorydb_info, dict(memorydb_sg_map)

def get_security_groups_and_rules(all_vpc_info):
    """Security Group 정보 + 규칙을 단일 쿼리로 가져오기 (aggregator)"""
    query = """
        SELECT group_id, group_name, vpc_id, account_id,
               ip_permissions, ip_permissions_egress
        FROM aws_vpc_security_group
    """
    result = run_steampipe_query(query)

    sg_info = {}
    sg_rules = defaultdict(lambda: {'ingress': [], 'egress': []})

    for row in result.get('rows', []):
        sg_id = row['group_id']
        vpc_id = row['vpc_id']
        account_id = row['account_id']
        vpc_info = all_vpc_info.get(account_id, {})

        sg_info[sg_id] = {
            'name': row['group_name'],
            'vpc_id': vpc_id,
            'account_id': account_id,
            'color': vpc_info.get(vpc_id, {}).get('color', '#999999')
        }
        for rule in (row.get('ip_permissions') or []):
            sg_rules[sg_id]['ingress'].append(rule)
        for rule in (row.get('ip_permissions_egress') or []):
            sg_rules[sg_id]['egress'].append(rule)

    return sg_info, dict(sg_rules)

def enrich_nodes_with_account(nodes, account_metadata):
    """노드에 계정 정보 추가 및 ID에 프로파일 prefix 추가"""
    profile = account_metadata['profile_name']

    enriched_nodes = []
    for node in nodes:
        enriched_node = node.copy()
        # ID에 프로파일 prefix 추가 (충돌 방지)
        enriched_node['id'] = f"{profile}:{node['id']}"
        # VPC ID도 prefix 추가
        if 'vpc_id' in enriched_node and enriched_node['vpc_id']:
            enriched_node['vpc_id'] = f"{profile}:{enriched_node['vpc_id']}"
        # 계정 메타데이터 추가
        enriched_node['account_id'] = account_metadata['account_id']
        enriched_node['account_name'] = account_metadata['account_name']
        enriched_node['profile_name'] = profile
        enriched_nodes.append(enriched_node)

    return enriched_nodes

def enrich_edges_with_account(edges, account_metadata):
    """엣지에 계정 prefix 추가"""
    profile = account_metadata['profile_name']

    enriched_edges = []
    for edge in edges:
        enriched_edge = edge.copy()
        # From/To ID에 프로파일 prefix 추가
        enriched_edge['from'] = f"{profile}:{edge['from']}"
        enriched_edge['to'] = f"{profile}:{edge['to']}"
        # 계정 ID 추가
        enriched_edge['account_id'] = account_metadata['account_id']
        enriched_edges.append(enriched_edge)

    return enriched_edges

def enrich_vpc_info_with_account(vpc_info, account_metadata):
    """VPC 정보에 계정 prefix 추가"""
    profile = account_metadata['profile_name']

    enriched_vpc_info = {}
    for vpc_id, info in vpc_info.items():
        prefixed_vpc_id = f"{profile}:{vpc_id}"
        enriched_vpc_info[prefixed_vpc_id] = info.copy()

    return enriched_vpc_info

def enrich_sg_rules_with_account(sg_rules, account_metadata):
    """SG 규칙에 계정 prefix 추가"""
    profile = account_metadata['profile_name']

    enriched_sg_rules = {}
    for sg_id, rules in sg_rules.items():
        prefixed_sg_id = f"{profile}:{sg_id}"
        enriched_sg_rules[prefixed_sg_id] = rules

    return enriched_sg_rules

def generate_nodes_and_edges(resources, sg_info, sg_rules, extra_used_sgs=None):
    """노드와 엣지 데이터 생성 (리팩토링: ResourceData 기반 제네릭 루프)"""
    all_nodes = []
    all_edges = []
    used_sgs = set(extra_used_sgs) if extra_used_sgs else set()

    # 리소스 노드 + 엣지 생성 (제네릭 루프)
    for rd in resources:
        for res_id, info in rd.info.items():
            label = info.get('name', res_id)
            # Lambda는 긴 이름 잘라서 표시
            if rd.type == 'lambda':
                label = label[:30]

            node = {
                'id': res_id,
                'label': label,
                'group': rd.type,
                'vpc_id': info.get('vpc_id'),
                'color': info.get('color', '#999999'),
            }
            for key in _PASSTHROUGH_KEYS:
                if key in info:
                    node[key] = info[key]
            all_nodes.append(node)

        for res_id, sg_list in rd.sg_map.items():
            used_sgs.update(sg_list)
            for sg_id in sg_list:
                all_edges.append({'from': res_id, 'to': sg_id, 'label': 'uses'})

    # 취약 규칙 탐지
    vulnerabilities = detect_sg_vulnerabilities(sg_rules)

    # SG 노드 생성
    for sg_id, info in sg_info.items():
        sg_vulns = vulnerabilities.get(sg_id, [])
        all_nodes.append({
            'id': sg_id,
            'label': info['name'],
            'group': 'sg',
            'vpc_id': info['vpc_id'],
            'is_unused': sg_id not in used_sgs,
            'is_vulnerable': len(sg_vulns) > 0,
            'vulnerabilities': sg_vulns
        })

    # SG → SG 참조 엣지 및 사용 추적 (CRITICAL FIX)
    for sg_id, rules in sg_rules.items():
        # Ingress 규칙
        for rule in rules.get('ingress', []):
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                ref_sg_id = user_id_group_pair.get('GroupId')
                if ref_sg_id and ref_sg_id in sg_info:
                    all_edges.append({
                        'from': ref_sg_id,
                        'to': sg_id,
                        'label': 'ingress',
                        'dashes': True
                    })
                    used_sgs.add(ref_sg_id)
                    used_sgs.add(sg_id)

        # Egress 규칙
        for rule in rules.get('egress', []):
            for user_id_group_pair in rule.get('UserIdGroupPairs', []):
                ref_sg_id = user_id_group_pair.get('GroupId')
                if ref_sg_id and ref_sg_id in sg_info:
                    all_edges.append({
                        'from': sg_id,
                        'to': ref_sg_id,
                        'label': 'egress',
                        'dashes': True
                    })
                    used_sgs.add(ref_sg_id)
                    used_sgs.add(sg_id)

    # SG-to-SG 참조 추적 후 is_unused 플래그 업데이트
    for node in all_nodes:
        if node.get('group') == 'sg':
            node['is_unused'] = node['id'] not in used_sgs

    return all_nodes, all_edges

def _partition_by_account(info_dict, sg_map_dict):
    """account_id 기준으로 (info_dict, sg_map) 분리.
    prefixed key (account_id:res_id) → 원래 res_id로 복원."""
    by_account = {}
    for res_id, info in info_dict.items():
        acct = info.get('account_id')
        if acct not in by_account:
            by_account[acct] = ({}, {})
        original_id = res_id.split(':', 1)[1] if ':' in res_id else res_id
        by_account[acct][0][original_id] = info
        if res_id in sg_map_dict:
            by_account[acct][1][original_id] = sg_map_dict[res_id]
    return by_account

def _partition_sg_rules(sg_info, sg_rules):
    """SG info/rules를 account_id별로 분리 (SG ID는 글로벌 고유)"""
    by_account = {}
    for sg_id, info in sg_info.items():
        acct = info.get('account_id')
        if acct not in by_account:
            by_account[acct] = ({}, {})
        by_account[acct][0][sg_id] = info
        if sg_id in sg_rules:
            by_account[acct][1][sg_id] = sg_rules[sg_id]
    return by_account

def collect_multi_account_data():
    """Aggregator 방식: 1회 설정 + 1회 재시작 + ~13개 쿼리로 모든 계정 동시 수집"""
    profiles = get_aws_profiles()

    if not profiles:
        print("⚠️  AWS 프로파일을 찾을 수 없습니다")
        print("   ~/.aws/credentials 파일을 확인해주세요")
        sys.exit(1)

    print(f"📋 발견된 AWS 프로파일: {', '.join(profiles)}\n")

    # Step 0: AWS CLI 인증 확인 (aggregator에 만료된 connection 포함 방지)
    auth_ok_profiles = check_aws_cli_auth(profiles)
    if not auth_ok_profiles:
        print(f"\n⚠️  모든 프로파일 인증 실패")
        sys.exit(1)

    if len(auth_ok_profiles) < len(profiles):
        failed = [p for p in profiles if p not in auth_ok_profiles]
        print(f"   ⚠️  인증 실패 프로파일 제외: {', '.join(failed)}")

    # Step 1: Aggregator 설정 (인증 성공 프로파일만)
    print(f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"🔧 Steampipe Aggregator 설정 중...")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    setup_aggregator_config(auth_ok_profiles)

    # Step 2: 서비스 재시작 (1회)
    reload_steampipe_service()

    # Step 3: 계정 메타데이터 일괄 조회
    accounts = get_all_account_identities(auth_ok_profiles)
    if not accounts:
        print(f"\n⚠️  모든 프로파일에서 데이터 수집 실패")
        sys.exit(1)

    # 계정별 색상 할당
    account_colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#30cfd0', '#a8edea']
    for idx, (account_id, meta) in enumerate(sorted(accounts.items())):
        meta['color'] = account_colors[idx % len(account_colors)]

    # Step 4: VPC 정보 (aggregator가 3계정 병렬 조회)
    print(f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"📊 Aggregator로 모든 계정 리소스 수집 중...")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    all_vpc_info = get_vpc_info()

    # Step 5: 독립 쿼리 병렬 실행 (ThreadPoolExecutor)
    print(f"   ⏱  병렬 쿼리 시작...")
    parallel_start = time.time()

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(get_ec2_instances, all_vpc_info): 'EC2',
            executor.submit(get_rds_instances, all_vpc_info): 'RDS',
            executor.submit(get_load_balancers, all_vpc_info): 'LB',
            executor.submit(get_vpc_endpoints, all_vpc_info): 'VPC Endpoint',
            executor.submit(get_lambda_functions, all_vpc_info): 'Lambda',
            executor.submit(get_security_groups_and_rules, all_vpc_info): 'SG',
            executor.submit(_fetch_elasticache_shared_data, auth_ok_profiles): 'ElastiCache Shared',
        }
        results = {}
        for future in as_completed(futures, timeout=120):
            label = futures[future]
            try:
                results[label] = future.result()
                info_count = len(results[label][0]) if isinstance(results[label], tuple) else 0
                print(f"   ✓ {label}: {info_count}개")
            except Exception as e:
                print(f"   ⚠️  {label} 조회 실패 (건너뜀): {e}")
                results[label] = ({}, {})

    parallel_elapsed = time.time() - parallel_start
    print(f"   ⏱  병렬 쿼리 완료: {parallel_elapsed:.1f}초")

    # SG 데이터 검증 게이트
    sg_info, sg_rules = results.get('SG', ({}, {}))
    if not sg_info:
        print("❌ FATAL: Security Group 쿼리 실패 또는 결과 없음. 중단합니다.")
        sys.exit(1)
    print(f"   ✓ Security Group: {len(sg_info)}개")

    # 병렬 결과 추출
    ec2_info, ec2_sg_map = results.get('EC2', ({}, {}))
    rds_info, rds_sg_map = results.get('RDS', ({}, {}))
    lb_info, lb_sg_map = results.get('LB', ({}, {}))
    endpoint_info, endpoint_sg_map = results.get('VPC Endpoint', ({}, {}))
    lambda_info, lambda_sg_map = results.get('Lambda', ({}, {}))
    clusters_raw, subnet_groups_raw = results.get('ElastiCache Shared', ({}, {}))

    # 의존성 있는 쿼리는 순차 실행
    try:
        elasticache_info, elasticache_sg_map = get_elasticache_clusters(
            all_vpc_info, clusters_raw, subnet_groups_raw)
    except Exception as e:
        print(f"   ⚠️  ElastiCache 클러스터 조회 실패 (건너뜀): {e}")
        elasticache_info, elasticache_sg_map = {}, {}
    print(f"   ✓ ElastiCache Cluster: {len(elasticache_info)}개")

    try:
        rg_raw = _run_query_with_connection_fallback(RG_QUERY, auth_ok_profiles)
        elasticache_groups, elasticache_group_sg_map = get_elasticache_replication_groups(
            all_vpc_info, clusters_raw, subnet_groups_raw, rg_raw)
    except Exception as e:
        print(f"   ⚠️  ElastiCache 복제 그룹 조회 실패 (건너뜀): {e}")
        elasticache_groups, elasticache_group_sg_map = {}, {}
    print(f"   ✓ ElastiCache RG: {len(elasticache_groups)}개")

    # Tier 1 서비스: ECS (SG 역참조 필요 → sg_info 필요), Redshift, OpenSearch
    try:
        ecs_info, ecs_sg_map = get_ecs_services(all_vpc_info, sg_info)
    except Exception as e:
        print(f"   ⚠️  ECS 서비스 조회 실패 (건너뜀): {e}")
        ecs_info, ecs_sg_map = {}, {}
    print(f"   ✓ ECS: {len(ecs_info)}개")

    try:
        redshift_info, redshift_sg_map = get_redshift_clusters(all_vpc_info)
    except Exception as e:
        print(f"   ⚠️  Redshift 클러스터 조회 실패 (건너뜀): {e}")
        redshift_info, redshift_sg_map = {}, {}
    print(f"   ✓ Redshift: {len(redshift_info)}개")

    try:
        opensearch_info, opensearch_sg_map = get_opensearch_domains(all_vpc_info)
    except Exception as e:
        print(f"   ⚠️  OpenSearch 도메인 조회 실패 (건너뜀): {e}")
        opensearch_info, opensearch_sg_map = {}, {}
    print(f"   ✓ OpenSearch: {len(opensearch_info)}개")

    # Tier 2 서비스: DocumentDB, Neptune, MemoryDB (sg_info 필요)
    try:
        docdb_info, docdb_sg_map = get_docdb_clusters(all_vpc_info, sg_info)
    except Exception as e:
        print(f"   ⚠️  DocumentDB 조회 실패 (건너뜀): {e}")
        docdb_info, docdb_sg_map = {}, {}
    print(f"   ✓ DocumentDB: {len(docdb_info)}개")

    try:
        neptune_info, neptune_sg_map = get_neptune_clusters(all_vpc_info, sg_info)
    except Exception as e:
        print(f"   ⚠️  Neptune 조회 실패 (건너뜀): {e}")
        neptune_info, neptune_sg_map = {}, {}
    print(f"   ✓ Neptune: {len(neptune_info)}개")

    try:
        memorydb_info, memorydb_sg_map = get_memorydb_clusters(all_vpc_info, sg_info)
    except Exception as e:
        print(f"   ⚠️  MemoryDB 조회 실패 (건너뜀): {e}")
        memorydb_info, memorydb_sg_map = {}, {}
    print(f"   ✓ MemoryDB: {len(memorydb_info)}개")

    # ENI는 EC2 결과(known_ec2_ids) 필요 → 병렬 완료 후 실행
    known_ec2_ids = set(ec2_info.keys())
    try:
        eni_info, eni_sg_map = get_network_interfaces(all_vpc_info, known_ec2_ids=known_ec2_ids)
    except Exception as e:
        print(f"   ⚠️  네트워크 인터페이스 조회 실패 (건너뜀): {e}")
        eni_info, eni_sg_map = {}, {}
    print(f"   ✓ ENI (안전망): {len(eni_sg_map)}개")

    # Step 6: account_id별 파티셔닝
    ec2_by_acct = _partition_by_account(ec2_info, ec2_sg_map)
    rds_by_acct = _partition_by_account(rds_info, rds_sg_map)
    lb_by_acct = _partition_by_account(lb_info, lb_sg_map)
    endpoint_by_acct = _partition_by_account(endpoint_info, endpoint_sg_map)
    lambda_by_acct = _partition_by_account(lambda_info, lambda_sg_map)
    elasticache_by_acct = _partition_by_account(elasticache_info, elasticache_sg_map)
    elasticache_rg_by_acct = _partition_by_account(elasticache_groups, elasticache_group_sg_map)
    ecs_by_acct = _partition_by_account(ecs_info, ecs_sg_map)
    redshift_by_acct = _partition_by_account(redshift_info, redshift_sg_map)
    opensearch_by_acct = _partition_by_account(opensearch_info, opensearch_sg_map)
    docdb_by_acct = _partition_by_account(docdb_info, docdb_sg_map)
    neptune_by_acct = _partition_by_account(neptune_info, neptune_sg_map)
    memorydb_by_acct = _partition_by_account(memorydb_info, memorydb_sg_map)
    # ENI: eni_info에 account_id가 있으면 파티셔닝, 없으면 sg_map만 account로 분배
    eni_by_acct = _partition_by_account(eni_info, eni_sg_map) if eni_info else {}
    sg_by_acct = _partition_sg_rules(sg_info, sg_rules)

    # Step 7: 계정별 노드/엣지 생성 + enrichment
    all_data = {
        'nodes': [],
        'edges': [],
        'sg_rules': {},
        'vpc_info': {},
        'account_info': {}
    }

    for account_id, account_meta in accounts.items():
        profile = account_meta['profile_name']

        # 해당 계정의 파티션된 데이터 추출 (없으면 빈 dict)
        acct_ec2, acct_ec2_sg = ec2_by_acct.get(account_id, ({}, {}))
        acct_rds, acct_rds_sg = rds_by_acct.get(account_id, ({}, {}))
        acct_lb, acct_lb_sg = lb_by_acct.get(account_id, ({}, {}))
        acct_ep, acct_ep_sg = endpoint_by_acct.get(account_id, ({}, {}))
        acct_lam, acct_lam_sg = lambda_by_acct.get(account_id, ({}, {}))
        acct_ec_cl, acct_ec_cl_sg = elasticache_by_acct.get(account_id, ({}, {}))
        acct_ec_rg, acct_ec_rg_sg = elasticache_rg_by_acct.get(account_id, ({}, {}))
        acct_ecs, acct_ecs_sg = ecs_by_acct.get(account_id, ({}, {}))
        acct_redshift, acct_redshift_sg = redshift_by_acct.get(account_id, ({}, {}))
        acct_opensearch, acct_opensearch_sg = opensearch_by_acct.get(account_id, ({}, {}))
        acct_docdb, acct_docdb_sg = docdb_by_acct.get(account_id, ({}, {}))
        acct_neptune, acct_neptune_sg = neptune_by_acct.get(account_id, ({}, {}))
        acct_memorydb, acct_memorydb_sg = memorydb_by_acct.get(account_id, ({}, {}))
        acct_eni_info, acct_eni_sg = eni_by_acct.get(account_id, ({}, {}))
        acct_sg_info, acct_sg_rules = sg_by_acct.get(account_id, ({}, {}))
        acct_vpc_info = all_vpc_info.get(account_id, {})

        # ENI 안전망: eni_info가 없는 경우도 sg_map은 필요
        if not acct_eni_info and eni_sg_map:
            acct_eni_sg_fallback = {}
            for eni_id, sg_list in eni_sg_map.items():
                for sg_id in sg_list:
                    if sg_id in acct_sg_info:
                        acct_eni_sg_fallback[eni_id] = sg_list
                        break
            if acct_eni_sg_fallback:
                acct_eni_sg = acct_eni_sg_fallback

        # ENI는 노드 생성 불필요, used_sgs 추적만
        eni_used_sgs = set()
        for sg_list in acct_eni_sg.values():
            eni_used_sgs.update(sg_list)

        resources = [
            ResourceData('ec2', acct_ec2, acct_ec2_sg),
            ResourceData('rds', acct_rds, acct_rds_sg),
            ResourceData('lb', acct_lb, acct_lb_sg),
            ResourceData('vpc_endpoint', acct_ep, acct_ep_sg),
            ResourceData('lambda', acct_lam, acct_lam_sg),
            ResourceData('elasticache', acct_ec_cl, acct_ec_cl_sg),
            ResourceData('elasticache_rg', acct_ec_rg, acct_ec_rg_sg),
            ResourceData('ecs', acct_ecs, acct_ecs_sg),
            ResourceData('redshift', acct_redshift, acct_redshift_sg),
            ResourceData('opensearch', acct_opensearch, acct_opensearch_sg),
            ResourceData('docdb', acct_docdb, acct_docdb_sg),
            ResourceData('neptune', acct_neptune, acct_neptune_sg),
            ResourceData('memorydb', acct_memorydb, acct_memorydb_sg),
        ]

        nodes, edges = generate_nodes_and_edges(
            resources, acct_sg_info, acct_sg_rules,
            extra_used_sgs=eni_used_sgs
        )

        enriched_nodes = enrich_nodes_with_account(nodes, account_meta)
        enriched_edges = enrich_edges_with_account(edges, account_meta)
        enriched_vpc_info = enrich_vpc_info_with_account(acct_vpc_info, account_meta)
        enriched_sg_rules = enrich_sg_rules_with_account(acct_sg_rules, account_meta)

        all_data['nodes'].extend(enriched_nodes)
        all_data['edges'].extend(enriched_edges)
        all_data['sg_rules'].update(enriched_sg_rules)
        all_data['vpc_info'].update(enriched_vpc_info)
        all_data['account_info'][profile] = {
            'account_id': account_id,
            'account_name': account_meta['account_name'],
            'profile_name': profile,
            'color': account_meta['color'],
            'node_count': len(enriched_nodes),
            'edge_count': len(enriched_edges)
        }

        print(f"   ✓ {account_meta['account_name']} ({profile}): {len(enriched_nodes)}개 노드, {len(enriched_edges)}개 엣지")

    # 요약 출력
    print(f"\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"📊 데이터 수집 완료")
    print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"✅ 성공: {len(accounts)}개 계정")
    for profile, info in all_data['account_info'].items():
        print(f"   - {info['account_name']} ({profile}): {info['node_count']}개 노드")

    print(f"\n📈 전체 통계:")
    print(f"   - 총 노드: {len(all_data['nodes'])}개")
    print(f"   - 총 엣지: {len(all_data['edges'])}개")
    print(f"   - 총 VPC: {len(all_data['vpc_info'])}개")

    return all_data

def update_html_template(template_file, nodes, edges, sg_rules, vpc_info, account_info):
    """템플릿 HTML 파일의 DATA SECTION 마커 사이에 데이터를 주입"""

    START_MARKER = '// ===== DATA SECTION (replaced by Python script) ====='
    END_MARKER = '// ===== END DATA SECTION ====='

    with open(template_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    start_idx = html_content.index(START_MARKER)
    end_idx = html_content.index(END_MARKER) + len(END_MARKER)

    # 데이터를 JSON 문자열로 변환
    data_section = f"""{START_MARKER}
        const nodesData = {json.dumps(nodes, indent=8, ensure_ascii=False)};
        const edgesData = {json.dumps(edges, indent=8, ensure_ascii=False)};
        const sgRules = {json.dumps(sg_rules, indent=8, ensure_ascii=False)};
        const vpcInfo = {json.dumps(vpc_info, indent=8, ensure_ascii=False)};
        const accountInfo = {json.dumps(account_info, indent=8, ensure_ascii=False)};
        {END_MARKER}"""

    return html_content[:start_idx] + data_section + html_content[end_idx:]

def main():
    print("🚀 Security Group Review Dashboard - 멀티 어카운트 데이터 수집 시작...\n")

    # 멀티 어카운트 데이터 수집
    all_data = collect_multi_account_data()

    if not all_data['nodes']:
        print("\n⚠️  수집된 데이터가 없습니다")
        sys.exit(1)

    print("\n🎨 HTML 대시보드 생성 중...")
    template_file = 'sg_dashboard_template.html'
    output_file = 'sg_interactive_graph_v2.html'

    html_content = update_html_template(
        template_file,
        all_data['nodes'],
        all_data['edges'],
        all_data['sg_rules'],
        all_data['vpc_info'],
        all_data['account_info']
    )

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    print(f"\n✅ 완료! 파일 생성: {output_file}")
    print("\n🌐 사용 방법:")
    print("   python3 -m http.server 8080")
    print(f"   http://localhost:8080/{output_file}")
    print("\n💡 새로운 기능:")
    print("   ✅ 멀티 어카운트 지원 (Account 필터)")
    print("   ✅ 계정별 VPC 필터링")
    print("   ✅ 기존 모든 기능 유지")
    print("   ✅ 자동 프로파일 감지")

if __name__ == '__main__':
    main()
