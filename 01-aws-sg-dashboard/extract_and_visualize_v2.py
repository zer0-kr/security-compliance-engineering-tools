#!/usr/bin/env python3
"""
Security Group Review Dashboard - Multi-Account Template-based Generator
Collects SG data from all AWS profiles in a multi-account environment.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict, namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import logging

logger = logging.getLogger(__name__)


def configure_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s %(levelname)-5s %(message)s',
        datefmt='%H:%M:%S',
        stream=sys.stderr
    )


# ===== Configuration =====
DEFAULT_REGIONS = [os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')]
DEFAULT_TEMPLATE = 'sg_dashboard_template.html'
DEFAULT_OUTPUT = 'sg_interactive_graph_v2.html'
STEAMPIPE_CONFIG_PATH = os.path.expanduser('~/.steampipe/config/aws.spc')
STEAMPIPE_PID_PATH = os.path.expanduser('~/.steampipe/internal/steampipe.pid')
QUERY_TIMEOUT_SECONDS = 300
SERVICE_READY_TIMEOUT_SECONDS = 30
PARALLEL_WORKERS = 4


# Vulnerability detection constants
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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description='Security Group Review Dashboard - collect AWS SG data and generate interactive HTML dashboard'
    )
    parser.add_argument('--regions', nargs='+', default=DEFAULT_REGIONS,
        help='AWS regions to query (default: $AWS_DEFAULT_REGION or us-east-1)')
    parser.add_argument('--skip-config', action='store_true',
        help='Skip Steampipe aggregator config generation (use existing config)')
    parser.add_argument('--template', default=DEFAULT_TEMPLATE,
        help='Path to HTML template file (default: sg_dashboard_template.html)')
    parser.add_argument('--output', '-o', default=DEFAULT_OUTPUT,
        help='Output HTML file path (default: sg_interactive_graph_v2.html)')
    parser.add_argument('--verbose', '-v', action='store_true',
        help='Enable verbose/debug output')
    return parser.parse_args(argv)


# Additional resource fields (copied to nodes in generic loop)
_PASSTHROUGH_KEYS = ('lb_type', 'engine', 'instance_state', 'public_ip', 'publicly_accessible', 'tags')

OVERLY_PERMISSIVE_CIDRS = {
    '10.0.0.0/8': 8, '172.16.0.0/12': 12, '192.168.0.0/16': 16,
}


def _check_rules_for_public_exposure(rules, direction):
    vulns = []
    for rule in rules:
        protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')

        open_sources = []
        for r in (rule.get('IpRanges') or []):
            if r.get('CidrIp') == '0.0.0.0/0':
                open_sources.append('0.0.0.0/0')
        for r in (rule.get('Ipv6Ranges') or []):
            if r.get('CidrIpv6') == '::/0':
                open_sources.append('::/0')

        if not open_sources:
            continue

        if str(protocol) == '-1':
            for src in open_sources:
                vulns.append({
                    'port': 'ALL', 'protocol': 'ALL',
                    'service': 'All Traffic', 'source': src,
                    'severity': 'critical', 'direction': direction
                })
            continue

        if from_port is None or to_port is None:
            continue

        from_port = int(from_port)
        to_port = int(to_port)

        if from_port == to_port and from_port in SAFE_PUBLIC_PORTS:
            continue

        for port, (service, severity) in SENSITIVE_PORTS.items():
            if from_port <= port <= to_port:
                proto_str = 'TCP' if str(protocol) == '6' else str(protocol).upper()
                for src in open_sources:
                    vulns.append({
                        'port': str(port), 'protocol': proto_str,
                        'service': service, 'source': src,
                        'severity': severity, 'direction': direction
                    })
    return vulns


def _check_rules_for_permissive_private_cidrs(rules, direction):
    vulns = []
    for rule in rules:
        protocol = rule.get('IpProtocol', '')
        from_port = rule.get('FromPort')
        to_port = rule.get('ToPort')

        is_all_traffic = str(protocol) == '-1'
        is_all_ports = False
        if from_port is not None and to_port is not None:
            is_all_ports = (int(from_port) == 0 and int(to_port) == 65535)

        if not is_all_traffic and not is_all_ports:
            continue

        for r in (rule.get('IpRanges') or []):
            cidr = r.get('CidrIp', '')
            if cidr in OVERLY_PERMISSIVE_CIDRS:
                vulns.append({
                    'port': 'ALL' if is_all_traffic else '0-65535',
                    'protocol': 'ALL' if is_all_traffic else str(protocol).upper(),
                    'service': 'Overly permissive private CIDR',
                    'source': cidr, 'severity': 'medium', 'direction': direction
                })
    return vulns


def detect_sg_vulnerabilities(sg_rules, sg_info=None):
    vulnerabilities = {}

    for sg_id, rules in sg_rules.items():
        sg_vulns = []

        sg_vulns.extend(_check_rules_for_public_exposure(rules.get('ingress', []), 'ingress'))
        sg_vulns.extend(_check_rules_for_public_exposure(rules.get('egress', []), 'egress'))

        sg_vulns.extend(_check_rules_for_permissive_private_cidrs(rules.get('ingress', []), 'ingress'))
        sg_vulns.extend(_check_rules_for_permissive_private_cidrs(rules.get('egress', []), 'egress'))

        if sg_info and sg_id in sg_info:
            info = sg_info[sg_id]
            group_name = info.get('group_name', '')
            if group_name == 'default':
                has_ingress = len(rules.get('ingress', [])) > 0
                has_egress = len([r for r in rules.get('egress', [])
                                  if str(r.get('IpProtocol', '')) != '-1' or
                                  not any(ip.get('CidrIp') == '0.0.0.0/0'
                                          for ip in (r.get('IpRanges') or []))]) > 0
                if has_ingress or has_egress:
                    sg_vulns.append({
                        'port': 'N/A', 'protocol': 'N/A',
                        'service': 'Default SG with rules (CIS 5.4)',
                        'source': 'N/A', 'severity': 'medium', 'direction': 'compliance'
                    })

        if sg_vulns:
            vulnerabilities[sg_id] = sg_vulns

    return vulnerabilities


def detect_transitive_exposure(sg_rules):
    exposed_sgs = {}
    for sg_id in sg_rules:
        for rule in sg_rules[sg_id].get('ingress', []):
            for pair in (rule.get('UserIdGroupPairs') or []):
                source_sg = pair.get('GroupId', '')
                if not source_sg or source_sg not in sg_rules:
                    continue
                source_vulns = _check_rules_for_public_exposure(
                    sg_rules[source_sg].get('ingress', []), 'ingress')
                if source_vulns:
                    if sg_id not in exposed_sgs:
                        exposed_sgs[sg_id] = []
                    sources = set()
                    for v in source_vulns:
                        sources.add(v['source'])
                    for s in sources:
                        exposed_sgs[sg_id].append({
                            'exposed_via': source_sg, 'source': s
                        })
    return exposed_sgs


# ElastiCache Replication Group query
RG_QUERY = """
    SELECT replication_group_id, description, cache_node_type, member_clusters, account_id
    FROM aws_elasticache_replication_group
"""

def get_aws_profiles():
    """Discover all AWS profiles from ~/.aws/credentials"""
    credentials_path = os.path.expanduser('~/.aws/credentials')

    if not os.path.exists(credentials_path):
        logger.warning(f"⚠️  ~/.aws/credentials file not found")
        return []

    profiles = []
    with open(credentials_path, 'r') as f:
        for line in f:
            match = re.match(r'^\[([^\]]+)\]', line.strip())
            if match:
                profile_name = match.group(1)
                # 'default' profile is used without explicit name
                if profile_name == 'default':
                    profiles.append('default')
                else:
                    profiles.append(profile_name)

    return profiles

def setup_aggregator_config(profiles, regions=None):
    regions = regions or DEFAULT_REGIONS
    regions_str = json.dumps(regions)

    if os.path.exists(STEAMPIPE_CONFIG_PATH):
        backup_path = STEAMPIPE_CONFIG_PATH + '.backup.' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        shutil.copy2(STEAMPIPE_CONFIG_PATH, backup_path)
        logger.warning(f"   ⚠️  Existing config backed up to: {backup_path}")

    config_parts = []
    for profile in profiles:
        conn_name = f"aws_{profile}"
        config_parts.append(f'''connection "{conn_name}" {{
  plugin  = "aws"
  profile = "{profile}"
  regions = {regions_str}
}}''')

    # Aggregator connection named "aws" — uses default search path
    config_parts.append('''connection "aws" {
  plugin      = "aws"
  type        = "aggregator"
  connections = ["aws_*"]
}''')

    config_content = '\n\n'.join(config_parts) + '\n'

    with open(STEAMPIPE_CONFIG_PATH, 'w') as f:
        f.write(config_content)

    logger.info(f"   ✓ Steampipe aggregator config written: {', '.join(profiles)} → aws (aggregator)")

def reload_steampipe_service():
    subprocess.run(['steampipe', 'service', 'stop', '--force'], capture_output=True, check=False)
    _wait_for_steampipe_stopped()

    result = subprocess.run(['steampipe', 'service', 'start'], capture_output=True, text=True)

    if result.returncode != 0:
        if 'unknown state' in (result.stderr or '') or 'unknown state' in (result.stdout or ''):
            logger.warning("   ⚠️  Steampipe unknown state detected, terminating via PID file...")
            _kill_steampipe_by_pid()
            _wait_for_steampipe_stopped()
            subprocess.run(['steampipe', 'service', 'start'], capture_output=True, check=True)
        else:
            raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)

    if not _wait_for_steampipe_ready():
        logger.warning("   ⚠️  Steampipe service may not be fully ready")
    logger.info("   ✓ Steampipe service restarted")


def _kill_steampipe_by_pid():
    if not os.path.exists(STEAMPIPE_PID_PATH):
        subprocess.run(['steampipe', 'service', 'stop', '--force'], capture_output=True, check=False)
        return
    try:
        with open(STEAMPIPE_PID_PATH, 'r') as pf:
            pid = int(pf.read().strip())
        os.kill(pid, signal.SIGTERM)
        time.sleep(2)
        try:
            os.kill(pid, 0)
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    except (OSError, ValueError):
        pass


def _wait_for_steampipe_ready(timeout=None):
    timeout = timeout or SERVICE_READY_TIMEOUT_SECONDS
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(['steampipe', 'service', 'status'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'running' in result.stdout.lower():
            return True
        time.sleep(1)
    return False


def _wait_for_steampipe_stopped(timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(['steampipe', 'service', 'status'], capture_output=True, text=True, timeout=10)
        if result.returncode != 0 or 'running' not in result.stdout.lower():
            return True
        time.sleep(1)
    return False

def run_steampipe_query(query):
    """Execute Steampipe query"""
    try:
        result = subprocess.run(
            ['steampipe', 'query', query, '--output', 'json'],
            capture_output=True,
            text=True,
            check=True,
            timeout=QUERY_TIMEOUT_SECONDS
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        logger.error(f"   ❌ Query timed out after {QUERY_TIMEOUT_SECONDS}s")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"   ❌ Query failed: {e.stderr}")
        raise
    except json.JSONDecodeError as e:
        logger.error(f"   ❌ JSON parse failed: {e}")
        raise

def check_aws_cli_auth(profiles, region=None):
    region = region or DEFAULT_REGIONS[0]
    logger.info(f"   🔍 Checking AWS CLI authentication...")
    auth_ok = []
    for profile in profiles:
        try:
            result = subprocess.run(
                ['aws', 'sts', 'get-caller-identity', '--profile', profile, '--region', region],
                capture_output=True, text=True, check=True, timeout=30
            )
            identity = json.loads(result.stdout)
            logger.info(f"   ✓ {profile}: {identity.get('Account')}")
            auth_ok.append(profile)
        except subprocess.TimeoutExpired:
            logger.error(f"   ❌ {profile}: timeout")
        except subprocess.CalledProcessError as e:
            logger.error(f"   ❌ {profile}: auth failed - {e.stderr.strip()}")
        except json.JSONDecodeError:
            logger.error(f"   ❌ {profile}: response parse failed")
    return auth_ok

def get_all_account_identities(auth_ok_profiles):
    """Fetch account metadata via aggregator.
    Returns: {account_id: {profile_name, account_id, account_name}}
    """
    logger.info(f"   🔍 Fetching account info via Steampipe aggregator...")
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

            # Extract profile from connection_name: 'aws_myprofile' → 'myprofile'
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
            logger.info(f"   ✓ Account verified: {account_name} ({account_id}) [connection: {connection_name}]")

        # Detect partial failures
        if len(accounts) < len(auth_ok_profiles):
            found_profiles = {a['profile_name'] for a in accounts.values()}
            missing = [p for p in auth_ok_profiles if p not in found_profiles]
            if missing:
                logger.warning(f"   ⚠️  Missing profiles: {', '.join(missing)}")

        return accounts

    except Exception as e:
        logger.error(f"   ❌ Steampipe account query failed: {e}")
        return {}

def get_vpc_info():
    """Fetch VPC info via aggregator (all accounts in parallel).
    Returns: {account_id: {vpc_id: {name, color}}}
    """
    # Single query: VPC discovery (EC2 + SG VPCs via UNION) + account_id
    vpc_discovery_query = """
        SELECT DISTINCT vpc_id, account_id FROM aws_ec2_instance WHERE vpc_id IS NOT NULL
        UNION
        SELECT DISTINCT vpc_id, account_id FROM aws_vpc_security_group WHERE vpc_id IS NOT NULL
    """
    result = run_steampipe_query(vpc_discovery_query)

    # Group vpc_id by account_id
    vpcs_by_account = defaultdict(set)
    for row in result.get('rows', []):
        vpcs_by_account[row['account_id']].add(row['vpc_id'])

    # Single query: VPC names (eliminates N+1) + account_id
    vpc_names_query = "SELECT vpc_id, account_id, tags ->> 'Name' as vpc_name FROM aws_vpc"
    vpc_names_result = run_steampipe_query(vpc_names_query)
    vpc_names = {(row['account_id'], row['vpc_id']): row.get('vpc_name') or row['vpc_id']
                 for row in vpc_names_result.get('rows', [])}

    # Assign VPC colors per account (independent per-account)
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
    """Fetch EC2 instance info via aggregator"""
    query = """
    SELECT
        instance_id,
        tags ->> 'Name' as instance_name,
        instance_state,
        vpc_id,
        account_id,
        public_ip_address,
        tags,
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
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999'),
                'public_ip': row.get('public_ip_address'),
                'tags': row.get('tags') or {},
            }

        ec2_sg_map[instance_id].append(sg_id)

    return ec2_info, ec2_sg_map

def get_rds_instances(all_vpc_info):
    """Fetch RDS instance info via aggregator (ID prefixed for collision prevention)"""
    query = """
    SELECT
        db_instance_identifier,
        tags ->> 'Name' as db_name,
        engine,
        vpc_id,
        account_id,
        publicly_accessible,
        tags,
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

        # RDS IDs are user-specified, prefix with account_id to prevent collisions
        prefixed_id = f"{account_id}||{db_instance_id}"

        if prefixed_id not in rds_info:
            rds_info[prefixed_id] = {
                'name': row.get('db_name') or db_instance_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999'),
                'engine': row.get('engine', ''),
                'publicly_accessible': row.get('publicly_accessible', False),
                'tags': row.get('tags') or {},
            }

        rds_sg_map[prefixed_id].append(sg_id)

    return rds_info, rds_sg_map

def get_load_balancers(all_vpc_info):
    """Fetch Load Balancer (ALB/NLB) info via aggregator"""
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
            logger.warning(f"   ⚠️  {cfg['type']} query error: {e}")

    return lb_info, lb_sg_map

def get_vpc_endpoints(all_vpc_info):
    """Fetch VPC Endpoint info via aggregator"""
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
        logger.warning(f"   ⚠️  VPC Endpoint query error: {e}")

    return endpoint_info, endpoint_sg_map

def get_lambda_functions(all_vpc_info):
    """Fetch VPC Lambda function info via aggregator"""
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

            lambda_id = arn
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
        logger.warning(f"   ⚠️  Lambda function query error: {e}")

    return lambda_info, lambda_sg_map

def _run_query_with_connection_fallback(query, auth_ok_profiles):
    """Run aggregator query. Falls back to per-connection queries on AccessDenied."""
    try:
        return run_steampipe_query(query)
    except Exception as e:
        error_text = str(e) + (getattr(e, 'stderr', '') or '') + (getattr(e, 'stdout', '') or '')
        if 'AccessDenied' not in error_text and 'not authorized' not in error_text:
            raise

        logger.warning(f"   ⚠️  Aggregator access denied, retrying per-connection...")
        all_rows = []
        for profile in auth_ok_profiles:
            conn_name = f"aws_{profile}"
            try:
                result = subprocess.run(
                    ['steampipe', 'query', query,
                     '--search-path-prefix', conn_name,
                     '--output', 'json'],
                    capture_output=True, text=True, check=True,
                    timeout=QUERY_TIMEOUT_SECONDS
                )
                data = json.loads(result.stdout)
                all_rows.extend(data.get('rows', []))
            except Exception as conn_err:
                logger.warning(f"   ⚠️  Skipping connection {conn_name}: {conn_err}")
        return {'rows': all_rows}

def _fetch_elasticache_shared_data(auth_ok_profiles):
    """Fetch ElastiCache shared data once (aggregator with AccessDenied fallback)"""
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
    """Fetch ElastiCache cluster info via aggregator (ID prefixed)"""
    elasticache_info = {}
    elasticache_sg_map = {}

    try:
        # subnet_to_vpc: (account_id, subnet_group_name) → vpc_id (cross-account collision prevention)
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

            prefixed_id = f"{account_id}||{cluster_id}"
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
        logger.warning(f"   ⚠️  ElastiCache cluster query error: {e}")

    return elasticache_info, elasticache_sg_map

def get_elasticache_replication_groups(all_vpc_info, clusters_result, subnet_groups_result, rg_result):
    """Fetch ElastiCache replication group info via aggregator (ID prefixed)"""
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

            # Find VPC via member cluster
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

            prefixed_id = f"{account_id}||{group_id}"
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
        logger.warning(f"   ⚠️  ElastiCache replication group query error: {e}")

    return replication_group_info, replication_group_sg_map

def get_network_interfaces(all_vpc_info, known_ec2_ids=None):
    """Fetch network interface SG info via aggregator (safety net)"""
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
        logger.warning(f"   ⚠️  Network interface query error: {e}")

    return eni_info, eni_sg_map

def _resolve_vpc_from_sg(sg_id_list, sg_info):
    """Determine resource vpc_id via SG reverse lookup"""
    for sg_id in sg_id_list:
        sg = sg_info.get(sg_id)
        if sg and sg.get('vpc_id'):
            return sg['vpc_id']
    return None

def get_ecs_services(all_vpc_info, sg_info):
    """Fetch ECS Fargate service info via aggregator"""
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

            prefixed_id = f"{account_id}||{service_name}"
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
        logger.warning(f"   ⚠️  ECS service query error (skipping): {e}")

    return ecs_info, dict(ecs_sg_map)

def get_redshift_clusters(all_vpc_info):
    """Fetch Redshift cluster info via aggregator"""
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

            prefixed_id = f"{account_id}||{cluster_id}"
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
        logger.warning(f"   ⚠️  Redshift cluster query error (skipping): {e}")

    return redshift_info, dict(redshift_sg_map)

def get_opensearch_domains(all_vpc_info):
    """Fetch OpenSearch domain info via aggregator"""
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

            prefixed_id = f"{account_id}||{domain_name}"
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
        logger.warning(f"   ⚠️  OpenSearch domain query error (skipping): {e}")

    return opensearch_info, dict(opensearch_sg_map)

def get_docdb_clusters(all_vpc_info, sg_info):
    """Fetch DocumentDB cluster info via aggregator"""
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

            prefixed_id = f"{account_id}||{cluster_id}"
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
        logger.warning(f"   ⚠️  DocumentDB query error (skipping): {e}")

    return docdb_info, dict(docdb_sg_map)

def get_neptune_clusters(all_vpc_info, sg_info):
    """Fetch Neptune cluster info via aggregator"""
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

            prefixed_id = f"{account_id}||{cluster_id}"
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
        logger.warning(f"   ⚠️  Neptune query error (skipping): {e}")

    return neptune_info, dict(neptune_sg_map)

def get_memorydb_clusters(all_vpc_info, sg_info):
    """Fetch MemoryDB cluster info via aggregator"""
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

            prefixed_id = f"{account_id}||{cluster_name}"
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
        logger.warning(f"   ⚠️  MemoryDB query error (skipping): {e}")

    return memorydb_info, dict(memorydb_sg_map)


def get_eks_clusters(all_vpc_info):
    query = """
    SELECT name, arn, account_id, resources_vpc_config
    FROM aws_eks_cluster
    """
    eks_info = {}
    eks_sg_map = defaultdict(list)

    result = run_steampipe_query(query)
    for row in result.get('rows', []):
        cluster_name = row['name']
        account_id = row['account_id']
        vpc_config = row.get('resources_vpc_config') or {}
        vpc_id = vpc_config.get('vpc_id')
        sg_ids = vpc_config.get('security_group_ids') or []
        cluster_sg = vpc_config.get('cluster_security_group_id')
        vpc_info = all_vpc_info.get(account_id, {})

        prefixed_id = f"{account_id}||{cluster_name}"
        eks_info[prefixed_id] = {
            'name': cluster_name,
            'vpc_id': vpc_id,
            'account_id': account_id,
            'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999',
        }
        all_sgs = list(sg_ids)
        if cluster_sg and cluster_sg not in all_sgs:
            all_sgs.append(cluster_sg)
        eks_sg_map[prefixed_id] = all_sgs

    return eks_info, dict(eks_sg_map)


def get_efs_mount_targets(all_vpc_info):
    query = """
    SELECT mount_target_id, file_system_id, subnet_id, vpc_id, account_id, security_groups
    FROM aws_efs_mount_target
    """
    efs_info = {}
    efs_sg_map = defaultdict(list)

    result = run_steampipe_query(query)
    for row in result.get('rows', []):
        fs_id = row['file_system_id']
        account_id = row['account_id']
        vpc_id = row.get('vpc_id')
        sg_ids = row.get('security_groups') or []
        vpc_info = all_vpc_info.get(account_id, {})

        prefixed_id = f"{account_id}||{fs_id}"
        if prefixed_id not in efs_info:
            efs_info[prefixed_id] = {
                'name': fs_id,
                'vpc_id': vpc_id,
                'account_id': account_id,
                'color': vpc_info.get(vpc_id, {}).get('color', '#999999') if vpc_id else '#999999',
            }
            efs_sg_map[prefixed_id] = []

        for sg_id in sg_ids:
            if sg_id not in efs_sg_map[prefixed_id]:
                efs_sg_map[prefixed_id].append(sg_id)

    return efs_info, dict(efs_sg_map)


def get_security_groups_and_rules(all_vpc_info):
    """Fetch SG info and rules in single query via aggregator"""
    query = """
        SELECT group_id, group_name, vpc_id, account_id,
               description, tags,
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
            'group_name': row['group_name'],
            'vpc_id': vpc_id,
            'account_id': account_id,
            'color': vpc_info.get(vpc_id, {}).get('color', '#999999'),
            'description': row.get('description', ''),
            'tags': row.get('tags') or {},
        }
        for rule in (row.get('ip_permissions') or []):
            sg_rules[sg_id]['ingress'].append(rule)
        for rule in (row.get('ip_permissions_egress') or []):
            sg_rules[sg_id]['egress'].append(rule)

    return sg_info, dict(sg_rules)

def enrich_nodes_with_account(nodes, account_metadata):
    """Add account info to nodes and prefix IDs with profile"""
    profile = account_metadata['profile_name']

    enriched_nodes = []
    for node in nodes:
        enriched_node = node.copy()
        # Add profile prefix to ID (collision prevention)
        enriched_node['id'] = f"{profile}:{node['id']}"
        # Also prefix VPC ID
        if 'vpc_id' in enriched_node and enriched_node['vpc_id']:
            enriched_node['vpc_id'] = f"{profile}:{enriched_node['vpc_id']}"
        # Add account metadata
        enriched_node['account_id'] = account_metadata['account_id']
        enriched_node['account_name'] = account_metadata['account_name']
        enriched_node['profile_name'] = profile
        enriched_nodes.append(enriched_node)

    return enriched_nodes

def enrich_edges_with_account(edges, account_metadata):
    """Add account prefix to edges"""
    profile = account_metadata['profile_name']

    enriched_edges = []
    for edge in edges:
        enriched_edge = edge.copy()
        # Add profile prefix to From/To IDs
        enriched_edge['from'] = f"{profile}:{edge['from']}"
        enriched_edge['to'] = f"{profile}:{edge['to']}"
        # Add account ID
        enriched_edge['account_id'] = account_metadata['account_id']
        enriched_edges.append(enriched_edge)

    return enriched_edges

def enrich_vpc_info_with_account(vpc_info, account_metadata):
    """Add account prefix to VPC info"""
    profile = account_metadata['profile_name']

    enriched_vpc_info = {}
    for vpc_id, info in vpc_info.items():
        prefixed_vpc_id = f"{profile}:{vpc_id}"
        enriched_vpc_info[prefixed_vpc_id] = info.copy()

    return enriched_vpc_info

def enrich_sg_rules_with_account(sg_rules, account_metadata):
    """Add account prefix to SG rules"""
    profile = account_metadata['profile_name']

    enriched_sg_rules = {}
    for sg_id, rules in sg_rules.items():
        prefixed_sg_id = f"{profile}:{sg_id}"
        enriched_sg_rules[prefixed_sg_id] = rules

    return enriched_sg_rules

def generate_nodes_and_edges(resources, sg_info, sg_rules, extra_used_sgs=None):
    """Generate node and edge data (generic loop based on ResourceData)"""
    all_nodes = []
    all_edges = []
    used_sgs = set(extra_used_sgs) if extra_used_sgs else set()

    # Create resource nodes + edges (generic loop)
    for rd in resources:
        for res_id, info in rd.info.items():
            label = info.get('name', res_id)

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


    vulnerabilities = detect_sg_vulnerabilities(sg_rules, sg_info)
    transitive = detect_transitive_exposure(sg_rules)


    for sg_id, info in sg_info.items():
        sg_vulns = vulnerabilities.get(sg_id, [])
        all_nodes.append({
            'id': sg_id,
            'label': info['name'],
            'group': 'sg',
            'vpc_id': info['vpc_id'],
            'is_unused': sg_id not in used_sgs,
            'is_vulnerable': len(sg_vulns) > 0,
            'vulnerabilities': sg_vulns,
            'description': info.get('description', ''),
            'tags': info.get('tags') or {},
            'transitive_exposure': transitive.get(sg_id, []),
        })


    for sg_id, rules in sg_rules.items():

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


    for node in all_nodes:
        if node.get('group') == 'sg':
            node['is_unused'] = node['id'] not in used_sgs

    return all_nodes, all_edges

def _partition_by_account(info_dict, sg_map_dict):
    """Partition (info_dict, sg_map) by account_id.
    prefixed key (account_id||res_id) → restore original res_id."""
    by_account = {}
    for res_id, info in info_dict.items():
        acct = info.get('account_id')
        if acct not in by_account:
            by_account[acct] = ({}, {})
        original_id = res_id.split('||', 1)[1] if '||' in res_id else res_id
        by_account[acct][0][original_id] = info
        if res_id in sg_map_dict:
            by_account[acct][1][original_id] = sg_map_dict[res_id]
    return by_account

def _partition_sg_rules(sg_info, sg_rules):
    """Partition SG info/rules by account_id (SG IDs are globally unique)"""
    by_account = {}
    for sg_id, info in sg_info.items():
        acct = info.get('account_id')
        if acct not in by_account:
            by_account[acct] = ({}, {})
        by_account[acct][0][sg_id] = info
        if sg_id in sg_rules:
            by_account[acct][1][sg_id] = sg_rules[sg_id]
    return by_account

def collect_multi_account_data(args=None):
    """Aggregator mode: single config + restart + ~18 parallel queries across all accounts"""
    profiles = get_aws_profiles()
    regions = getattr(args, 'regions', None) or DEFAULT_REGIONS
    skip_config = getattr(args, 'skip_config', False)

    if not profiles:
        logger.warning("⚠️  No AWS profiles found")
        logger.info("   Please check ~/.aws/credentials")
        sys.exit(1)

    logger.info(f"📋 Discovered AWS profiles: {', '.join(profiles)}\n")


    auth_ok_profiles = check_aws_cli_auth(profiles, region=regions[0])
    if not auth_ok_profiles:
        logger.warning(f"⚠️  All profiles auth failed")
        sys.exit(1)

    if len(auth_ok_profiles) < len(profiles):
        failed = [p for p in profiles if p not in auth_ok_profiles]
        logger.warning(f"   ⚠️  Excluding failed profiles: {', '.join(failed)}")


    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info(f"🔧 Configuring Steampipe Aggregator...")
    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    if not skip_config:
        setup_aggregator_config(auth_ok_profiles, regions=regions)
        reload_steampipe_service()
    else:
        logger.info("   ⏭️  Skipping Steampipe config (--skip-config)")


    accounts = get_all_account_identities(auth_ok_profiles)
    if not accounts:
        logger.warning(f"⚠️  Data collection failed for all profiles")
        sys.exit(1)


    account_colors = ['#667eea', '#764ba2', '#f093fb', '#4facfe', '#43e97b', '#fa709a', '#30cfd0', '#a8edea']
    for idx, (account_id, meta) in enumerate(sorted(accounts.items())):
        meta['color'] = account_colors[idx % len(account_colors)]


    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info(f"📊 Collecting all account resources via aggregator...")
    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    all_vpc_info = get_vpc_info()


    logger.info(f"   ⏱  Starting parallel queries...")
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
                logger.info(f"   ✓ {label}: {info_count}")
            except Exception as e:
                logger.warning(f"   ⚠️  {label} query failed (skipping): {e}")
                results[label] = ({}, {})

    parallel_elapsed = time.time() - parallel_start
    logger.info(f"   ⏱  Parallel queries completed: {parallel_elapsed:.1f}s")


    sg_info, sg_rules = results.get('SG', ({}, {}))
    if not sg_info:
        logger.error("❌ FATAL: Security Group query failed or no results. Aborting.")
        sys.exit(1)
    logger.info(f"   ✓ Security Group: {len(sg_info)}")


    ec2_info, ec2_sg_map = results.get('EC2', ({}, {}))
    rds_info, rds_sg_map = results.get('RDS', ({}, {}))
    lb_info, lb_sg_map = results.get('LB', ({}, {}))
    endpoint_info, endpoint_sg_map = results.get('VPC Endpoint', ({}, {}))
    lambda_info, lambda_sg_map = results.get('Lambda', ({}, {}))
    clusters_raw, subnet_groups_raw = results.get('ElastiCache Shared', ({}, {}))


    try:
        elasticache_info, elasticache_sg_map = get_elasticache_clusters(
            all_vpc_info, clusters_raw, subnet_groups_raw)
    except Exception as e:
        logger.warning(f"   ⚠️  ElastiCache cluster query failed (skipping): {e}")
        elasticache_info, elasticache_sg_map = {}, {}
    logger.info(f"   ✓ ElastiCache Cluster: {len(elasticache_info)}")

    try:
        rg_raw = _run_query_with_connection_fallback(RG_QUERY, auth_ok_profiles)
        elasticache_groups, elasticache_group_sg_map = get_elasticache_replication_groups(
            all_vpc_info, clusters_raw, subnet_groups_raw, rg_raw)
    except Exception as e:
        logger.warning(f"   ⚠️  ElastiCache replication group query failed (skipping): {e}")
        elasticache_groups, elasticache_group_sg_map = {}, {}
    logger.info(f"   ✓ ElastiCache RG: {len(elasticache_groups)}")


    try:
        ecs_info, ecs_sg_map = get_ecs_services(all_vpc_info, sg_info)
    except Exception as e:
        logger.warning(f"   ⚠️  ECS service query failed (skipping): {e}")
        ecs_info, ecs_sg_map = {}, {}
    logger.info(f"   ✓ ECS: {len(ecs_info)}")

    try:
        redshift_info, redshift_sg_map = get_redshift_clusters(all_vpc_info)
    except Exception as e:
        logger.warning(f"   ⚠️  Redshift cluster query failed (skipping): {e}")
        redshift_info, redshift_sg_map = {}, {}
    logger.info(f"   ✓ Redshift: {len(redshift_info)}")

    try:
        opensearch_info, opensearch_sg_map = get_opensearch_domains(all_vpc_info)
    except Exception as e:
        logger.warning(f"   ⚠️  OpenSearch domain query failed (skipping): {e}")
        opensearch_info, opensearch_sg_map = {}, {}
    logger.info(f"   ✓ OpenSearch: {len(opensearch_info)}")


    try:
        docdb_info, docdb_sg_map = get_docdb_clusters(all_vpc_info, sg_info)
    except Exception as e:
        logger.warning(f"   ⚠️  DocumentDB query failed (skipping): {e}")
        docdb_info, docdb_sg_map = {}, {}
    logger.info(f"   ✓ DocumentDB: {len(docdb_info)}")

    try:
        neptune_info, neptune_sg_map = get_neptune_clusters(all_vpc_info, sg_info)
    except Exception as e:
        logger.warning(f"   ⚠️  Neptune query failed (skipping): {e}")
        neptune_info, neptune_sg_map = {}, {}
    logger.info(f"   ✓ Neptune: {len(neptune_info)}")

    try:
        memorydb_info, memorydb_sg_map = get_memorydb_clusters(all_vpc_info, sg_info)
    except Exception as e:
        logger.warning(f"   ⚠️  MemoryDB query failed (skipping): {e}")
        memorydb_info, memorydb_sg_map = {}, {}
    logger.info(f"   ✓ MemoryDB: {len(memorydb_info)}")

    try:
        eks_info, eks_sg_map = get_eks_clusters(all_vpc_info)
    except Exception as e:
        logger.info(f"   EKS query error (skipping): {e}")
        eks_info, eks_sg_map = {}, {}
    logger.info(f"   ✓ EKS: {len(eks_info)}")

    try:
        efs_info, efs_sg_map = get_efs_mount_targets(all_vpc_info)
    except Exception as e:
        logger.info(f"   EFS query error (skipping): {e}")
        efs_info, efs_sg_map = {}, {}
    logger.info(f"   ✓ EFS: {len(efs_info)}")


    known_ec2_ids = set(ec2_info.keys())
    try:
        eni_info, eni_sg_map = get_network_interfaces(all_vpc_info, known_ec2_ids=known_ec2_ids)
    except Exception as e:
        logger.warning(f"   ⚠️  Network interface query failed (skipping): {e}")
        eni_info, eni_sg_map = {}, {}
    logger.info(f"   ✓ ENI (safety net): {len(eni_sg_map)}")


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

    eks_by_acct = _partition_by_account(eks_info, eks_sg_map)
    efs_by_acct = _partition_by_account(efs_info, efs_sg_map)
    eni_by_acct = _partition_by_account(eni_info, eni_sg_map) if eni_info else {}
    sg_by_acct = _partition_sg_rules(sg_info, sg_rules)


    all_data = {
        'nodes': [],
        'edges': [],
        'sg_rules': {},
        'vpc_info': {},
        'account_info': {}
    }

    for account_id, account_meta in accounts.items():
        profile = account_meta['profile_name']


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
        acct_eks, acct_eks_sg = eks_by_acct.get(account_id, ({}, {}))
        acct_efs, acct_efs_sg = efs_by_acct.get(account_id, ({}, {}))
        acct_eni_info, acct_eni_sg = eni_by_acct.get(account_id, ({}, {}))
        acct_sg_info, acct_sg_rules = sg_by_acct.get(account_id, ({}, {}))
        acct_vpc_info = all_vpc_info.get(account_id, {})


        if not acct_eni_info and eni_sg_map:
            acct_eni_sg_fallback = {}
            for eni_id, sg_list in eni_sg_map.items():
                for sg_id in sg_list:
                    if sg_id in acct_sg_info:
                        acct_eni_sg_fallback[eni_id] = sg_list
                        break
            if acct_eni_sg_fallback:
                acct_eni_sg = acct_eni_sg_fallback


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
            ResourceData('eks', acct_eks, acct_eks_sg),
            ResourceData('efs', acct_efs, acct_efs_sg),
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

        logger.info(f"   ✓ {account_meta['account_name']} ({profile}): {len(enriched_nodes)} nodes, {len(enriched_edges)} edges")


    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info(f"📊 Data collection complete")
    logger.info(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    logger.info(f"✅ Success: {len(accounts)} accounts")
    for profile, info in all_data['account_info'].items():
        logger.info(f"   - {info['account_name']} ({profile}): {info['node_count']} nodes")

    logger.info(f"📈 Overall statistics:")
    logger.info(f"   - Total nodes: {len(all_data['nodes'])}")
    logger.info(f"   - Total edges: {len(all_data['edges'])}")
    logger.info(f"   - Total VPCs: {len(all_data['vpc_info'])}")

    return all_data

def update_html_template(template_file, nodes, edges, sg_rules, vpc_info, account_info):
    """Inject data between DATA SECTION markers in template HTML file"""

    START_MARKER = '// ===== DATA SECTION (replaced by Python script) ====='
    END_MARKER = '// ===== END DATA SECTION ====='

    with open(template_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    try:
        start_idx = html_content.index(START_MARKER)
    except ValueError:
        raise ValueError(
            f"Start marker not found in {template_file}. "
            f"Expected: {START_MARKER!r}"
        )
    try:
        end_idx = html_content.index(END_MARKER) + len(END_MARKER)
    except ValueError:
        raise ValueError(
            f"End marker not found in {template_file}. "
            f"Expected: {END_MARKER!r}"
        )


    def _safe_json(obj):
        return json.dumps(obj, indent=8, ensure_ascii=False).replace('</', '<\\/')

    data_section = f"""{START_MARKER}
        const nodesData = {_safe_json(nodes)};
        const edgesData = {_safe_json(edges)};
        const sgRules = {_safe_json(sg_rules)};
        const vpcInfo = {_safe_json(vpc_info)};
        const accountInfo = {_safe_json(account_info)};
        {END_MARKER}"""

    return html_content[:start_idx] + data_section + html_content[end_idx:]

def main():
    args = parse_args()
    configure_logging(verbose=args.verbose)
    logger.info("🚀 Security Group Review Dashboard - Multi-account data collection starting...\n")

    all_data = collect_multi_account_data(args)

    if not all_data['nodes']:
        logger.warning("\n⚠️  No data collected")
        sys.exit(1)

    logger.info("🎨 Generating HTML dashboard...")

    html_content = update_html_template(
        args.template,
        all_data['nodes'],
        all_data['edges'],
        all_data['sg_rules'],
        all_data['vpc_info'],
        all_data['account_info']
    )

    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(html_content)

    logger.info(f"✅ Done! Generated: {args.output}")
    logger.info("🌐 Usage:")
    logger.info("   python3 -m http.server 8080")
    logger.info(f"   http://localhost:8080/{args.output}")

if __name__ == '__main__':
    main()
