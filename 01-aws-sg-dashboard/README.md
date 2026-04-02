# AWS Security Group Review Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

[한국어 README](README.ko.md)

An interactive dashboard that visualizes AWS Security Group relationships across multi-account environments. Collects data from **15 AWS resource types** via [Steampipe](https://steampipe.io), performs automated security analysis, and generates a self-contained HTML dashboard.

![Demo](demo.gif)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Workstation                          │
│                                                             │
│  ~/.aws/credentials ──→ extract_and_visualize_v2.py         │
│    [profile prod]         │                                 │
│    [profile dev]          ├── 1. Configure Steampipe        │
│    [profile staging]      │      Aggregator                 │
│                           │                                 │
│                           ├── 2. Parallel Steampipe Queries │
│                           │      (18 queries, 3 waves)      │
│                           │                                 │
│                           ├── 3. Security Analysis          │
│                           │      • Ingress/Egress scan      │
│                           │      • Default SG audit         │
│                           │      • CIDR permissiveness      │
│                           │      • Transitive exposure      │
│                           │                                 │
│                           └── 4. Generate HTML Dashboard    │
│                                  sg_interactive_graph.html  │
│                                         │                   │
│  Browser ◀──── python3 -m http.server ──┘                   │
└─────────────────────────────────────────────────────────────┘
         │
         ▼  (Steampipe queries via AWS API)
┌─────────────────────────────────────────────────────────────┐
│  AWS Account(s)                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐                    │
│  │ prod     │ │ dev      │ │ staging  │  ...                │
│  │ EC2, RDS │ │ EKS, ECS │ │ Lambda   │                    │
│  │ SG, VPC  │ │ SG, VPC  │ │ SG, VPC  │                    │
│  └──────────┘ └──────────┘ └──────────┘                    │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Profile Discovery** — Reads `~/.aws/credentials` to find all AWS profiles
2. **Authentication Check** — Validates each profile via `aws sts get-caller-identity`
3. **Steampipe Aggregator Setup** — Generates a single aggregator config combining all profiles (backs up existing config)
4. **Parallel Data Collection** — 18 queries in 3 waves:
   - **Wave 1**: EC2, RDS, ALB/NLB, Lambda, VPC Endpoints, Security Groups, ElastiCache (parallel)
   - **Wave 2**: Redshift, OpenSearch, EKS, EFS, ElastiCache post-processing, ENIs (parallel)
   - **Wave 3**: ECS, DocumentDB, Neptune, MemoryDB (parallel, depends on SG data)
5. **Security Analysis** — Vulnerability detection on collected rules
6. **HTML Generation** — Injects JSON data into the template, outputs a self-contained HTML file

## Prerequisites

### 1. Python 3.8+

```bash
python3 --version  # Must be 3.8 or higher
```

### 2. Steampipe + AWS Plugin

```bash
# Install Steampipe
# macOS
brew tap turbot/tap && brew install steampipe

# Linux
sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"

# Install the AWS plugin
steampipe plugin install aws

# Verify
steampipe --version
```

### 3. AWS CLI + Credentials

```bash
# Install AWS CLI (if not present)
# https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Configure at least one profile
aws configure --profile my-profile

# Verify authentication
aws sts get-caller-identity --profile my-profile
```

The script auto-detects **all profiles** in `~/.aws/credentials`. Each profile becomes a separate connection in the Steampipe aggregator.

### 4. Required IAM Permissions

The IAM user/role for each profile needs **read-only** access to the following services:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SGDashboardReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeInstances",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeNetworkInterfaces",
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "ecs:ListClusters",
        "ecs:ListServices",
        "ecs:DescribeServices",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:DescribeReplicationGroups",
        "redshift:DescribeClusters",
        "es:DescribeDomains",
        "es:ListDomainNames",
        "rds:DescribeDBClusters",
        "neptune:DescribeDBClusters",
        "memorydb:DescribeClusters",
        "eks:ListClusters",
        "eks:DescribeCluster",
        "elasticfilesystem:DescribeMountTargets",
        "elasticfilesystem:DescribeFileSystems",
        "sts:GetCallerIdentity",
        "iam:ListAccountAliases"
      ],
      "Resource": "*"
    }
  ]
}
```

> **Tip**: The AWS managed policy `ReadOnlyAccess` covers all of the above. For least-privilege, use the policy above.

## Installation

```bash
git clone https://github.com/zer0-kr/security-compliance-engineering-tools.git
cd security-compliance-engineering-tools/01-aws-sg-dashboard
```

No additional Python packages required — the script uses only the standard library.

For development (running tests):
```bash
pip install pytest
```

## Usage

### Quick Start

```bash
# Generate dashboard for all profiles in default region (us-east-1)
python3 extract_and_visualize_v2.py

# Open in browser
python3 -m http.server 8080
# Visit http://localhost:8080/sg_interactive_graph_v2.html
```

### Common Options

```bash
# Specific regions
python3 extract_and_visualize_v2.py --regions ap-northeast-2 us-west-2

# Skip Steampipe config regeneration (faster on subsequent runs)
python3 extract_and_visualize_v2.py --skip-config

# Custom output file
python3 extract_and_visualize_v2.py -o my-review.html

# Verbose logging
python3 extract_and_visualize_v2.py -v
```

### CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `--regions` | `$AWS_DEFAULT_REGION` or `us-east-1` | AWS regions to query (space-separated) |
| `--skip-config` | `false` | Skip Steampipe aggregator config generation |
| `--output`, `-o` | `sg_interactive_graph_v2.html` | Output HTML file path |
| `--template` | `sg_dashboard_template.html` | Path to the HTML template file |
| `--verbose`, `-v` | `false` | Enable debug-level logging |

## Supported Resource Types (15)

| Resource | Steampipe Table | What's Collected |
|----------|----------------|-----------------|
| EC2 | `aws_ec2_instance` | instance ID, name, state, VPC, SGs, public IP, tags |
| RDS | `aws_rds_db_instance` | DB identifier, engine, VPC, SGs, publicly_accessible, tags |
| ALB/NLB | `aws_ec2_application_load_balancer` + `aws_ec2_network_load_balancer` | LB name, type, VPC, SGs |
| Lambda | `aws_lambda_function` | function name, VPC, SGs (VPC-attached only) |
| ECS | `aws_ecs_service` | service name, VPC, SGs (Fargate) |
| ElastiCache | `aws_elasticache_cluster` + `aws_elasticache_replication_group` | cluster/RG ID, VPC, SGs |
| VPC Endpoints | `aws_vpc_endpoint` | endpoint ID, service name, VPC, SGs |
| Redshift | `aws_redshift_cluster` | cluster ID, VPC, SGs |
| OpenSearch | `aws_opensearch_domain` | domain name, VPC, SGs |
| DocumentDB | `aws_docdb_cluster` | cluster ID, VPC, SGs |
| Neptune | `aws_neptune_db_cluster` | cluster ID, VPC, SGs |
| MemoryDB | `aws_memorydb_cluster` | cluster name, VPC, SGs |
| EKS | `aws_eks_cluster` | cluster name, VPC, SGs |
| EFS | `aws_efs_mount_target` | file system ID, VPC, SGs |
| ENI | `aws_ec2_network_interface` | SG associations (safety net for unused SG detection) |

## Security Analysis

| Check | Severity | Description |
|-------|----------|-------------|
| **Public ingress on sensitive ports** | Critical/High | Detects `0.0.0.0/0` or `::/0` on SSH(22), RDP(3389), MySQL(3306), PostgreSQL(5432), Redis(6379), MongoDB(27017), and 10 more |
| **Public egress on sensitive ports** | Critical/High | Same analysis on outbound rules |
| **Default SG with rules (CIS 5.4)** | Medium | Flags default security groups that have any non-default rules |
| **Overly permissive private CIDRs** | Medium | Detects `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` with all-traffic or all-ports access |
| **Cross-SG transitive exposure** | Warning | If SG-A allows ingress from SG-B, and SG-B allows `0.0.0.0/0`, then SG-A is flagged as indirectly exposed |
| **Unused security groups** | Info | SGs not attached to any resource or ENI |

## Dashboard Features

### Filtering
- **Account filter** — view resources per AWS account with color coding
- **VPC filter** — select VPCs independently within chosen accounts
- **Resource type filter** — show/hide any of the 15 resource types
- **Search** — filter nodes by name or ID
- **Unused SG toggle** — show/hide unused security groups

### Detail Panel (click any node)
- Full inbound/outbound rules table with descriptions
- Vulnerability warnings with direction labels (↓IN / ↑OUT)
- Transitive exposure warnings
- EC2 public IP, RDS publicly_accessible badges
- Tags display
- Connected SGs / attached resources navigation

### Export
- **PNG** — export graph as image
- **XLSX** — download unused and vulnerable SG lists as spreadsheets

### Keyboard Shortcuts
| Key | Action |
|-----|--------|
| `/` | Focus search input |
| `Escape` | Close detail panel |
| `f` | Fit graph to viewport |

## Project Structure

```
01-aws-sg-dashboard/
├── extract_and_visualize_v2.py  # Data collection + HTML generation (Python)
├── sg_dashboard_template.html   # Dashboard UI template (vis.js, no data)
├── tests/                       # Unit tests (pytest)
│   ├── test_vulnerability_detection.py
│   ├── test_partition.py
│   └── test_template_injection.py
├── pyproject.toml               # Project metadata
├── LICENSE                      # MIT License
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contribution guidelines
├── README.md                    # This file
└── README.ko.md                 # Korean README
```

## Security Notice

Generated HTML files contain **real AWS infrastructure data** including account IDs, resource IDs, IP ranges, and security group rules. The `.gitignore` excludes generated files, but:

- **Never** commit `sg_interactive_graph_v2.html` to version control
- **Never** share generated files on public channels
- Use `--output` to name files clearly (e.g., `review-2025-01.html`)

## Troubleshooting

### "steampipe: command not found"
```bash
curl -fsSL https://steampipe.io/install/steampipe.sh | sh
steampipe plugin install aws
```

### "Could not load AWS credentials"
```bash
aws sts get-caller-identity --profile <your-profile>
# If SSO: aws sso login --profile <your-profile>
steampipe service restart
```

### Empty graph / no data
```bash
# Test Steampipe queries directly
steampipe query "SELECT count(*) FROM aws_vpc_security_group"
steampipe query "SELECT count(*) FROM aws_ec2_instance"
```

### Slow execution
```bash
# Skip config regeneration on subsequent runs
python3 extract_and_visualize_v2.py --skip-config

# Limit regions
python3 extract_and_visualize_v2.py --regions us-east-1
```

## Running Tests

```bash
pip install pytest  # one-time setup
python3 -m pytest tests/ -v
```

## References

- [Steampipe Documentation](https://steampipe.io/docs)
- [Steampipe AWS Plugin](https://hub.steampipe.io/plugins/turbot/aws)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [vis.js Network Documentation](https://visjs.github.io/vis-network/docs/network/)

## License

MIT License — see [LICENSE](LICENSE) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.
