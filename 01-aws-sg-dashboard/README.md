# Security Group Review Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

An interactive dashboard for reviewing AWS Security Groups across multi-account environments. Collects data from 15 resource types via [Steampipe](https://steampipe.io) and generates a self-contained HTML dashboard with [vis.js](https://visjs.org) network graph visualization.

## Security

**Warning:** Generated HTML files (`sg_interactive_graph_v2.html`) contain real AWS resource data including account IDs, resource IDs, IP ranges, and security group rules. Never commit these files to version control or share them publicly. The `.gitignore` already excludes them.

## Project Structure

```
sg-dashboard/
├── extract_and_visualize_v2.py  # Data collection + HTML generation script
├── sg_dashboard_template.html   # UI template (no data, safe to commit)
├── tests/                       # Test suite
├── pyproject.toml               # Project metadata and dependencies
├── LICENSE                      # MIT License
├── .gitignore                   # Excludes generated HTML files
└── README.md
```

**Committed to git:** template + scripts (no sensitive data)  
**Not committed:** generated HTML files containing real AWS data

## Prerequisites

### 1. Steampipe

```bash
# macOS/Linux
brew tap turbot/tap
brew install steampipe

# Install the AWS plugin
steampipe plugin install aws
```

### 2. AWS credentials

```bash
# Verify credentials
aws sts get-caller-identity

# If your token has expired
aws sso login --profile <your-profile>
```

### 3. Multi-account setup

The script auto-detects all AWS profiles in `~/.aws/credentials`.

```bash
# List configured profiles
aws configure list-profiles

# Verify each profile
aws sts get-caller-identity --profile <profile-name>
```

To add a new account:
```bash
aws configure --profile new-profile-name
```

## Installation

```bash
git clone https://github.com/zer0-kr/security-compliance-engineering-tools.git
cd sg-dashboard

chmod +x extract_and_visualize_v2.py
```

## Usage

### Workflow

```
sg_dashboard_template.html          # UI template managed in git
        │
        └── extract_and_visualize_v2.py ──→ sg_interactive_graph_v2.html (real data)
```

### Generate the dashboard

```bash
# Basic usage — queries all configured AWS profiles
python3 extract_and_visualize_v2.py

# Limit to specific regions
python3 extract_and_visualize_v2.py --regions us-east-1 eu-west-1

# Skip Steampipe config regeneration (faster if config is already set up)
python3 extract_and_visualize_v2.py --skip-config

# Write output to a custom file
python3 extract_and_visualize_v2.py --output my-dashboard.html

# Use a custom HTML template
python3 extract_and_visualize_v2.py --template my_template.html

# Verbose logging
python3 extract_and_visualize_v2.py --verbose
```

**CLI flags:**

| Flag | Description |
|------|-------------|
| `--regions` | Space-separated list of AWS regions to query (default: `$AWS_DEFAULT_REGION` or `us-east-1`) |
| `--skip-config` | Skip Steampipe aggregator config generation |
| `--output`, `-o` | Output HTML file path (default: `sg_interactive_graph_v2.html`) |
| `--template` | Path to the HTML template file |
| `--verbose`, `-v` | Enable verbose logging |

The script automatically:
1. Detects all AWS profiles from `~/.aws/credentials`
2. Configures the Steampipe Aggregator and runs 3-wave parallel queries
3. Collects 15 resource types: EC2, RDS, ALB/NLB, Lambda, ECS, ElastiCache, VPC Endpoints, Redshift, OpenSearch, DocumentDB, Neptune, MemoryDB, EKS, EFS, and ENIs
4. Runs security analysis (ingress + egress vulnerabilities, default SG audit, permissive CIDR detection, cross-SG transitive exposure)
5. Injects data into `sg_dashboard_template.html`
6. Writes `sg_interactive_graph_v2.html`

### Open the dashboard

```bash
# Recommended: serve via HTTP (required for some browser security policies)
python3 -m http.server 8080
# Then open http://localhost:8080/sg_interactive_graph_v2.html

# Or open directly
open sg_interactive_graph_v2.html  # macOS
```

### Run tests

```bash
python3 -m pytest tests/ -v
```

## Features

### Supported resource types (15)

EC2, RDS, ALB/NLB, Lambda, ECS (Fargate), ElastiCache (clusters + replication groups), VPC Endpoints, Redshift, OpenSearch, DocumentDB, Neptune, MemoryDB, EKS, EFS, ENIs (as safety net for unused SG detection)

### Security analysis

- **Ingress vulnerability detection:** sensitive ports open to `0.0.0.0/0` or `::/0` (SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB, and 10 more)
- **Egress vulnerability detection:** same analysis on outbound rules
- **Default SG audit (CIS 5.4):** flags default security groups that have any non-default rules
- **Overly permissive private CIDRs:** detects `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` with all-traffic or all-ports access
- **Cross-SG transitive exposure:** if SG-A allows ingress from SG-B, and SG-B is open to `0.0.0.0/0`, SG-A is flagged as indirectly exposed
- **Unused SG identification:** flags security groups not attached to any resource or ENI
- **XLSX export:** download vulnerable and unused SG lists as spreadsheets

### Multi-account filtering

- **Account filter:** per-account resource view with color coding
- **VPC filter:** independent VPC selection within selected accounts
- **Type filter:** filter by any of the 15 resource types

### Interactive visualization

- **Detail panel:** click any node to see SG rules (inbound/outbound), description, tags, vulnerabilities, transitive exposure warnings, public IP, and publicly accessible flags
- **Public accessibility indicators:** EC2 public IP and RDS `publicly_accessible` shown with warning badges
- **Tags display:** resource and SG tags displayed in detail panel
- **Keyboard shortcuts:** `/` to search, `Escape` to close panel, `f` to fit view
- **SG-to-SG references:** cross-reference edges between security groups
- **Node sizing:** scales with connection count, color-coded per VPC

## How it works

```
extract_and_visualize_v2.py
      ↓
Configure Steampipe Aggregator (all AWS profiles)
      ↓
Wave 1 — parallel queries (independent)
      ├─ EC2, RDS, ALB/NLB, Lambda, VPC Endpoints
      ├─ Security Groups + Rules, ElastiCache shared data
      └─ VPC metadata
      ↓
Wave 2 — parallel queries (depend on Wave 1)
      ├─ Redshift, OpenSearch, EKS, EFS, ENIs
      └─ ElastiCache clusters + replication groups
      ↓
Wave 3 — parallel queries (depend on SG data)
      └─ ECS, DocumentDB, Neptune, MemoryDB
      ↓
Security analysis
      ├─ Ingress + egress vulnerability scan
      ├─ Default SG audit (CIS 5.4)
      ├─ Permissive private CIDR detection
      └─ Cross-SG transitive exposure
      ↓
Inject data between DATA SECTION markers in sg_dashboard_template.html
      ↓
Write sg_interactive_graph_v2.html
      ↓
Browser renders interactive graph via vis.js
```

## Troubleshooting

### "steampipe: command not found"

```bash
curl -s https://steampipe.io/install/steampipe.sh | sh
steampipe --version
```

### "Could not load AWS credentials"

```bash
aws sts get-caller-identity
aws sso login --profile <your-profile>
steampipe service restart
```

### Empty graph or no data

```bash
# Test Steampipe queries directly
steampipe query "SELECT * FROM aws_ec2_instance LIMIT 5"
steampipe query "SELECT * FROM aws_vpc_security_group LIMIT 5"
```

### HTML file won't open in browser

```bash
# Serve via HTTP instead of opening the file directly
python3 -m http.server 8080
# http://localhost:8080/sg_interactive_graph_v2.html
```

## References

- [Steampipe documentation](https://steampipe.io/docs)
- [Steampipe AWS plugin](https://hub.steampipe.io/plugins/turbot/aws)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, and PR guidelines.
