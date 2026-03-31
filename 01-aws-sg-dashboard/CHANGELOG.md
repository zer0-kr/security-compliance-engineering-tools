# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project uses [Semantic Versioning](https://semver.org/).

## [3.0.0] - 2026-03-31

This release prepares the project for open-source distribution with a full CLI interface, security hardening, and a comprehensive test suite.

### Added

- **CLI interface:** `extract_and_visualize_v2.py` now accepts command-line flags:
  - `--regions` to limit queries to specific AWS regions
  - `--skip-config` to skip Steampipe aggregator config regeneration
  - `--output` / `-o` to set the output HTML file path
  - `--template` to specify a custom HTML template
  - `--verbose` / `-v` for detailed logging
- **Config backup:** existing Steampipe config files are backed up before being overwritten, preventing accidental data loss
- **SRI integrity hashes:** CDN-loaded resources (vis.js, xlsx.js) now include `integrity` attributes for Subresource Integrity verification
- **Filter-aware statistics:** the dashboard stats panel updates to reflect the currently active filters rather than always showing totals for all resources
- **Sensitive data warning:** generated HTML files display a visible warning that they contain real AWS data
- **Steampipe PID-based restart:** Steampipe is now restarted by targeting its specific PID instead of a system-wide `pkill`, avoiding interference with other processes
- **Query timeout protection:** long-running Steampipe queries now time out gracefully instead of hanging indefinitely
- **Comprehensive test suite:** `tests/` directory with unit and integration tests covering data extraction, HTML generation, masking logic, and CLI argument parsing

### Fixed

- **XSS vulnerability:** resource names and SG rule descriptions are now HTML-escaped before being injected into the dashboard template
- **ARN ID preservation:** resource ARNs are no longer mangled during the data injection step; full ARNs are preserved correctly in the output

## [2.3.0] - 2025-02

### Added

- Steampipe Aggregator support: all AWS profiles are queried through a single aggregator connection
- Parallel data collection via `ThreadPoolExecutor` (completes in under 3.5 seconds for typical environments)
- Automatic fallback to per-connection queries when the aggregator returns `AccessDenied`
- Support for additional resource types: VPC Endpoint, Lambda, ECS, ElastiCache, Network Interface
- Vulnerability detection: auto-identifies security groups with sensitive ports open to `0.0.0.0/0` or `::/0` (16 service types including SSH, RDP, MySQL, PostgreSQL, Redis, MongoDB)
- Warning indicators on vulnerable SG nodes in the graph
- XLSX export for vulnerable SG and unused SG lists
- Template/data separation: `sg_dashboard_template.html` holds the UI with no embedded data; `extract_and_visualize_v2.py` injects data between `DATA SECTION` markers at runtime

## [2.2.0] - 2025-01

### Added

- Auto-detection of all AWS profiles from `~/.aws/credentials`
- Single-run collection across all configured AWS accounts
- Account filter dropdown in the dashboard
- Per-account VPC filtering: selecting an account shows only that account's VPCs
- Account ID prefix on resource IDs to prevent collisions across accounts (e.g., `prod:i-0abc123`)
- Per-account color coding in the graph

### Fixed

- Individual account failures no longer abort the entire collection run

## [2.1.0] - 2025-01

### Changed

- Filter response time improved by 95% (from 2-5 seconds to 100-200ms) for environments with 500+ nodes
- Security analysis, cycle detection, and conflicting-rule results are now cached
- DOM updates are batched (from ~2,500 individual updates to 2 bulk updates)
- All `.find()` calls replaced with `Map`-based O(1) lookups

## [2.0.0] - 2025-01

### Added

- Centralized `COLOR_PALETTE` object: all node colors managed from a single source
- RDS instance support (rendered as blue triangles)

### Changed

- Generated data files excluded from git via `.gitignore`
