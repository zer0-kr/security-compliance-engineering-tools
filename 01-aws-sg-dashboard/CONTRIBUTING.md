# Contributing

Thanks for taking the time to contribute. This document covers how to set up a development environment, run tests, and submit changes.

## Development setup

You'll need Python 3.8+ and the external dependencies listed in the README (Steampipe, AWS CLI).

```bash
git clone https://github.com/zer0-kr/security-compliance-engineering-tools.git
cd sg-dashboard

# Install Python dev dependencies
pip install -e ".[dev]"
```

If `pyproject.toml` doesn't define a `[dev]` extra in your local copy, install pytest directly:

```bash
pip install pytest
```

## Running tests

```bash
python3 -m pytest tests/ -v
```

All tests must pass before submitting a PR. If you're adding a feature or fixing a bug, add a corresponding test in `tests/`.

## Code style

- Follow the patterns already in the codebase. Don't introduce new abstractions without a clear reason.
- No `# type: ignore` suppressions. Fix the underlying type issue instead.
- Keep functions focused. If a function is doing three things, it probably should be three functions.
- Comments should explain *why*, not *what*. The code already shows what it does.
- Don't add dependencies without discussion. The project intentionally keeps its dependency footprint small.

## Submitting a pull request

1. Fork the repository and create a branch from `main`:
   ```bash
   git checkout -b fix/your-descriptive-branch-name
   ```

2. Make your changes. Keep commits atomic and write clear commit messages.

3. Run the test suite and confirm everything passes:
   ```bash
   python3 -m pytest tests/ -v
   ```

4. Push your branch and open a PR against `main`. In the PR description, explain:
   - What the change does
   - Why it's needed
   - How you tested it

5. A maintainer will review and may request changes. Address feedback in new commits rather than force-pushing, so the review history stays readable.

## Reporting issues

Before opening an issue, check whether it's already reported. When filing a new one, include:

- Your OS and Python version
- Steampipe version (`steampipe --version`)
- The full command you ran
- The full error output or unexpected behavior
- A minimal reproduction case if possible

For security vulnerabilities, don't open a public issue. Contact the maintainers directly.
