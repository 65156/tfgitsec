<<<<<<< HEAD
# tfgitsec
tracks tfsec json results as github security issues.
=======
# TfGitSec

TfGitSec is a Python tool that automatically creates and manages GitHub issues from TfSec security scan results. It helps teams track and resolve Terraform security findings by creating comprehensive GitHub issues with full lifecycle management.

## Features

- **Parse TfSec JSON Results**: Reads and validates TfSec JSON output files
- **Smart Issue Management**: Creates, reopens, and auto-closes GitHub issues based on scan results
- **Duplicate Prevention**: Uses resource[rule-id] format to prevent duplicate issues
- **Rich Issue Content**: Creates detailed GitHub issues with security findings, impacts, and solutions
- **Lifecycle Tracking**: Automatically manages issue states based on scan results
- **Flexible Configuration**: Supports environment variables and configuration files
- **Dry Run Support**: Preview changes without making actual GitHub modifications
- **Multiple Output Formats**: Text and JSON output options

## Installation

### From Source

```bash
git clone <repository-url>
cd tfgitsec
pip install -e .
```

### Using pip (when published)

```bash
pip install tfgitsec
```

## Quick Start

1. **Set up environment variables:**

```bash
export GITHUB_TOKEN="ghp_your_token_here"
export GITHUB_OWNER="your-org"
export GITHUB_REPO="your-repo"
```

2. **Run TfSec to generate results:**

```bash
tfsec --format json --out tfsec-results.json /path/to/terraform
```

3. **Process results with TfGitSec:**

```bash
tfgitsec scan tfsec-results.json
```

## Usage

### Commands

#### `scan` - Process TfSec results and manage GitHub issues

```bash
# Basic usage
tfgitsec scan results.json

# With explicit GitHub configuration
tfgitsec scan results.json --token ghp_xxx --owner myorg --repo myrepo

# Dry run to see what would happen
tfgitsec scan results.json --dry-run

# Don't auto-close resolved issues
tfgitsec scan results.json --no-auto-close

# JSON output format
tfgitsec scan results.json --output json

# Verbose output
tfgitsec scan results.json --verbose
```

#### `summary` - Generate scan summary without managing issues

```bash
# Text summary
tfgitsec summary results.json

# JSON summary
tfgitsec summary results.json --output json
```

#### `test` - Test GitHub API connection

```bash
tfgitsec test
```

### Configuration

TfGitSec supports configuration via environment variables or configuration files.

#### Environment Variables

- `GITHUB_TOKEN` - GitHub Personal Access Token
- `GITHUB_OWNER` - Repository owner/organization
- `GITHUB_REPO` - Repository name

#### Configuration File

Create a `tfgitsec.ini` file in your project root:

```ini
[github]
token = ghp_your_token_here
owner = your-org
repo = your-repo

[settings]
auto_close = true
dry_run = false
output_format = text
verbose = false

[labels]
base_label = tfsec-security
critical_label = severity-critical
high_label = severity-high
medium_label = severity-medium
low_label = severity-low
```

Configuration file locations (in order of precedence):
- File specified with `--config` option
- `tfgitsec.ini` in current directory
- `.tfgitsec.ini` in current directory
- `~/.tfgitsec.ini` in home directory
- `~/.config/tfgitsec/config.ini`

## How It Works

### Issue Lifecycle

1. **Create**: New security findings create new GitHub issues
2. **Track**: Issues remain open while the finding exists in scans
3. **Reopen**: Previously resolved issues are reopened if the finding reappears
4. **Auto-Close**: Issues are automatically closed when findings no longer appear in scans

### Duplicate Prevention

TfGitSec uses a unique identifier format `resource[rule-id]` to prevent duplicate issues:

```
aws_s3_bucket.example[aws-s3-bucket-public-access-block]
```

This ensures one issue per unique security finding.

### Issue Content

Each GitHub issue contains:
- **Severity Level**: Critical/High/Medium/Low with appropriate labels
- **Resource Information**: Affected Terraform resource
- **Location Details**: File and line numbers (with change disclaimers)
- **Security Details**: Rule description, impact, and resolution steps
- **Documentation Links**: References to security documentation
- **Unique Identifier**: For tracking and duplicate prevention

### GitHub Labels

Issues are automatically tagged with:
- `tfsec-security` - Base label for all TfGitSec issues
- `severity-{level}` - Severity-based labels
- `{provider}` - Cloud provider (aws, azure, gcp, etc.)

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run TfSec
        uses: aquasecurity/tfsec-action@v1.0.0
        with:
          format: json
          soft_fail: true
          
      - name: Process with TfGitSec
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITHUB_OWNER: ${{ github.repository_owner }}
          GITHUB_REPO: ${{ github.event.repository.name }}
        run: |
          pip install tfgitsec
          tfgitsec scan results.json
```

### Jenkins Example

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh 'tfsec --format json --out tfsec-results.json .'
                
                withCredentials([string(credentialsId: 'github-token', variable: 'GITHUB_TOKEN')]) {
                    sh '''
                        export GITHUB_OWNER="your-org"
                        export GITHUB_REPO="your-repo"
                        tfgitsec scan tfsec-results.json
                    '''
                }
            }
        }
    }
}
```

## Development

### Setting up for Development

```bash
git clone <repository-url>
cd tfgitsec
pip install -e .[dev]
```

### Running Tests

```bash
# Run tests
python -m pytest

# With coverage
python -m pytest --cov=tfgitsec

# Linting
black tfgitsec/
isort tfgitsec/
mypy tfgitsec/
```

### Project Structure

```
tfgitsec/
├── tfgitsec/
│   ├── __init__.py
│   ├── cli.py              # Command-line interface
│   ├── config.py           # Configuration management
│   ├── formatter.py        # Issue formatting
│   ├── github_client.py    # GitHub API client
│   ├── manager.py          # Main issue management logic
│   ├── models.py           # Data models
│   └── parser.py           # TfSec JSON parser
├── examples/
│   ├── sample-tfsec.json   # Sample TfSec output
│   └── ci-examples/        # CI/CD examples
├── README.md
├── requirements.txt
└── setup.py
```

## Security Considerations

- **Token Security**: Store GitHub tokens securely using environment variables or secret management
- **Permissions**: The GitHub token needs `repo` scope for private repositories or `public_repo` for public repositories
- **Rate Limiting**: TfGitSec handles GitHub API rate limiting gracefully

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Troubleshooting

### Common Issues

**Error: GitHub token is required**
- Set the `GITHUB_TOKEN` environment variable or use `--token` option

**Error: Failed to connect to GitHub API**
- Verify your token has the correct permissions
- Check if you can access the repository with the provided credentials

**Error: TfSec file not found**
- Ensure the TfSec JSON file path is correct
- Verify the file was created successfully by TfSec

**No issues created despite findings**
- Use `--verbose` to see detailed output
- Check if issues already exist for the findings
- Verify the TfSec JSON format is supported

### Getting Help

- Check the [Issues](https://github.com/yourusername/tfgitsec/issues) page
- Review the documentation
- Use `tfgitsec --help` or `tfgitsec <command> --help` for command-specific help

## Changelog

### v1.0.0
- Initial release
- TfSec JSON parsing
- GitHub issue management
- CLI interface
- Configuration support
- CI/CD integration examples
>>>>>>> 269f83e (add files)
