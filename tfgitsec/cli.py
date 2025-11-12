"""
Command-line interface for tfgitsec
"""
import argparse
import sys
import json
import os
from typing import Optional

from . import __version__
from .manager import IssueManager, IssueManagerError
from .github_client import GitHubClient, GitHubAPIError
from .parser import TfSecParser, TfSecParseError


def create_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser"""
    parser = argparse.ArgumentParser(
        description="TfGitSec - Generate GitHub security issues from TfSec scan results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with environment variables
  tfgitsec scan results.json

  # GitHub.com usage
  tfgitsec scan results.json --github-repo "myorg/myrepo"

  # GitHub Enterprise usage
  tfgitsec scan results.json --github-repo "IBM-Sports/sports-cloud-sandbox-x81js" --ghe-base-url "https://github.ibm.com"

  # With explicit token
  tfgitsec scan results.json --token ghp_xxx --github-repo "myorg/myrepo"

  # Dry run to see what would happen
  tfgitsec scan results.json --github-repo "myorg/myrepo" --dry-run

  # Don't auto-close resolved issues
  tfgitsec scan results.json --github-repo "myorg/myrepo" --no-auto-close

  # Just get scan summary without creating issues
  tfgitsec summary results.json

  # Test GitHub connection
  tfgitsec test --github-repo "myorg/myrepo"

Environment Variables:
  GITHUB_TOKEN       - GitHub personal access token
  GITHUB_REPO        - Repository in owner/repo format
  GHE_BASE_URL       - GitHub Enterprise base URL (optional)
        """
    )
    
    # Add version argument
    parser.add_argument('--version', action='version', version=f'tfgitsec {__version__}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Process TfSec results and manage GitHub issues')
    scan_parser.add_argument('tfsec_file', help='Path to TfSec JSON results file')
    scan_parser.add_argument('--token', help='GitHub personal access token (or set GITHUB_TOKEN)')
    scan_parser.add_argument('--github-repo', help='GitHub repository in owner/repo format (or set GITHUB_REPO)')
    scan_parser.add_argument('--ghe-base-url', help='GitHub Enterprise base URL (or set GHE_BASE_URL)')
    scan_parser.add_argument('--owner', help='GitHub repository owner (DEPRECATED - use --github-repo)')
    scan_parser.add_argument('--repo', help='GitHub repository name (DEPRECATED - use --github-repo)')
    scan_parser.add_argument('--dry-run', action='store_true', 
                           help='Show what would be done without making changes')
    scan_parser.add_argument('--no-auto-close', action='store_true',
                           help='Don\'t automatically close resolved issues')
    scan_parser.add_argument('--output', choices=['text', 'json'], default='text',
                           help='Output format (default: text)')
    scan_parser.add_argument('--verbose', '-v', action='store_true',
                           help='Enable verbose output')
    scan_parser.add_argument('--prefix', 
                           help='Prefix to add to unique IDs for environment isolation (e.g., "production-east2")')
    
    # Summary command 
    summary_parser = subparsers.add_parser('summary', help='Generate scan summary without managing issues')
    summary_parser.add_argument('tfsec_file', help='Path to TfSec JSON results file')
    summary_parser.add_argument('--output', choices=['text', 'json'], default='text',
                              help='Output format (default: text)')
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Test GitHub API connection')
    test_parser.add_argument('--token', help='GitHub personal access token (or set GITHUB_TOKEN)')
    test_parser.add_argument('--github-repo', help='GitHub repository in owner/repo format (or set GITHUB_REPO)')
    test_parser.add_argument('--ghe-base-url', help='GitHub Enterprise base URL (or set GHE_BASE_URL)')
    test_parser.add_argument('--owner', help='GitHub repository owner (DEPRECATED - use --github-repo)')
    test_parser.add_argument('--repo', help='GitHub repository name (DEPRECATED - use --github-repo)')
    
    return parser


def get_github_config(args) -> tuple[str, str, str, str, str]:
    """Get GitHub configuration from args or environment variables
    
    Returns:
        Tuple of (token, owner, repo, api_base_url, web_base_url)
    """
    token = args.token or os.getenv('GITHUB_TOKEN')
    
    # Handle new github-repo format
    github_repo = getattr(args, 'github_repo', None) or os.getenv('GITHUB_REPO')
    ghe_base_url = getattr(args, 'ghe_base_url', None) or os.getenv('GHE_BASE_URL')
    
    # Handle legacy owner/repo format with deprecation warning
    legacy_owner = getattr(args, 'owner', None) or os.getenv('GITHUB_OWNER')
    legacy_repo = getattr(args, 'repo', None) or os.getenv('GITHUB_REPO')
    
    if not token:
        print("Error: GitHub token is required. Set GITHUB_TOKEN environment variable or use --token", file=sys.stderr)
        sys.exit(1)
    
    # Determine owner/repo from new or legacy format
    owner = None
    repo = None
    
    if github_repo:
        if '/' not in github_repo:
            print("Error: --github-repo must be in 'owner/repo' format", file=sys.stderr)
            sys.exit(1)
        owner, repo = github_repo.split('/', 1)
    elif legacy_owner and legacy_repo:
        # Show deprecation warning
        print("Warning: --owner and --repo are deprecated. Use --github-repo 'owner/repo' instead.", file=sys.stderr)
        owner = legacy_owner
        repo = legacy_repo
    else:
        print("Error: Repository is required. Use --github-repo 'owner/repo' or set GITHUB_REPO environment variable", file=sys.stderr)
        sys.exit(1)
    
    # Determine API and web base URLs
    if ghe_base_url:
        # GitHub Enterprise
        api_base_url = f"{ghe_base_url.rstrip('/')}/api/v3"
        web_base_url = ghe_base_url.rstrip('/')
    else:
        # GitHub.com
        api_base_url = "https://api.github.com"
        web_base_url = "https://github.com"
    
    return token, owner, repo, api_base_url, web_base_url


def print_scan_results(result: dict, output_format: str = 'text', verbose: bool = False) -> None:
    """Print scan results in the specified format"""
    if output_format == 'json':
        print(json.dumps(result, indent=2))
        return
    
    # Text format
    print(f"\n🔍 TfGitSec Scan Results")
    print(f"📅 Scan Date: {result['scan_date']}")
    
    if result['dry_run']:
        print("🧪 DRY RUN - No changes were made")
    
    print(f"📊 Total Findings: {result['total_findings']}")
    
    # Summary stats
    summary = result['summary']
    print(f"\n📋 Action Summary:")
    print(f"  ✅ Issues Created: {summary['issues_created']}")
    print(f"  🔄 Issues Reopened: {summary['issues_reopened']}")
    print(f"  ❌ Issues Closed: {summary['issues_closed']}")
    print(f"  ⏸️  Issues Unchanged: {summary['issues_unchanged']}")
    
    if summary['errors'] > 0:
        print(f"  ⚠️  Errors: {summary['errors']}")
    
    # Show detailed actions if verbose or if there were actions taken
    actions = result['actions']
    
    if verbose or summary['issues_created'] > 0:
        if actions['created']:
            print(f"\n✅ Created Issues:")
            for item in actions['created']:
                if result['dry_run']:
                    print(f"  • {item['title']} ({item['severity']})")
                else:
                    print(f"  • {item['title']} ({item['severity']}) - #{item['issue_number']}")
                    if 'url' in item:
                        print(f"    {item['url']}")
    
    if verbose or summary['issues_reopened'] > 0:
        if actions['reopened']:
            print(f"\n🔄 Reopened Issues:")
            for item in actions['reopened']:
                if result['dry_run']:
                    print(f"  • {item['title']} - #{item['issue_number']}")
                else:
                    print(f"  • {item['title']} - #{item['issue_number']}")
                    if 'url' in item:
                        print(f"    {item['url']}")
    
    if verbose or summary['issues_closed'] > 0:
        if actions['closed']:
            print(f"\n❌ Closed Issues:")
            for item in actions['closed']:
                if result['dry_run']:
                    print(f"  • {item['title']} - #{item['issue_number']}")
                else:
                    print(f"  • {item['title']} - #{item['issue_number']}")
                    if 'url' in item:
                        print(f"    {item['url']}")
    
    if actions['errors']:
        print(f"\n⚠️ Errors:")
        for error in actions['errors']:
            print(f"  • {error['action']}: {error['error']}")
    
    # Show scan statistics
    if verbose:
        stats = result['scan_stats']
        print(f"\n📈 Scan Statistics:")
        
        by_severity = stats.get('by_severity', {})
        if by_severity:
            print("  Severity Distribution:")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = by_severity.get(severity, 0)
                if count > 0:
                    print(f"    {severity}: {count}")
        
        by_service = stats.get('by_service', {})
        if by_service:
            print("  By Service:")
            for service, count in sorted(by_service.items()):
                print(f"    {service}: {count}")


def handle_scan_command(args) -> None:
    """Handle the scan command"""
    # Validate TfSec file exists
    if not os.path.exists(args.tfsec_file):
        print(f"Error: TfSec file not found: {args.tfsec_file}", file=sys.stderr)
        sys.exit(1)
    
    # Get GitHub configuration
    token, owner, repo, api_base_url, web_base_url = get_github_config(args)
    
    try:
        # Create GitHub client and issue manager
        github_client = GitHubClient(token, owner, repo, api_base_url, web_base_url)
        auto_close = not args.no_auto_close
        
        # Test connection first
        print(f"🔗 Testing connection to {owner}/{repo}...")
        if not github_client.test_connection():
            print("❌ Failed to connect to GitHub API", file=sys.stderr)
            sys.exit(1)
        print("✅ GitHub connection successful")
        
        # Create issue manager
        issue_manager = IssueManager(github_client, auto_close=auto_close, dry_run=args.dry_run)
        
        # Process scan results
        print(f"📖 Processing TfSec results from {args.tfsec_file}...")
        result = issue_manager.process_scan_results(args.tfsec_file)
        
        # Print results
        print_scan_results(result, args.output, args.verbose)
        
    except (GitHubAPIError, IssueManagerError, TfSecParseError) as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def handle_summary_command(args) -> None:
    """Handle the summary command"""
    # Validate TfSec file exists
    if not os.path.exists(args.tfsec_file):
        print(f"Error: TfSec file not found: {args.tfsec_file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Parse findings and generate summary
        findings = TfSecParser.parse_file(args.tfsec_file)
        stats = TfSecParser.validate_findings(findings)
        
        if args.output == 'json':
            print(json.dumps(stats, indent=2))
        else:
            print("📊 TfSec Scan Summary")
            print(f"Total Findings: {stats['total']}")
            
            by_severity = stats.get('by_severity', {})
            if by_severity:
                print("\nBy Severity:")
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = by_severity.get(severity, 0)
                    if count > 0:
                        icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚫')
                        print(f"  {icon} {severity}: {count}")
            
            by_service = stats.get('by_service', {})
            if by_service:
                print("\nBy Service:")
                for service, count in sorted(by_service.items()):
                    print(f"  {service}: {count}")
        
    except TfSecParseError as e:
        print(f"❌ Error parsing TfSec file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def handle_test_command(args) -> None:
    """Handle the test command"""
    token, owner, repo, api_base_url, web_base_url = get_github_config(args)
    
    try:
        github_client = GitHubClient(token, owner, repo, api_base_url, web_base_url)
        
        print(f"🔗 Testing connection to {owner}/{repo}...")
        if github_client.test_connection():
            print("✅ GitHub connection successful!")
            
            # Get some basic info
            issues = github_client.get_tfsec_issues()
            print(f"📋 Found {len(issues)} existing tfgitsec issues")
            
        else:
            print("❌ Failed to connect to GitHub API", file=sys.stderr)
            sys.exit(1)
            
    except GitHubAPIError as e:
        print(f"❌ GitHub API error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'scan':
        handle_scan_command(args)
    elif args.command == 'summary':
        handle_summary_command(args)
    elif args.command == 'test':
        handle_test_command(args)


if __name__ == "__main__":
    main()
