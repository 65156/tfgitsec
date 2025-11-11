"""
Main issue management logic that orchestrates the full lifecycle
"""
from typing import List, Dict, Set, Tuple, Any
from datetime import datetime

from .models import TfSecFinding, GitHubIssue
from .parser import TfSecParser, TfSecParseError
from .github_client import GitHubClient, GitHubAPIError
from .formatter import IssueFormatter


class IssueManagerError(Exception):
    """Raised when there's an error with issue management"""
    pass


class IssueManager:
    """Manages the complete lifecycle of security issues"""
    
    def __init__(self, github_client: GitHubClient, auto_close: bool = True, dry_run: bool = False):
        """Initialize the issue manager
        
        Args:
            github_client: GitHub API client
            auto_close: Whether to automatically close resolved issues
            dry_run: If True, don't make any actual changes to GitHub
        """
        self.github = github_client
        self.auto_close = auto_close
        self.dry_run = dry_run
        self.scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    def process_scan_results(self, tfsec_file_path: str) -> Dict[str, Any]:
        """Process TfSec scan results and manage GitHub issues
        
        Returns a summary of actions taken
        """
        try:
            # Parse TfSec results
            findings = TfSecParser.parse_file(tfsec_file_path)
            stats = TfSecParser.validate_findings(findings)
            
            # Get existing tfsec issues from GitHub
            existing_issues = self.github.get_tfsec_issues()
            
            # Process findings and manage issues
            result = self._process_findings(findings, existing_issues, stats)
            
            return result
            
        except TfSecParseError as e:
            raise IssueManagerError(f"Failed to parse TfSec results: {e}")
        except GitHubAPIError as e:
            raise IssueManagerError(f"GitHub API error: {e}")
        except Exception as e:
            raise IssueManagerError(f"Unexpected error: {e}")
    
    def _process_findings(self, findings: List[TfSecFinding], 
                         existing_issues: List[GitHubIssue], 
                         stats: Dict[str, Any]) -> Dict[str, Any]:
        """Process findings and manage issue lifecycle"""
        
        # Create maps for efficient lookups
        findings_by_id = {f.unique_id: f for f in findings}
        existing_by_id = {uid: issue 
                         for issue in existing_issues 
                         if (uid := issue.extract_unique_id()) is not None}
        
        # Track actions taken
        actions = {
            "created": [],
            "reopened": [], 
            "closed": [],
            "unchanged": [],
            "errors": []
        }
        
        # Process current findings
        for finding in findings:
            unique_id = finding.unique_id
            existing_issue = existing_by_id.get(unique_id)
            
            if existing_issue is None:
                # New finding - create issue
                self._create_new_issue(finding, actions)
            elif existing_issue.state == "closed":
                # Finding reappeared - reopen issue
                self._reopen_issue(existing_issue, actions)
            else:
                # Issue already exists and is open - leave it
                actions["unchanged"].append({
                    "unique_id": unique_id,
                    "issue_number": existing_issue.number,
                    "title": existing_issue.title
                })
        
        # Auto-close resolved issues if enabled
        if self.auto_close:
            self._close_resolved_issues(findings_by_id, existing_by_id, actions)
        
        # Build summary
        summary = {
            "scan_date": self.scan_date,
            "dry_run": self.dry_run,
            "total_findings": len(findings),
            "scan_stats": stats,
            "actions": actions,
            "summary": {
                "issues_created": len(actions["created"]),
                "issues_reopened": len(actions["reopened"]), 
                "issues_closed": len(actions["closed"]),
                "issues_unchanged": len(actions["unchanged"]),
                "errors": len(actions["errors"])
            }
        }
        
        return summary
    
    def _create_new_issue(self, finding: TfSecFinding, actions: Dict[str, List]) -> None:
        """Create a new GitHub issue for a finding"""
        try:
            issue_body = IssueFormatter.format_issue_body(finding)
            
            if self.dry_run:
                actions["created"].append({
                    "unique_id": finding.unique_id,
                    "title": finding.issue_title,
                    "severity": finding.severity,
                    "dry_run": True
                })
            else:
                new_issue = self.github.create_issue_from_finding(finding, issue_body)
                actions["created"].append({
                    "unique_id": finding.unique_id,
                    "issue_number": new_issue.number,
                    "title": new_issue.title,
                    "severity": finding.severity,
                    "url": f"{self.github.web_base_url}/{self.github.repo_owner}/{self.github.repo_name}/issues/{new_issue.number}"
                })
                
        except Exception as e:
            actions["errors"].append({
                "action": "create",
                "unique_id": finding.unique_id,
                "error": str(e)
            })
    
    def _reopen_issue(self, issue: GitHubIssue, actions: Dict[str, List]) -> None:
        """Reopen a closed issue that has reappeared"""
        try:
            comment = IssueFormatter.format_reopen_comment(self.scan_date)
            
            if self.dry_run:
                actions["reopened"].append({
                    "unique_id": issue.extract_unique_id(),
                    "issue_number": issue.number,
                    "title": issue.title,
                    "dry_run": True
                })
            else:
                reopened_issue = self.github.reopen_issue_with_comment(issue.number, comment)
                actions["reopened"].append({
                    "unique_id": issue.extract_unique_id(),
                    "issue_number": reopened_issue.number,
                    "title": reopened_issue.title,
                    "url": f"{self.github.web_base_url}/{self.github.repo_owner}/{self.github.repo_name}/issues/{reopened_issue.number}"
                })
                
        except Exception as e:
            actions["errors"].append({
                "action": "reopen", 
                "issue_number": issue.number,
                "error": str(e)
            })
    
    def _close_resolved_issues(self, findings_by_id: Dict[str, TfSecFinding],
                              existing_by_id: Dict[str, GitHubIssue], 
                              actions: Dict[str, List]) -> None:
        """Close issues for findings that no longer exist"""
        
        for unique_id, issue in existing_by_id.items():
            # Skip if finding still exists or issue is already closed
            if unique_id in findings_by_id or issue.state == "closed":
                continue
            
            try:
                comment = IssueFormatter.format_close_comment(self.scan_date)
                
                if self.dry_run:
                    actions["closed"].append({
                        "unique_id": unique_id,
                        "issue_number": issue.number,
                        "title": issue.title,
                        "dry_run": True
                    })
                else:
                    closed_issue = self.github.close_issue_with_comment(issue.number, comment)
                    actions["closed"].append({
                        "unique_id": unique_id,
                        "issue_number": closed_issue.number,
                        "title": closed_issue.title,
                        "url": f"{self.github.web_base_url}/{self.github.repo_owner}/{self.github.repo_name}/issues/{closed_issue.number}"
                    })
                    
            except Exception as e:
                actions["errors"].append({
                    "action": "close",
                    "issue_number": issue.number, 
                    "error": str(e)
                })
    
    def test_github_connection(self) -> bool:
        """Test if we can connect to GitHub"""
        return self.github.test_connection()
    
    def get_scan_summary(self, tfsec_file_path: str) -> str:
        """Generate a markdown summary of scan results"""
        try:
            findings = TfSecParser.parse_file(tfsec_file_path)
            stats = TfSecParser.validate_findings(findings)
            return IssueFormatter.format_summary_comment(stats, self.scan_date)
        except Exception as e:
            return f"Error generating scan summary: {e}"
    
    def cleanup_old_issues(self, days_old: int = 30) -> Dict[str, Any]:
        """Clean up old closed tfsec issues (utility function)
        
        Args:
            days_old: Close issues that have been closed for this many days
        
        Returns:
            Summary of cleanup actions
        """
        # This is a utility function that could be used for maintenance
        # Implementation would check issue dates and remove old ones
        # For now, just return a placeholder
        return {
            "message": "Cleanup functionality not yet implemented",
            "days_old": days_old
        }
