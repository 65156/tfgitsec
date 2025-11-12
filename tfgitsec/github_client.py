"""
GitHub API client for managing security issues
"""
import requests
from typing import List, Optional, Dict, Any
from datetime import datetime
from .models import GitHubIssue, TfSecFinding


class GitHubAPIError(Exception):
    """Raised when there's an error with the GitHub API"""
    pass


class GitHubClient:
    """Client for interacting with GitHub API"""
    
    def __init__(self, token: str, owner: str, repo: str, api_base_url: str = "https://api.github.com", web_base_url: str = "https://github.com"):
        """Initialize GitHub client
        
        Args:
            token: GitHub Personal Access Token
            owner: Repository owner/organization
            repo: Repository name
            api_base_url: GitHub API base URL (for GitHub Enterprise)
            web_base_url: GitHub web interface base URL (for GitHub Enterprise)
        """
        self.token = token
        self.owner = owner
        self.repo = repo
        self.api_base_url = api_base_url
        self.web_base_url = web_base_url
        
        # Keep legacy attributes for backward compatibility
        self.repo_owner = owner
        self.repo_name = repo
        self.base_url = api_base_url
        
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "tfgitsec/1.0.0"
        }
    
    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a request to the GitHub API"""
        url = f"{self.api_base_url}/repos/{self.owner}/{self.repo}/{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers, params=data)
            elif method.upper() == "POST":
                response = requests.post(url, headers=self.headers, json=data)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=self.headers, json=data)
            else:
                raise GitHubAPIError(f"Unsupported HTTP method: {method}")
            
            # Handle rate limiting
            if response.status_code == 403 and "rate limit" in response.text.lower():
                raise GitHubAPIError("GitHub API rate limit exceeded")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise GitHubAPIError(f"GitHub API request failed: {e}")
    
    def get_issues(self, state: str = "all", labels: Optional[List[str]] = None) -> List[GitHubIssue]:
        """Get issues from the repository
        
        Args:
            state: Issue state ('open', 'closed', 'all')
            labels: Filter by labels
        """
        params = {"state": state, "per_page": 100}
        if labels:
            params["labels"] = ",".join(labels)
        
        all_issues = []
        page = 1
        
        while True:
            params["page"] = page
            issues_data = self._make_request("GET", "issues", params)
            
            if not issues_data:
                break
            
            for issue_data in issues_data:
                # Skip pull requests (they show up in issues endpoint)
                if "pull_request" in issue_data:
                    continue
                
                issue = GitHubIssue(
                    number=int(issue_data.get("number", 0)),
                    title=str(issue_data.get("title", "")),
                    state=str(issue_data.get("state", "")),
                    labels=[str(label.get("name", "")) for label in issue_data.get("labels", []) if isinstance(label, dict)],
                    created_at=str(issue_data.get("created_at", "")),
                    updated_at=str(issue_data.get("updated_at", "")),
                    body=str(issue_data.get("body") or "")
                )
                all_issues.append(issue)
            
            page += 1
            
            # GitHub returns less than per_page items on the last page
            if len(issues_data) < params["per_page"]:
                break
        
        return all_issues
    
    def get_tfsec_issues(self) -> List[GitHubIssue]:
        """Get all issues created by tfgitsec"""
        return self.get_issues(labels=["tfsec-security"])
    
    def create_issue(self, title: str, body: str, labels: List[str]) -> GitHubIssue:
        """Create a new GitHub issue"""
        data = {
            "title": title,
            "body": body,
            "labels": labels
        }
        
        issue_data = self._make_request("POST", "issues", data)
        
        return GitHubIssue(
            number=int(issue_data.get("number", 0)),
            title=str(issue_data.get("title", "")),
            state=str(issue_data.get("state", "")),
            labels=[str(label.get("name", "")) for label in issue_data.get("labels", []) if isinstance(label, dict)],
            created_at=str(issue_data.get("created_at", "")),
            updated_at=str(issue_data.get("updated_at", "")),
            body=str(issue_data.get("body") or "")
        )
    
    def update_issue(self, issue_number: int, title: Optional[str] = None, 
                    body: Optional[str] = None, state: Optional[str] = None,
                    labels: Optional[List[str]] = None) -> GitHubIssue:
        """Update an existing GitHub issue"""
        data = {}
        
        if title is not None:
            data["title"] = title
        if body is not None:
            data["body"] = body
        if state is not None:
            data["state"] = state
        if labels is not None:
            data["labels"] = labels
        
        issue_data = self._make_request("PATCH", f"issues/{issue_number}", data)
        
        return GitHubIssue(
            number=int(issue_data.get("number", 0)),
            title=str(issue_data.get("title", "")),
            state=str(issue_data.get("state", "")),
            labels=[str(label.get("name", "")) for label in issue_data.get("labels", []) if isinstance(label, dict)],
            created_at=str(issue_data.get("created_at", "")),
            updated_at=str(issue_data.get("updated_at", "")),
            body=str(issue_data.get("body") or "")
        )
    
    def close_issue_with_comment(self, issue_number: int, comment: str) -> GitHubIssue:
        """Close an issue and add a comment"""
        # Add comment first
        self.add_comment(issue_number, comment)
        
        # Then close the issue
        return self.update_issue(issue_number, state="closed")
    
    def reopen_issue_with_comment(self, issue_number: int, comment: str) -> GitHubIssue:
        """Reopen an issue and add a comment"""
        # Reopen the issue first
        updated_issue = self.update_issue(issue_number, state="open")
        
        # Then add comment
        self.add_comment(issue_number, comment)
        
        return updated_issue
    
    def add_comment(self, issue_number: int, comment: str) -> Dict[str, Any]:
        """Add a comment to an issue"""
        data = {"body": comment}
        return self._make_request("POST", f"issues/{issue_number}/comments", data)
    
    def test_connection(self) -> bool:
        """Test if we can connect to the GitHub API"""
        try:
            self._make_request("GET", "")
            return True
        except GitHubAPIError:
            return False
    
    def create_issue_from_finding(self, finding: TfSecFinding, issue_body: str) -> GitHubIssue:
        """Create a GitHub issue from a TfSec finding"""
        return self.create_issue(
            title=finding.issue_title,
            body=issue_body,
            labels=finding.get_github_labels()
        )
    
    def get_issue_url(self, issue_number: int) -> str:
        """Get the web URL for an issue"""
        return f"{self.web_base_url}/{self.owner}/{self.repo}/issues/{issue_number}"
    
    def find_issue_by_unique_id(self, unique_id: str, issues: Optional[List[GitHubIssue]] = None) -> Optional[GitHubIssue]:
        """Find an existing issue by the unique ID (resource[rule_id])"""
        if issues is None:
            issues = self.get_tfsec_issues()
        
        for issue in issues:
            if issue.extract_unique_id() == unique_id:
                return issue
        
        return None
