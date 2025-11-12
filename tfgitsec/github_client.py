"""
GitHub API client for managing security issues
"""
import requests
from typing import List, Optional, Dict, Any
from datetime import datetime
import sys
from urllib.parse import urlparse
from .models import GitHubIssue, TfSecFinding


class GitHubAPIError(Exception):
    """Raised when there's an error with the GitHub API"""
    pass


class GitHubClient:
    """Client for interacting with GitHub API"""
    
    def __init__(self, token: str, owner: str, repo: str, api_base_url: str = "https://api.github.com", web_base_url: str = "https://github.com", debug: bool = False):
        """Initialize GitHub client
        
        Args:
            token: GitHub Personal Access Token
            owner: Repository owner/organization
            repo: Repository name
            api_base_url: GitHub API base URL (for GitHub Enterprise)
            web_base_url: GitHub web interface base URL (for GitHub Enterprise)
            debug: Enable debug output
        """
        self.token = token
        self.owner = owner
        self.repo = repo
        self.api_base_url = api_base_url
        self.web_base_url = web_base_url
        self.debug = debug
        
        # Keep legacy attributes for backward compatibility
        self.repo_owner = owner
        self.repo_name = repo
        self.base_url = api_base_url
        
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "tfgitsec/1.0.0"
        }
        
        # Headers for Security Advisories API (requires different accept header)
        self.advisory_headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "tfgitsec/1.0.0",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        if self.debug:
            self._debug_print(f"GitHubClient initialized for {owner}/{repo}")
            self._debug_print(f"API Base URL: {api_base_url}")
            self._debug_print(f"Web Base URL: {web_base_url}")
    
    def _debug_print(self, message: str) -> None:
        """Print debug message if debug is enabled"""
        if self.debug:
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            print(f"🔧 [{timestamp}] DEBUG: {message}", file=sys.stderr)

    def _make_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a request to the GitHub API"""
        url = f"{self.api_base_url}/repos/{self.owner}/{self.repo}/{endpoint}"
        
        self._debug_print(f"Making HTTP request:")
        self._debug_print(f"  Method: {method.upper()}")
        self._debug_print(f"  URL: {url}")
        if data:
            self._debug_print(f"  Data: {data}")
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.headers, params=data, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, headers=self.headers, json=data, timeout=30)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=self.headers, json=data, timeout=30)
            else:
                raise GitHubAPIError(f"Unsupported HTTP method: {method}")
            
            self._debug_print(f"HTTP Response:")
            self._debug_print(f"  Status: {response.status_code} {response.reason}")
            self._debug_print(f"  Headers: Content-Type={response.headers.get('Content-Type', 'Unknown')}")
            
            # Show response body for errors or if it's small
            if response.status_code >= 400 or len(response.content) < 1000:
                try:
                    response_text = response.text[:500]
                    if len(response.text) > 500:
                        response_text += "..."
                    self._debug_print(f"  Body: {response_text}")
                except:
                    self._debug_print(f"  Body: <binary content>")
            
            # Handle rate limiting
            if response.status_code == 403:
                if "rate limit" in response.text.lower():
                    raise GitHubAPIError("GitHub API rate limit exceeded")
                elif "not found" not in response.text.lower():
                    # Might be a permissions issue
                    raise GitHubAPIError(f"Access denied (403): {response.text[:200]}")
            
            # Handle common errors with better messages
            if response.status_code == 404:
                raise GitHubAPIError(f"Repository '{self.owner}/{self.repo}' not found or token lacks access")
            elif response.status_code == 401:
                raise GitHubAPIError("Authentication failed - check your GitHub token")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.ConnectTimeout:
            raise GitHubAPIError(f"Connection timeout to {urlparse(url).hostname}")
        except requests.exceptions.SSLError as e:
            raise GitHubAPIError(f"SSL certificate error: {e}")
        except requests.exceptions.ConnectionError as e:
            if "Name or service not known" in str(e) or "nodename nor servname provided" in str(e):
                raise GitHubAPIError(f"DNS resolution failed for {urlparse(url).hostname}")
            elif "Connection refused" in str(e):
                raise GitHubAPIError(f"Connection refused by {urlparse(url).hostname}")
            else:
                raise GitHubAPIError(f"Network connection error: {e}")
        except requests.exceptions.RequestException as e:
            raise GitHubAPIError(f"HTTP request failed: {e}")
    
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
        self._debug_print("Starting comprehensive connection test")
        
        # Test DNS resolution if it's not github.com
        parsed_url = urlparse(self.api_base_url)
        hostname = parsed_url.hostname
        
        if hostname != "api.github.com":
            self._debug_print(f"Testing DNS resolution for {hostname}")
            try:
                import socket
                ip = socket.gethostbyname(hostname)
                self._debug_print(f"DNS resolution successful: {hostname} -> {ip}")
            except socket.gaierror as e:
                self._debug_print(f"DNS resolution failed: {e}")
                return False
        
        # Test basic repository access
        try:
            self._debug_print("Testing repository access")
            self._make_request("GET", "")
            self._debug_print("Repository access successful")
            return True
        except GitHubAPIError as e:
            self._debug_print(f"Repository access failed: {e}")
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
    
    # Security Advisory API Methods
    
    def _make_advisory_request(self, method: str, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """Make a request to the GitHub Security Advisory API"""
        url = f"{self.api_base_url}/repos/{self.owner}/{self.repo}/{endpoint}"
        
        self._debug_print(f"Making Security Advisory HTTP request:")
        self._debug_print(f"  Method: {method.upper()}")
        self._debug_print(f"  URL: {url}")
        if data:
            self._debug_print(f"  Data: {data}")
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=self.advisory_headers, params=data, timeout=30)
            elif method.upper() == "POST":
                response = requests.post(url, headers=self.advisory_headers, json=data, timeout=30)
            elif method.upper() == "PATCH":
                response = requests.patch(url, headers=self.advisory_headers, json=data, timeout=30)
            else:
                raise GitHubAPIError(f"Unsupported HTTP method: {method}")
            
            self._debug_print(f"Security Advisory HTTP Response:")
            self._debug_print(f"  Status: {response.status_code} {response.reason}")
            self._debug_print(f"  Headers: Content-Type={response.headers.get('Content-Type', 'Unknown')}")
            
            # Show response body for errors or if it's small
            if response.status_code >= 400 or len(response.content) < 1000:
                try:
                    response_text = response.text[:500]
                    if len(response.text) > 500:
                        response_text += "..."
                    self._debug_print(f"  Body: {response_text}")
                except:
                    self._debug_print(f"  Body: <binary content>")
            
            # Handle rate limiting
            if response.status_code == 403:
                if "rate limit" in response.text.lower():
                    raise GitHubAPIError("GitHub API rate limit exceeded")
                elif "not found" not in response.text.lower():
                    # Might be a permissions issue
                    raise GitHubAPIError(f"Access denied (403) - Security Advisory API requires appropriate permissions: {response.text[:200]}")
            
            # Handle common errors with better messages
            if response.status_code == 404:
                raise GitHubAPIError(f"Repository '{self.owner}/{self.repo}' not found or token lacks Security Advisory access")
            elif response.status_code == 401:
                raise GitHubAPIError("Authentication failed - check your GitHub token has Security Advisory permissions")
            elif response.status_code == 422:
                raise GitHubAPIError(f"Invalid Security Advisory data: {response.text[:200]}")
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            raise GitHubAPIError(f"Security Advisory HTTP request failed: {e}")
    
    def create_security_advisory(self, title: str, description: str, severity: str, unique_id: str) -> Dict[str, Any]:
        """Create a GitHub Security Advisory from a TfSec finding
        
        Args:
            title: Advisory title
            description: Advisory description/summary
            severity: Severity level (critical, high, medium, low)
            unique_id: Unique identifier for deduplication
        
        Returns:
            Dictionary with advisory data including ghsa_id and html_url
        """
        # Map TfSec severity to GitHub Advisory severity
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low"
        }
        
        advisory_severity = severity_map.get(severity.upper(), "medium")
        
        data = {
            "summary": title,
            "description": description,
            "severity": advisory_severity,
            "state": "draft",  # Start as draft
            # Include unique ID in vulnerabilities for tracking
            "vulnerabilities": [{
                "package": {
                    "name": "terraform-configuration",
                    "ecosystem": "other"
                },
                "vulnerable_version_range": "*",
                "patched_versions": "See description for remediation",
                "vulnerable_functions": [unique_id]  # Store unique ID here for tracking
            }]
        }
        
        return self._make_advisory_request("POST", "security-advisories", data)
    
    def get_security_advisories(self, state: str = "all") -> List[Dict[str, Any]]:
        """Get Security Advisories for the repository
        
        Args:
            state: Advisory state ('triage', 'draft', 'published', 'closed', 'all')
        """
        params = {"per_page": 100}
        if state != "all":
            params["state"] = state
        
        all_advisories = []
        page = 1
        
        while True:
            params["page"] = page
            advisories_data = self._make_advisory_request("GET", "security-advisories", params)
            
            if not advisories_data:
                break
            
            all_advisories.extend(advisories_data)
            page += 1
            
            # GitHub returns less than per_page items on the last page
            if len(advisories_data) < params["per_page"]:
                break
        
        return all_advisories
    
    def get_tfsec_advisories(self) -> List[Dict[str, Any]]:
        """Get all Security Advisories created by tfgitsec"""
        advisories = self.get_security_advisories()
        
        # Filter advisories that contain tfgitsec identifier
        tfsec_advisories = []
        for advisory in advisories:
            if self._is_tfsec_advisory(advisory):
                tfsec_advisories.append(advisory)
        
        return tfsec_advisories
    
    def _is_tfsec_advisory(self, advisory: Dict[str, Any]) -> bool:
        """Check if a Security Advisory was created by tfgitsec"""
        # Check if description contains tfgitsec marker
        description = advisory.get("description", "")
        if "tfgitsec" in description.lower():
            return True
        
        # Check vulnerabilities for unique IDs (our tracking mechanism)
        vulnerabilities = advisory.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            functions = vuln.get("vulnerable_functions", [])
            for func in functions:
                if "[" in func and "]" in func:  # Unique ID format: resource[rule_id]
                    return True
        
        return False
    
    def find_advisory_by_unique_id(self, unique_id: str, advisories: Optional[List[Dict[str, Any]]] = None) -> Optional[Dict[str, Any]]:
        """Find an existing Security Advisory by unique ID"""
        if advisories is None:
            advisories = self.get_tfsec_advisories()
        
        for advisory in advisories:
            if self._extract_advisory_unique_id(advisory) == unique_id:
                return advisory
        
        return None
    
    def _extract_advisory_unique_id(self, advisory: Dict[str, Any]) -> Optional[str]:
        """Extract unique ID from Security Advisory"""
        vulnerabilities = advisory.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            functions = vuln.get("vulnerable_functions", [])
            for func in functions:
                if "[" in func and "]" in func:
                    return func
        return None
    
    def update_security_advisory(self, ghsa_id: str, title: Optional[str] = None, 
                                description: Optional[str] = None, state: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing Security Advisory"""
        data = {}
        
        if title is not None:
            data["summary"] = title
        if description is not None:
            data["description"] = description
        if state is not None:
            data["state"] = state
        
        return self._make_advisory_request("PATCH", f"security-advisories/{ghsa_id}", data)
    
    def close_security_advisory(self, ghsa_id: str) -> Dict[str, Any]:
        """Close a Security Advisory (mark as resolved)"""
        return self.update_security_advisory(ghsa_id, state="closed")
    
    def reopen_security_advisory(self, ghsa_id: str) -> Dict[str, Any]:
        """Reopen a Security Advisory"""
        return self.update_security_advisory(ghsa_id, state="draft")
    
    def get_advisory_url(self, ghsa_id: str) -> str:
        """Get the web URL for a Security Advisory"""
        return f"{self.web_base_url}/{self.owner}/{self.repo}/security/advisories/{ghsa_id}"
    
    def create_advisory_from_finding(self, finding: TfSecFinding, advisory_description: str) -> Dict[str, Any]:
        """Create a GitHub Security Advisory from a TfSec finding"""
        return self.create_security_advisory(
            title=finding.issue_title,
            description=advisory_description,
            severity=finding.severity,
            unique_id=finding.unique_id
        )
