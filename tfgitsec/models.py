"""
Data models for TfSec findings and GitHub issues
"""
from dataclasses import dataclass
from typing import List, Optional
import os
from datetime import datetime


@dataclass
class Location:
    """Represents the location of a security finding in a file"""
    filename: str
    start_line: int
    end_line: int

    @property
    def file_basename(self) -> str:
        """Return just the filename without the full path"""
        return os.path.basename(self.filename)

    @property
    def line_range_str(self) -> str:
        """Return a string representation of the line range"""
        if self.start_line == self.end_line:
            return str(self.start_line)
        return f"{self.start_line}-{self.end_line}"


@dataclass
class TfSecFinding:
    """Represents a security finding from TfSec"""
    rule_id: str
    long_id: str
    rule_description: str
    rule_provider: str
    rule_service: str
    impact: str
    resolution: str
    links: List[str]
    description: str
    severity: str
    warning: bool
    status: int
    resource: str
    location: Location
    prefix: Optional[str] = None

    @property
    def unique_id(self) -> str:
        """Generate unique identifier for deduplication: resource[rule_id]"""
        base_id = f"{self.resource}[{self.rule_id}]"
        if self.prefix:
            return f"{self.prefix}:{base_id}"
        return base_id

    @property
    def issue_title(self) -> str:
        """Generate GitHub issue title"""
        title = f"{self.rule_description} - {self.resource}[{self.rule_id}]"
        if self.prefix:
            title = f"[{self.prefix}] {title}"
        return title

    @property
    def severity_label(self) -> str:
        """Return severity as a GitHub label"""
        return f"severity-{self.severity.lower()}"

    @property
    def service_label(self) -> str:
        """Return AWS service as a GitHub label"""
        return f"aws-{self.rule_service}"

    def get_github_labels(self) -> List[str]:
        """Get all GitHub labels for this finding"""
        labels = [
            "tfsec-security",
            self.severity_label,
            self.service_label,
            f"provider-{self.rule_provider}"
        ]
        
        if self.warning:
            labels.append("warning")
            
        return labels


@dataclass
class GitHubIssue:
    """Represents a GitHub issue"""
    number: int
    title: str
    state: str  # 'open' or 'closed'
    labels: List[str]
    created_at: str
    updated_at: str
    body: str

    @property
    def is_tfsec_issue(self) -> bool:
        """Check if this is a tfsec security issue"""
        return "tfsec-security" in self.labels

    def extract_unique_id(self) -> Optional[str]:
        """Extract the unique ID from the issue title if it's a tfsec issue"""
        if not self.is_tfsec_issue:
            return None
        
        # Extract unique ID pattern from title
        # Formats: 
        # "[prefix] Rule description - resource[rule_id]"
        # "Rule description - resource[rule_id]"
        
        title = self.title
        
        # Handle prefixed titles
        if title.startswith("[") and "] " in title:
            # Extract prefix and rest of title
            prefix_end = title.find("] ")
            prefix = title[1:prefix_end]
            rest_title = title[prefix_end + 2:]
            
            # Extract resource[rule_id] from the rest
            if " - " in rest_title:
                parts = rest_title.split(" - ")
                if len(parts) >= 2:
                    resource_rule = parts[-1]
                    if "[" in resource_rule and resource_rule.endswith("]"):
                        return f"{prefix}:{resource_rule}"
        else:
            # Handle non-prefixed titles
            if " - " in title:
                parts = title.split(" - ")
                if len(parts) >= 2:
                    potential_id = parts[-1]
                    if "[" in potential_id and potential_id.endswith("]"):
                        return potential_id
        
        return None
