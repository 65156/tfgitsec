"""
Configuration management for tfgitsec
"""
import os
import configparser
from typing import Optional, Dict, Any
from pathlib import Path


class Config:
    """Configuration manager for tfgitsec"""
    
    def __init__(self, config_file: Optional[str] = None):
        """Initialize configuration
        
        Args:
            config_file: Path to configuration file. If None, looks for default locations
        """
        self.config = configparser.ConfigParser()
        self._load_config(config_file)
    
    def _load_config(self, config_file: Optional[str] = None) -> None:
        """Load configuration from file or defaults"""
        
        # Default configuration locations
        config_locations = []
        
        if config_file:
            config_locations.append(config_file)
        
        # Add default locations
        config_locations.extend([
            'tfgitsec.ini',
            '.tfgitsec.ini', 
            os.path.expanduser('~/.tfgitsec.ini'),
            os.path.expanduser('~/.config/tfgitsec/config.ini')
        ])
        
        # Try to read from each location
        for location in config_locations:
            if os.path.exists(location):
                try:
                    self.config.read(location)
                    break
                except Exception:
                    continue
        
        # Set defaults if no config file was loaded
        if not self.config.sections():
            self._set_defaults()
    
    def _set_defaults(self) -> None:
        """Set default configuration values"""
        self.config['github'] = {
            'token': '',
            'owner': '',
            'repo': ''
        }
        
        self.config['settings'] = {
            'auto_close': 'true',
            'dry_run': 'false',
            'output_format': 'text',
            'verbose': 'false'
        }
        
        self.config['labels'] = {
            'base_label': 'tfsec-security',
            'critical_label': 'severity-critical',
            'high_label': 'severity-high', 
            'medium_label': 'severity-medium',
            'low_label': 'severity-low'
        }
    
    def get_github_token(self) -> Optional[str]:
        """Get GitHub token from config or environment"""
        return (
            os.getenv('GITHUB_TOKEN') or 
            self.config.get('github', 'token', fallback=None)
        )
    
    def get_github_owner(self) -> Optional[str]:
        """Get GitHub owner from config or environment"""
        return (
            os.getenv('GITHUB_OWNER') or
            self.config.get('github', 'owner', fallback=None)
        )
    
    def get_github_repo(self) -> Optional[str]:
        """Get GitHub repo from config or environment"""
        return (
            os.getenv('GITHUB_REPO') or
            self.config.get('github', 'repo', fallback=None)
        )
    
    def get_auto_close(self) -> bool:
        """Get auto-close setting"""
        return self.config.getboolean('settings', 'auto_close', fallback=True)
    
    def get_dry_run(self) -> bool:
        """Get dry-run setting"""
        return self.config.getboolean('settings', 'dry_run', fallback=False)
    
    def get_output_format(self) -> str:
        """Get output format setting"""
        return self.config.get('settings', 'output_format', fallback='text')
    
    def get_verbose(self) -> bool:
        """Get verbose setting"""
        return self.config.getboolean('settings', 'verbose', fallback=False)
    
    def get_labels(self) -> Dict[str, str]:
        """Get label configuration"""
        return {
            'base': self.config.get('labels', 'base_label', fallback='tfsec-security'),
            'critical': self.config.get('labels', 'critical_label', fallback='severity-critical'),
            'high': self.config.get('labels', 'high_label', fallback='severity-high'),
            'medium': self.config.get('labels', 'medium_label', fallback='severity-medium'),
            'low': self.config.get('labels', 'low_label', fallback='severity-low')
        }
    
    def create_sample_config(self, path: str = 'tfgitsec.ini') -> None:
        """Create a sample configuration file"""
        sample_config = """[github]
# GitHub personal access token (can also use GITHUB_TOKEN env var)
token = 

# GitHub repository owner/organization (can also use GITHUB_OWNER env var)  
owner = 

# GitHub repository name (can also use GITHUB_REPO env var)
repo = 

[settings]
# Automatically close resolved issues (true/false)
auto_close = true

# Dry run mode - don't make actual changes (true/false)
dry_run = false

# Default output format (text/json)
output_format = text

# Verbose output (true/false)
verbose = false

[labels]
# Base label for all tfgitsec issues
base_label = tfsec-security

# Severity-specific labels
critical_label = severity-critical
high_label = severity-high
medium_label = severity-medium
low_label = severity-low
"""
        
        with open(path, 'w') as f:
            f.write(sample_config)
        
        print(f"Sample configuration created at {path}")
