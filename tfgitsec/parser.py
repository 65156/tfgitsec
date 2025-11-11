"""
TfSec JSON parser
"""
import json
from typing import List, Dict, Any
from .models import TfSecFinding, Location


class TfSecParseError(Exception):
    """Raised when there's an error parsing tfsec JSON"""
    pass


class TfSecParser:
    """Parser for TfSec JSON output"""
    
    @staticmethod
    def parse_file(file_path: str, prefix: str = None) -> List[TfSecFinding]:
        """Parse tfsec findings from a JSON file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return TfSecParser.parse_json(data, prefix)
        except FileNotFoundError:
            raise TfSecParseError(f"TfSec JSON file not found: {file_path}")
        except json.JSONDecodeError as e:
            raise TfSecParseError(f"Invalid JSON in tfsec file: {e}")
        except Exception as e:
            raise TfSecParseError(f"Error reading tfsec file: {e}")
    
    @staticmethod
    def parse_json(data: Dict[str, Any], prefix: str = None) -> List[TfSecFinding]:
        """Parse tfsec findings from JSON data"""
        findings = []
        
        if not isinstance(data, dict):
            raise TfSecParseError("TfSec JSON must be a dictionary")
        
        results = data.get("results", [])
        if not isinstance(results, list):
            raise TfSecParseError("TfSec 'results' field must be a list")
        
        for i, result in enumerate(results):
            try:
                finding = TfSecParser._parse_single_finding(result, prefix)
                findings.append(finding)
            except Exception as e:
                raise TfSecParseError(f"Error parsing finding #{i}: {e}")
        
        return findings
    
    @staticmethod
    def _parse_single_finding(result: Dict[str, Any], prefix: str = None) -> TfSecFinding:
        """Parse a single tfsec finding from JSON"""
        required_fields = [
            'rule_id', 'long_id', 'rule_description', 'rule_provider',
            'rule_service', 'impact', 'resolution', 'links', 'description',
            'severity', 'warning', 'status', 'resource', 'location'
        ]
        
        for field in required_fields:
            if field not in result:
                raise ValueError(f"Missing required field: {field}")
        
        # Parse location
        location_data = result['location']
        if not isinstance(location_data, dict):
            raise ValueError("Location must be a dictionary")
        
        location_required = ['filename', 'start_line', 'end_line']
        for field in location_required:
            if field not in location_data:
                raise ValueError(f"Missing required location field: {field}")
        
        location = Location(
            filename=location_data['filename'],
            start_line=int(location_data['start_line']),
            end_line=int(location_data['end_line'])
        )
        
        # Validate and convert data types
        links = result['links']
        if not isinstance(links, list):
            raise ValueError("Links must be a list")
        
        # Create the finding
        finding = TfSecFinding(
            rule_id=str(result['rule_id']),
            long_id=str(result['long_id']),
            rule_description=str(result['rule_description']),
            rule_provider=str(result['rule_provider']),
            rule_service=str(result['rule_service']),
            impact=str(result['impact']),
            resolution=str(result['resolution']),
            links=[str(link) for link in links],
            description=str(result['description']),
            severity=str(result['severity']).upper(),
            warning=bool(result['warning']),
            status=int(result['status']),
            resource=str(result['resource']),
            location=location,
            prefix=prefix
        )
        
        return finding
    
    @staticmethod
    def validate_findings(findings: List[TfSecFinding]) -> Dict[str, Any]:
        """Validate parsed findings and return statistics"""
        if not findings:
            return {
                "total": 0,
                "by_severity": {},
                "by_service": {},
                "warnings": 0
            }
        
        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_service": {},
            "warnings": sum(1 for f in findings if f.warning)
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.severity
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1
            
            # Count by service
            service = finding.rule_service
            stats["by_service"][service] = stats["by_service"].get(service, 0) + 1
        
        return stats
