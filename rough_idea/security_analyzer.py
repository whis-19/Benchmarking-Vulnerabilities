"""
Security Analyzer Module for HMSCG Pipeline

Integrates Bandit security scanner and custom security rules to analyze
generated Python code for vulnerabilities.
"""

import subprocess
import tempfile
import json
import os
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SecurityIssue:
    """Represents a security issue found in code"""
    severity: str  # HIGH, MEDIUM, LOW
    confidence: str  # HIGH, MEDIUM, LOW
    issue_text: str
    line_number: int
    tool: str = "custom"  # Bandit, Semgrep, custom
    cwe_id: Optional[str] = None
    test_id: Optional[str] = None
    
    @property
    def severity_score(self) -> int:
        """Convert severity to numeric score"""
        return {'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}.get(self.severity, 0)
    
    @property
    def confidence_score(self) -> int:
        """Convert confidence to numeric score"""
        return {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}.get(self.confidence, 0)


@dataclass
class SecurityReport:
    """Comprehensive security analysis report"""
    score: float  # 0-100, higher is better
    issues: List[SecurityIssue] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    high_severity_count: int = 0
    medium_severity_count: int = 0
    low_severity_count: int = 0
    
    @property
    def total_issues(self) -> int:
        """Total number of issues found"""
        return len(self.issues)
    
    @property
    def is_secure(self) -> bool:
        """Check if code meets security threshold"""
        return self.score >= 80 and self.high_severity_count == 0


class SecurityAnalyzer:
    """Analyzes Python code for security vulnerabilities"""
    
    # Custom security patterns to check
    CUSTOM_PATTERNS = {
        'sql_injection': [
            r'execute\s*\(\s*["\'].*%s.*["\']',
            r'execute\s*\(\s*f["\'].*\{.*\}.*["\']',
            r'execute\s*\(\s*.*\+.*\)',
        ],
        'command_injection': [
            r'os\.system\s*\(',
            r'subprocess\.(call|run|Popen)\s*\(\s*shell\s*=\s*True',
            r'eval\s*\(',
            r'exec\s*\(',
        ],
        'path_traversal': [
            r'open\s*\(\s*.*\+.*\)',
            r'open\s*\(\s*f["\'].*\{.*\}.*["\']',
        ],
        'hardcoded_credentials': [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ],
        'unsafe_deserialization': [
            r'pickle\.loads?\s*\(',
            r'marshal\.loads?\s*\(',
            r'yaml\.load\s*\(',  # Should use safe_load
        ],
        'weak_crypto': [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'random\.random\s*\(',  # For security, should use secrets module
        ],
    }
    
    def __init__(self, report_dir: Optional[str] = None):
        self.bandit_available = self._check_bandit_available()
        self.semgrep_available = self._check_semgrep_available()
        self.report_dir = Path(report_dir) if report_dir else None
        if self.report_dir:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            
        self.custom_pattern_regex = {
            category: [re.compile(p, re.IGNORECASE) for p in patterns]
            for category, patterns in self.CUSTOM_PATTERNS.items()
        }
    
    def _check_bandit_available(self) -> bool:
        """Check if Bandit is installed and available"""
        try:
            result = subprocess.run(['bandit', '--version'], 
                                  capture_output=True, 
                                  text=True,
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _check_semgrep_available(self) -> bool:
        """Check if Semgrep is installed and available"""
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                   capture_output=True, 
                                   text=True,
                                   timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def analyze(self, code: str, task_id: str = "unknown") -> SecurityReport:
        """
        Perform comprehensive security analysis on code
        
        Args:
            code: Python code to analyze
            task_id: Identifier for logging/debugging
            
        Returns:
            SecurityReport with findings and score
        """
        issues = []
        
        # 1. Run Bandit if available
        if self.bandit_available:
            bandit_issues = self._run_bandit(code, task_id)
            issues.extend(bandit_issues)
        
        # 2. Run Semgrep if available
        if self.semgrep_available:
            semgrep_issues = self._run_semgrep(code, task_id)
            issues.extend(semgrep_issues)
        
        # 3. Run custom security checks
        custom_issues = self._check_custom_rules(code)
        issues.extend(custom_issues)
        
        # 3. Calculate security score
        score = self._calculate_security_score(issues)
        
        # 4. Extract CWE IDs
        cwe_ids = self._extract_cwe_ids(issues)
        
        # 5. Count severity levels
        high_count = sum(1 for i in issues if i.severity == 'HIGH')
        medium_count = sum(1 for i in issues if i.severity == 'MEDIUM')
        low_count = sum(1 for i in issues if i.severity == 'LOW')
        
        return SecurityReport(
            score=score,
            issues=issues,
            cwe_ids=cwe_ids,
            high_severity_count=high_count,
            medium_severity_count=medium_count,
            low_severity_count=low_count
        )
    
    def _run_bandit(self, code: str, task_id: str) -> List[SecurityIssue]:
        """Run Bandit security scanner on code"""
        issues = []
        
        # Write code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(code)
            temp_path = f.name
        
        try:
            # Run Bandit
            result = subprocess.run(
                ['bandit', '-f', 'json', temp_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Parse JSON output
            if result.stdout:
                if self.report_dir:
                    bandit_dir = self.report_dir / "bandit"
                    bandit_dir.mkdir(parents=True, exist_ok=True)
                    report_file = bandit_dir / f"{task_id}_bandit.json"
                    with open(report_file, 'w') as rf:
                        rf.write(result.stdout)
                
                try:
                    bandit_output = json.loads(result.stdout)
                    
                    for result_item in bandit_output.get('results', []):
                        cwe_val = result_item.get('issue_cwe', {}).get('id') if isinstance(result_item.get('issue_cwe'), dict) else None
                        issue = SecurityIssue(
                            severity=result_item.get('issue_severity', 'MEDIUM'),
                            confidence=result_item.get('issue_confidence', 'MEDIUM'),
                            issue_text=result_item.get('issue_text', 'Unknown issue'),
                            line_number=result_item.get('line_number', 0),
                            tool='Bandit',
                            cwe_id=str(cwe_val) if cwe_val is not None else None,
                            test_id=result_item.get('test_id')
                        )
                        issues.append(issue)
                except json.JSONDecodeError:
                    print(f"Warning: Could not parse Bandit output")
        
        except subprocess.TimeoutExpired:
            print(f"Warning: Bandit analysis timed out")
        except Exception as e:
            print(f"Warning: Bandit analysis failed: {e}")
        finally:
            # Clean up temp file
            try:
                os.unlink(temp_path)
            except:
                pass
        
        return issues
    
    def _run_semgrep(self, code: str, task_id: str) -> List[SecurityIssue]:
        """Run Semgrep security scanner on code"""
        issues = []
        
        # Write code to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(code)
            temp_path = f.name
        
        try:
            # Run Semgrep with basic python security rules
            result = subprocess.run(
                ['semgrep', '--config', 'p/python', '--json', temp_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.stdout:
                if self.report_dir:
                    semgrep_dir = self.report_dir / "semgrep"
                    semgrep_dir.mkdir(parents=True, exist_ok=True)
                    report_file = semgrep_dir / f"{task_id}_semgrep.json"
                    with open(report_file, 'w') as rf:
                        rf.write(result.stdout)
                        
                semgrep_output = json.loads(result.stdout)
                for res in semgrep_output.get('results', []):
                    # Map Semgrep severity (ERROR, WARNING, INFO) to our levels
                    sem_sev = res.get('extra', {}).get('severity', 'WARNING')
                    severity = 'HIGH' if sem_sev == 'ERROR' else 'MEDIUM' if sem_sev == 'WARNING' else 'LOW'
                    
                    cwe_list = res.get('extra', {}).get('metadata', {}).get('cwe', [])
                    cwe_val = cwe_list[0] if isinstance(cwe_list, list) and len(cwe_list) > 0 else None
                    
                    issue = SecurityIssue(
                        severity=severity,
                        confidence='HIGH',
                        issue_text=res.get('extra', {}).get('message', 'Semgrep issue'),
                        line_number=res.get('start', {}).get('line', 0),
                        tool='Semgrep',
                        cwe_id=str(cwe_val) if cwe_val is not None else None,
                        test_id=res.get('check_id')
                    )
                    issues.append(issue)
        except Exception as e:
            print(f"Warning: Semgrep analysis failed: {e}")
        finally:
            try: os.unlink(temp_path)
            except: pass
            
        return issues
    
    def _check_custom_rules(self, code: str) -> List[SecurityIssue]:
        """Check code against custom security patterns"""
        issues = []
        lines = code.split('\n')
        
        for category, patterns in self.custom_pattern_regex.items():
            for pattern in patterns:
                for line_num, line in enumerate(lines, 1):
                    if pattern.search(line):
                        # Determine severity based on category
                        severity = self._get_category_severity(category)
                        
                        issue = SecurityIssue(
                            severity=severity,
                            confidence='MEDIUM',
                            issue_text=f"Potential {category.replace('_', ' ')}: {line.strip()[:50]}",
                            line_number=line_num,
                            cwe_id=self._get_category_cwe(category)
                        )
                        issues.append(issue)
        
        return issues
    
    def _get_category_severity(self, category: str) -> str:
        """Map vulnerability category to severity level"""
        high_severity = {'sql_injection', 'command_injection', 'unsafe_deserialization'}
        medium_severity = {'path_traversal', 'weak_crypto'}
        
        if category in high_severity:
            return 'HIGH'
        elif category in medium_severity:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_category_cwe(self, category: str) -> Optional[str]:
        """Map vulnerability category to CWE ID"""
        cwe_mapping = {
            'sql_injection': 'CWE-89',
            'command_injection': 'CWE-78',
            'path_traversal': 'CWE-22',
            'hardcoded_credentials': 'CWE-798',
            'unsafe_deserialization': 'CWE-502',
            'weak_crypto': 'CWE-327',
        }
        return cwe_mapping.get(category)
    
    def _calculate_security_score(self, issues: List[SecurityIssue]) -> float:
        """
        Calculate security score (0-100, higher is better)
        
        Score calculation:
        - Start at 100
        - Deduct points based on severity and confidence
        - High severity, high confidence: -15 points
        - Medium severity, medium confidence: -5 points
        - Low severity: -2 points
        """
        if not issues:
            return 100.0
        
        score = 100.0
        
        for issue in issues:
            deduction = (issue.severity_score * issue.confidence_score) / 3
            score -= deduction
        
        return max(0.0, score)
    
    def _extract_cwe_ids(self, issues: List[SecurityIssue]) -> List[str]:
        """Extract unique CWE IDs from issues"""
        cwe_ids = set()
        for issue in issues:
            if issue.cwe_id:
                cwe_ids.add(str(issue.cwe_id))
        return sorted(list(cwe_ids))


def analyze_code(code: str, task_id: str = "unknown") -> SecurityReport:
    """Convenience function to analyze code security"""
    analyzer = SecurityAnalyzer()
    return analyzer.analyze(code, task_id)


if __name__ == "__main__":
    # Test the analyzer
    test_code = """
import os
import sqlite3

def unsafe_query(user_input):
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    return cursor.fetchall()

def unsafe_command(filename):
    # Command injection vulnerability
    os.system(f"cat {filename}")

def weak_hash(password):
    import hashlib
    # Weak cryptographic hash
    return hashlib.md5(password.encode()).hexdigest()

# Hardcoded credentials
api_key = "sk-1234567890abcdef"
"""
    
    report = analyze_code(test_code, "test")
    print(f"Security Score: {report.score:.2f}")
    print(f"Total Issues: {report.total_issues}")
    print(f"High Severity: {report.high_severity_count}")
    print(f"Medium Severity: {report.medium_severity_count}")
    print(f"Low Severity: {report.low_severity_count}")
    print(f"CWE IDs: {report.cwe_ids}")
    print(f"Is Secure: {report.is_secure}")
    print("\nIssues:")
    for issue in report.issues:
        print(f"  Line {issue.line_number}: [{issue.severity}] {issue.issue_text}")
