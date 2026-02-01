"""
Context-Aware Generation (CAG) Module

Implements context-aware code generation that analyzes the task
and dynamically adjusts the generation strategy based on:
- Task complexity
- Security requirements
- Domain-specific patterns
- CWE categories involved
"""

from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import re


@dataclass
class TaskContext:
    """Analyzed context from a coding task"""
    task: str
    complexity: str  # 'simple', 'moderate', 'complex'
    security_domains: List[str]  # e.g., ['database', 'file_io', 'network']
    potential_cwes: List[str]  # Potential CWE categories
    requires_validation: bool
    requires_sanitization: bool
    requires_encryption: bool
    suggested_guidelines: List[str]


class ContextAnalyzer:
    """Analyzes coding tasks to extract context and security requirements"""
    
    # Domain patterns
    DOMAIN_PATTERNS = {
        'database': [
            r'\b(sql|database|query|select|insert|update|delete|db)\b',
            r'\b(mysql|postgres|sqlite|mongodb)\b',
        ],
        'file_io': [
            r'\b(file|read|write|open|path|directory|folder)\b',
            r'\b(upload|download|save|load)\b',
        ],
        'network': [
            r'\b(http|https|api|request|url|socket|network)\b',
            r'\b(get|post|put|delete|fetch)\b',
        ],
        'authentication': [
            r'\b(login|auth|password|credential|token|session)\b',
            r'\b(user|username|authenticate)\b',
        ],
        'cryptography': [
            r'\b(encrypt|decrypt|hash|crypto|cipher|key)\b',
            r'\b(password|secret|token)\b',
        ],
        'command_execution': [
            r'\b(command|execute|run|shell|process|subprocess)\b',
            r'\b(system|exec|eval)\b',
        ],
        'deserialization': [
            r'\b(pickle|marshal|json|yaml|deserialize|load)\b',
        ],
        'web': [
            r'\b(html|javascript|xss|csrf|web|browser)\b',
            r'\b(form|input|output|render)\b',
        ],
    }
    
    # CWE mappings for domains
    DOMAIN_CWE_MAP = {
        'database': ['CWE-89'],  # SQL Injection
        'file_io': ['CWE-22', 'CWE-73'],  # Path Traversal, External Control of File Name
        'network': ['CWE-918', 'CWE-20'],  # SSRF, Improper Input Validation
        'authentication': ['CWE-798', 'CWE-259', 'CWE-307'],  # Hardcoded Credentials, etc.
        'cryptography': ['CWE-327', 'CWE-328'],  # Weak Crypto
        'command_execution': ['CWE-78', 'CWE-94'],  # Command Injection, Code Injection
        'deserialization': ['CWE-502'],  # Deserialization of Untrusted Data
        'web': ['CWE-79', 'CWE-352'],  # XSS, CSRF
    }
    
    # Security guidelines for domains
    DOMAIN_GUIDELINES = {
        'database': [
            "Use parameterized queries or prepared statements",
            "Never concatenate user input into SQL queries",
            "Implement proper input validation for all database inputs",
            "Use ORM frameworks with built-in SQL injection protection",
        ],
        'file_io': [
            "Validate and sanitize all file paths",
            "Prevent path traversal attacks (check for ../ patterns)",
            "Use allowlists for file extensions and locations",
            "Implement proper file permissions and access controls",
        ],
        'network': [
            "Validate and sanitize all URLs",
            "Implement allowlists for allowed domains/IPs",
            "Use HTTPS for all sensitive communications",
            "Validate SSL/TLS certificates",
        ],
        'authentication': [
            "Never hardcode credentials or API keys",
            "Use strong password hashing (bcrypt, scrypt, PBKDF2)",
            "Implement rate limiting for login attempts",
            "Use secure session management",
        ],
        'cryptography': [
            "Use strong, modern cryptographic algorithms",
            "Never implement custom cryptography",
            "Use proper key management and storage",
            "Use cryptographically secure random number generators",
        ],
        'command_execution': [
            "Avoid shell execution when possible",
            "Use subprocess with argument lists, not shell=True",
            "Validate and sanitize all command inputs",
            "Use allowlists for allowed commands",
        ],
        'deserialization': [
            "Avoid deserializing untrusted data",
            "Use safe deserialization methods (json.loads, yaml.safe_load)",
            "Validate data before deserialization",
            "Implement integrity checks (HMAC)",
        ],
        'web': [
            "Escape all user input before rendering",
            "Use Content Security Policy (CSP)",
            "Implement CSRF tokens for state-changing operations",
            "Validate and sanitize all form inputs",
        ],
    }
    
    def analyze_task(self, task: str) -> TaskContext:
        """
        Analyze a coding task to extract context and requirements
        
        Args:
            task: The coding task description
            
        Returns:
            TaskContext with analyzed information
        """
        task_lower = task.lower()
        
        # Detect security domains
        domains = self._detect_domains(task_lower)
        
        # Determine complexity
        complexity = self._assess_complexity(task)
        
        # Identify potential CWEs
        potential_cwes = self._identify_cwes(domains)
        
        # Determine security requirements
        requires_validation = self._requires_validation(task_lower, domains)
        requires_sanitization = self._requires_sanitization(task_lower, domains)
        requires_encryption = self._requires_encryption(task_lower, domains)
        
        # Get suggested guidelines
        suggested_guidelines = self._get_guidelines(domains)
        
        return TaskContext(
            task=task,
            complexity=complexity,
            security_domains=domains,
            potential_cwes=potential_cwes,
            requires_validation=requires_validation,
            requires_sanitization=requires_sanitization,
            requires_encryption=requires_encryption,
            suggested_guidelines=suggested_guidelines
        )
    
    def _detect_domains(self, task_lower: str) -> List[str]:
        """Detect which security domains are relevant to the task"""
        detected_domains = []
        
        for domain, patterns in self.DOMAIN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, task_lower, re.IGNORECASE):
                    detected_domains.append(domain)
                    break
        
        return list(set(detected_domains))
    
    def _assess_complexity(self, task: str) -> str:
        """Assess task complexity based on various factors"""
        # Simple heuristics
        word_count = len(task.split())
        has_multiple_operations = len(re.findall(r'\band\b', task.lower())) > 1
        has_conditions = bool(re.search(r'\b(if|when|condition|check)\b', task.lower()))
        
        if word_count < 15 and not has_multiple_operations:
            return 'simple'
        elif word_count > 40 or has_multiple_operations:
            return 'complex'
        else:
            return 'moderate'
    
    def _identify_cwes(self, domains: List[str]) -> List[str]:
        """Identify potential CWE categories based on domains"""
        cwes = []
        for domain in domains:
            if domain in self.DOMAIN_CWE_MAP:
                cwes.extend(self.DOMAIN_CWE_MAP[domain])
        return list(set(cwes))
    
    def _requires_validation(self, task_lower: str, domains: List[str]) -> bool:
        """Determine if task requires input validation"""
        validation_keywords = ['input', 'user', 'form', 'parameter', 'data']
        return any(kw in task_lower for kw in validation_keywords) or len(domains) > 0
    
    def _requires_sanitization(self, task_lower: str, domains: List[str]) -> bool:
        """Determine if task requires input sanitization"""
        risky_domains = {'database', 'command_execution', 'web', 'file_io'}
        return bool(risky_domains.intersection(set(domains)))
    
    def _requires_encryption(self, task_lower: str, domains: List[str]) -> bool:
        """Determine if task requires encryption"""
        encryption_keywords = ['password', 'secret', 'credential', 'sensitive', 'encrypt']
        return any(kw in task_lower for kw in encryption_keywords) or 'cryptography' in domains
    
    def _get_guidelines(self, domains: List[str]) -> List[str]:
        """Get relevant security guidelines for detected domains"""
        guidelines = []
        for domain in domains:
            if domain in self.DOMAIN_GUIDELINES:
                guidelines.extend(self.DOMAIN_GUIDELINES[domain])
        return guidelines
    
    def enhance_prompt_with_context(self, task: str, base_prompt: str) -> str:
        """
        Enhance a prompt with context-aware information
        
        Args:
            task: The coding task
            base_prompt: Base prompt to enhance
            
        Returns:
            Enhanced prompt with context
        """
        context = self.analyze_task(task)
        
        enhancement = f"\n\nCONTEXT ANALYSIS:\n"
        enhancement += f"- Task Complexity: {context.complexity.upper()}\n"
        enhancement += f"- Security Domains: {', '.join(context.security_domains) if context.security_domains else 'General'}\n"
        enhancement += f"- Potential Vulnerabilities: {', '.join(context.potential_cwes) if context.potential_cwes else 'None identified'}\n"
        
        if context.requires_validation:
            enhancement += "- ⚠️ REQUIRES: Input validation\n"
        if context.requires_sanitization:
            enhancement += "- ⚠️ REQUIRES: Input sanitization\n"
        if context.requires_encryption:
            enhancement += "- ⚠️ REQUIRES: Encryption/secure storage\n"
        
        if context.suggested_guidelines:
            enhancement += "\nCONTEXT-SPECIFIC GUIDELINES:\n"
            for i, guideline in enumerate(context.suggested_guidelines, 1):
                enhancement += f"{i}. {guideline}\n"
        
        return base_prompt + enhancement


# Convenience function
def analyze_task_context(task: str) -> TaskContext:
    """Analyze a coding task and return context"""
    analyzer = ContextAnalyzer()
    return analyzer.analyze_task(task)


if __name__ == "__main__":
    # Test the context analyzer
    test_tasks = [
        "Create a function to query user data from a database",
        "Write a function to hash passwords securely",
        "Implement file upload functionality",
        "Create an API endpoint to execute system commands",
    ]
    
    analyzer = ContextAnalyzer()
    
    for task in test_tasks:
        print(f"\nTask: {task}")
        print("=" * 80)
        context = analyzer.analyze_task(task)
        print(f"Complexity: {context.complexity}")
        print(f"Domains: {context.security_domains}")
        print(f"Potential CWEs: {context.potential_cwes}")
        print(f"Requires Validation: {context.requires_validation}")
        print(f"Requires Sanitization: {context.requires_sanitization}")
        print(f"Guidelines: {len(context.suggested_guidelines)} suggested")
