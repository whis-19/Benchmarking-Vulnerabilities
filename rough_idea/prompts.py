"""
Prompt Templates Module for HMSCG Pipeline

Centralized prompt engineering with:
- Role-based prompting
- Few-shot examples
- Explicit security constraints
- Structured output formatting
- Chain-of-thought reasoning
"""

from typing import List, Optional
from dataclasses import dataclass


@dataclass
class SecureCodeExample:
    """Example of secure code for few-shot learning"""
    task: str
    insecure_code: str
    secure_code: str
    explanation: str


class PromptTemplates:
    """Advanced prompt templates for secure code generation"""
    
    # System role for the LLM
    SYSTEM_ROLE = """You are an expert security engineer specializing in writing secure Python code.
Your code must be:
- Free from common vulnerabilities (SQL injection, XSS, command injection, path traversal, etc.)
- Following OWASP secure coding guidelines and CWE best practices
- Properly validated and sanitized for all user inputs
- Using parameterized queries for database operations
- Implementing proper error handling without exposing sensitive information
- Following the principle of least privilege
- Well-documented with security considerations explained

You have deep knowledge of:
- OWASP Top 10 vulnerabilities
- CWE (Common Weakness Enumeration)
- Secure coding standards for Python
- Cryptography best practices
- Input validation and output encoding
- Authentication and authorization patterns"""

    # Few-shot examples for secure code generation
    SECURE_EXAMPLES = [
        SecureCodeExample(
            task="Create a function to query user data from database",
            insecure_code="""def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()""",
            secure_code="""def get_user(username):
    # Use parameterized query to prevent SQL injection
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()""",
            explanation="Use parameterized queries instead of string formatting to prevent SQL injection (CWE-89)"
        ),
        SecureCodeExample(
            task="Create a function to execute system commands",
            insecure_code="""def run_command(filename):
    os.system(f"cat {filename}")""",
            secure_code="""import subprocess
import shlex

def run_command(filename):
    # Validate filename to prevent path traversal
    if '..' in filename or filename.startswith('/'):
        raise ValueError("Invalid filename")
    
    # Use subprocess with argument list (not shell=True)
    result = subprocess.run(['cat', filename], 
                          capture_output=True, 
                          text=True,
                          check=True)
    return result.stdout""",
            explanation="Use subprocess with argument list instead of os.system to prevent command injection (CWE-78). Validate input to prevent path traversal (CWE-22)"
        ),
        SecureCodeExample(
            task="Create a function to hash passwords",
            insecure_code="""import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()""",
            secure_code="""import hashlib
import os

def hash_password(password):
    # Use strong hashing algorithm with salt
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', 
                               password.encode('utf-8'), 
                               salt, 
                               100000)
    return salt + key""",
            explanation="Use strong cryptographic hash (PBKDF2) with salt instead of weak MD5 (CWE-327, CWE-759)"
        )
    ]
    
    @staticmethod
    def format_examples(examples: List[SecureCodeExample] = None) -> str:
        """Format secure code examples for prompt"""
        if examples is None:
            examples = PromptTemplates.SECURE_EXAMPLES
        
        formatted = "SECURE CODING EXAMPLES:\n\n"
        for i, example in enumerate(examples, 1):
            formatted += f"Example {i}: {example.task}\n\n"
            formatted += f"❌ INSECURE (DO NOT DO THIS):\n```python\n{example.insecure_code}\n```\n\n"
            formatted += f"✅ SECURE (DO THIS):\n```python\n{example.secure_code}\n```\n\n"
            formatted += f"Why: {example.explanation}\n\n"
            formatted += "---\n\n"
        
        return formatted
    
    @staticmethod
    def format_guidelines(guidelines: List[str]) -> str:
        """Format security guidelines from RAG retrieval"""
        if not guidelines:
            return ""
        
        formatted = "RELEVANT SECURITY GUIDELINES:\n\n"
        for i, guideline in enumerate(guidelines, 1):
            # Extract content from Document object if needed
            content = guideline.page_content if hasattr(guideline, 'page_content') else str(guideline)
            formatted += f"{i}. {content}\n\n"
        
        return formatted
    
    @staticmethod
    def generation_prompt(task: str, 
                         guidelines: List[str] = None,
                         include_examples: bool = True,
                         include_reasoning: bool = True) -> str:
        """
        Generate the main code generation prompt
        
        Args:
            task: The coding task description
            guidelines: Retrieved security guidelines from RAG
            include_examples: Whether to include few-shot examples
            include_reasoning: Whether to request chain-of-thought reasoning
            
        Returns:
            Formatted prompt string
        """
        prompt = f"{PromptTemplates.SYSTEM_ROLE}\n\n"
        prompt += "=" * 80 + "\n\n"
        
        # Add task
        prompt += f"TASK:\n{task}\n\n"
        
        # Add guidelines if provided
        if guidelines:
            prompt += PromptTemplates.format_guidelines(guidelines)
        
        # Add examples if requested
        if include_examples:
            prompt += PromptTemplates.format_examples()
        
        # Add constraints
        prompt += """SECURITY CONSTRAINTS (MUST FOLLOW):
1. DO NOT use: eval(), exec(), compile(), __import__() for dynamic code execution
2. DO NOT use: pickle, marshal for deserialization without validation
3. DO NOT use: os.system(), subprocess with shell=True for command execution
4. DO NOT use: MD5, SHA1 for password hashing (use bcrypt, scrypt, or PBKDF2)
5. DO NOT concatenate user input into SQL queries (use parameterized queries)
6. DO NOT trust user input - always validate, sanitize, and escape
7. DO NOT expose sensitive information in error messages
8. DO NOT hardcode credentials, API keys, or secrets
9. ALWAYS use secure random (secrets module) for security-sensitive operations
10. ALWAYS implement proper error handling and logging

"""
        
        # Add output format instructions
        if include_reasoning:
            prompt += """Please provide your response in the following format:

```reasoning
[Your security analysis and design decisions]
- What security risks does this task involve?
- What vulnerabilities should be avoided?
- What security measures will you implement?
```

```python
[Your complete, secure Python code]
```

"""
        else:
            prompt += """Please provide your response as:

```python
[Your complete, secure Python code]
```

"""
        
        return prompt
    
    @staticmethod
    def critique_prompt(code: str, 
                       security_issues: List[str] = None,
                       task_context: str = None) -> str:
        """
        Generate critique prompt for code refinement
        
        Args:
            code: The code to critique
            security_issues: Known security issues from analyzer
            task_context: Original task for context
            
        Returns:
            Formatted critique prompt
        """
        prompt = """You are a security code reviewer. Review the following code for security vulnerabilities and quality issues.

"""
        
        if task_context:
            prompt += f"ORIGINAL TASK:\n{task_context}\n\n"
        
        prompt += f"""CODE TO REVIEW:
```python
{code}
```

"""
        
        if security_issues:
            prompt += "DETECTED SECURITY ISSUES:\n"
            for i, issue in enumerate(security_issues, 1):
                prompt += f"{i}. {issue}\n"
            prompt += "\n"
        
        prompt += """Provide a detailed security critique focusing on:

1. **Security Vulnerabilities**: 
   - Identify specific vulnerabilities (SQL injection, XSS, command injection, etc.)
   - Map to CWE IDs where applicable
   - Rate severity (HIGH/MEDIUM/LOW)

2. **Code Quality Issues**:
   - Input validation problems
   - Error handling weaknesses
   - Hardcoded secrets or credentials
   - Weak cryptography usage

3. **Specific Recommendations**:
   - Which lines need to be changed?
   - What specific changes should be made?
   - Provide code snippets for fixes

Be specific, actionable, and focus on the most critical issues first.
"""
        
        return prompt
    
    @staticmethod
    def improvement_prompt(code: str, 
                          critique: str, 
                          task: str,
                          guidelines: List[str] = None) -> str:
        """
        Generate improvement prompt for code refinement
        
        Args:
            code: Original code to improve
            critique: Security critique
            task: Original task
            guidelines: Security guidelines
            
        Returns:
            Formatted improvement prompt
        """
        prompt = f"""{PromptTemplates.SYSTEM_ROLE}

ORIGINAL TASK:
{task}

"""
        
        if guidelines:
            prompt += PromptTemplates.format_guidelines(guidelines)
        
        prompt += f"""CURRENT CODE (WITH SECURITY ISSUES):
```python
{code}
```

SECURITY CRITIQUE:
{critique}

Based on the security critique above, provide an IMPROVED version of the code that:
1. Fixes ALL identified security vulnerabilities
2. Implements proper input validation and sanitization
3. Uses secure coding practices
4. Maintains the original functionality
5. Adds security-focused comments

Provide ONLY the complete improved code, not just the changes.

```python
[Your complete improved code here]
```
"""
        
        return prompt
    
    @staticmethod
    def extract_code_from_response(response: str) -> str:
        """
        Extract Python code from LLM response
        
        Handles multiple formats:
        - ```python ... ```
        - ```reasoning ... ``` followed by ```python ... ```
        - Plain code without markers
        """
        import re
        
        # Try to find python code block
        python_blocks = re.findall(r'```python\s*(.*?)```', response, re.DOTALL)
        
        if python_blocks:
            # Return the last python block (in case there are examples before)
            return python_blocks[-1].strip()
        
        # Try to find any code block
        code_blocks = re.findall(r'```\s*(.*?)```', response, re.DOTALL)
        
        if code_blocks:
            # Filter out reasoning blocks
            for block in reversed(code_blocks):
                if not block.strip().startswith('[Your') and len(block.strip()) > 50:
                    return block.strip()
        
        # If no code blocks found, return the whole response
        # (might be plain code without markers)
        return response.strip()


# Convenience functions
def generate_code_prompt(task: str, guidelines: List[str] = None) -> str:
    """Generate a code generation prompt"""
    return PromptTemplates.generation_prompt(task, guidelines)


def generate_critique_prompt(code: str, issues: List[str] = None, task: str = None) -> str:
    """Generate a code critique prompt"""
    return PromptTemplates.critique_prompt(code, issues, task)


def generate_improvement_prompt(code: str, critique: str, task: str, guidelines: List[str] = None) -> str:
    """Generate a code improvement prompt"""
    return PromptTemplates.improvement_prompt(code, critique, task, guidelines)


if __name__ == "__main__":
    # Test prompt generation
    task = "Create a function to authenticate users with username and password"
    
    print("=" * 80)
    print("GENERATION PROMPT:")
    print("=" * 80)
    print(generate_code_prompt(task))
    
    print("\n" + "=" * 80)
    print("CRITIQUE PROMPT:")
    print("=" * 80)
    test_code = "def auth(user, pwd): return user == 'admin' and pwd == 'password123'"
    print(generate_critique_prompt(test_code, ["Hardcoded credentials"], task))
