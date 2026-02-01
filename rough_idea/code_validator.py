"""
Code Validator Module for HMSCG Pipeline

Provides multi-stage validation of generated Python code:
- Syntax validation using compile()
- AST parsing and validation
- Import safety checking
- Code complexity analysis
"""

import ast
import re
from typing import Dict, List, Set, Optional
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Results from code validation"""
    syntax_valid: bool
    ast_valid: bool
    imports_safe: bool
    complexity_score: float
    errors: List[str]
    warnings: List[str]
    dangerous_imports: List[str]
    
    @property
    def is_valid(self) -> bool:
        """Overall validity check"""
        return self.syntax_valid and self.ast_valid and self.imports_safe
    
    @property
    def quality_score(self) -> float:
        """Calculate overall quality score (0-100)"""
        if not self.syntax_valid:
            return 0.0
        
        score = 50.0  # Base score for valid syntax
        
        if self.ast_valid:
            score += 20.0
        
        if self.imports_safe:
            score += 20.0
        
        # Complexity bonus (lower is better)
        complexity_bonus = max(0, 10 - (self.complexity_score / 10))
        score += complexity_bonus
        
        return min(100.0, score)


class CodeValidator:
    """Validates generated Python code for syntax, safety, and quality"""
    
    # Dangerous functions and modules that should be avoided
    DANGEROUS_IMPORTS = {
        'eval', 'exec', 'compile', '__import__',
        'pickle', 'shelve', 'marshal',
        'os.system', 'subprocess.call', 'subprocess.run',
        'input', 'raw_input'
    }
    
    # Dangerous patterns in code
    DANGEROUS_PATTERNS = [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\b__import__\s*\(',
        r'os\.system\s*\(',
        r'subprocess\.call\s*\(',
        r'subprocess\.run\s*\(',
        r'pickle\.loads?\s*\(',
        r'marshal\.loads?\s*\(',
    ]
    
    def __init__(self):
        self.dangerous_pattern_regex = [re.compile(p) for p in self.DANGEROUS_PATTERNS]
    
    def validate(self, code: str) -> ValidationResult:
        """
        Perform comprehensive validation of Python code
        
        Args:
            code: Python code string to validate
            
        Returns:
            ValidationResult with detailed validation information
        """
        errors = []
        warnings = []
        dangerous_imports = []
        
        # 1. Syntax validation
        syntax_valid = self._check_syntax(code, errors)
        
        # 2. AST validation
        ast_valid, ast_tree = self._parse_ast(code, errors)
        
        # 3. Import safety check
        if ast_tree:
            dangerous_imports = self._check_imports(ast_tree, warnings)
        
        # Also check for dangerous patterns in raw code
        pattern_dangers = self._check_dangerous_patterns(code, warnings)
        dangerous_imports.extend(pattern_dangers)
        
        imports_safe = len(dangerous_imports) == 0
        
        # 4. Complexity analysis
        complexity_score = self._calculate_complexity(ast_tree) if ast_tree else 100.0
        
        return ValidationResult(
            syntax_valid=syntax_valid,
            ast_valid=ast_valid,
            imports_safe=imports_safe,
            complexity_score=complexity_score,
            errors=errors,
            warnings=warnings,
            dangerous_imports=list(set(dangerous_imports))
        )
    
    def _check_syntax(self, code: str, errors: List[str]) -> bool:
        """Check if code has valid Python syntax"""
        try:
            compile(code, '<string>', 'exec')
            return True
        except SyntaxError as e:
            errors.append(f"Syntax error at line {e.lineno}: {e.msg}")
            return False
        except Exception as e:
            errors.append(f"Compilation error: {str(e)}")
            return False
    
    def _parse_ast(self, code: str, errors: List[str]) -> tuple[bool, Optional[ast.AST]]:
        """Parse code into AST"""
        try:
            tree = ast.parse(code)
            return True, tree
        except SyntaxError as e:
            errors.append(f"AST parse error at line {e.lineno}: {e.msg}")
            return False, None
        except Exception as e:
            errors.append(f"AST error: {str(e)}")
            return False, None
    
    def _check_imports(self, tree: ast.AST, warnings: List[str]) -> List[str]:
        """Check for dangerous imports in AST"""
        dangerous = []
        
        for node in ast.walk(tree):
            # Check import statements
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.DANGEROUS_IMPORTS:
                        dangerous.append(alias.name)
                        warnings.append(f"Dangerous import detected: {alias.name}")
            
            # Check from...import statements
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    for alias in node.names:
                        full_name = f"{node.module}.{alias.name}"
                        if full_name in self.DANGEROUS_IMPORTS or alias.name in self.DANGEROUS_IMPORTS:
                            dangerous.append(full_name)
                            warnings.append(f"Dangerous import detected: {full_name}")
            
            # Check for direct calls to dangerous functions
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in self.DANGEROUS_IMPORTS:
                        dangerous.append(node.func.id)
                        warnings.append(f"Dangerous function call: {node.func.id}()")
        
        return dangerous
    
    def _check_dangerous_patterns(self, code: str, warnings: List[str]) -> List[str]:
        """Check for dangerous patterns using regex"""
        dangerous = []
        
        for pattern in self.dangerous_pattern_regex:
            matches = pattern.findall(code)
            if matches:
                pattern_str = pattern.pattern.replace(r'\b', '').replace(r'\s*\(', '')
                dangerous.append(pattern_str)
                warnings.append(f"Dangerous pattern detected: {pattern_str}")
        
        return dangerous
    
    def _calculate_complexity(self, tree: Optional[ast.AST]) -> float:
        """
        Calculate cyclomatic complexity of code
        
        Simplified complexity calculation based on:
        - Number of decision points (if, for, while, etc.)
        - Nesting depth
        - Number of functions/classes
        """
        if not tree:
            return 100.0  # Maximum complexity for invalid code
        
        complexity = 1  # Base complexity
        max_depth = 0
        current_depth = 0
        
        class ComplexityVisitor(ast.NodeVisitor):
            def __init__(self):
                self.complexity = 1
                self.depth = 0
                self.max_depth = 0
            
            def visit_If(self, node):
                self.complexity += 1
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1
            
            def visit_For(self, node):
                self.complexity += 1
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1
            
            def visit_While(self, node):
                self.complexity += 1
                self.depth += 1
                self.max_depth = max(self.max_depth, self.depth)
                self.generic_visit(node)
                self.depth -= 1
            
            def visit_ExceptHandler(self, node):
                self.complexity += 1
                self.generic_visit(node)
            
            def visit_With(self, node):
                self.complexity += 1
                self.generic_visit(node)
            
            def visit_BoolOp(self, node):
                self.complexity += len(node.values) - 1
                self.generic_visit(node)
        
        visitor = ComplexityVisitor()
        visitor.visit(tree)
        
        # Combine complexity and depth for final score
        # Lower is better
        complexity_score = visitor.complexity + (visitor.max_depth * 2)
        
        return float(complexity_score)


def validate_code(code: str) -> ValidationResult:
    """Convenience function to validate code"""
    validator = CodeValidator()
    return validator.validate(code)


if __name__ == "__main__":
    # Test the validator
    test_code = """
import os
import json

def process_data(user_input):
    # This is unsafe!
    result = eval(user_input)
    return result

def safe_function(data):
    if data:
        for item in data:
            if item > 0:
                print(item)
    return True
"""
    
    result = validate_code(test_code)
    print(f"Syntax Valid: {result.syntax_valid}")
    print(f"AST Valid: {result.ast_valid}")
    print(f"Imports Safe: {result.imports_safe}")
    print(f"Complexity Score: {result.complexity_score}")
    print(f"Quality Score: {result.quality_score}")
    print(f"Errors: {result.errors}")
    print(f"Warnings: {result.warnings}")
    print(f"Dangerous Imports: {result.dangerous_imports}")
