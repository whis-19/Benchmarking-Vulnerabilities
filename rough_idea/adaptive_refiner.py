"""
Adaptive Refiner Module for HMSCG Pipeline

Intelligent code refinement system that:
- Only refines when security score is below threshold
- Uses targeted critique based on detected issues
- Implements convergence detection
- Supports multi-iteration refinement with quality tracking
"""

from typing import List, Optional, Tuple
from dataclasses import dataclass
import time

from code_validator import CodeValidator, ValidationResult
from security_analyzer import SecurityAnalyzer, SecurityReport
from prompts import PromptTemplates


@dataclass
class RefinementResult:
    """Results from code refinement process"""
    final_code: str
    iterations: int
    initial_score: float
    final_score: float
    improved: bool
    refinement_history: List[dict]


class AdaptiveRefiner:
    """Intelligently refines code based on security and quality metrics"""
    
    def __init__(self, 
                 security_threshold: float = 80.0,
                 max_iterations: int = 3,
                 min_improvement: float = 5.0):
        """
        Initialize the adaptive refiner
        
        Args:
            security_threshold: Minimum security score to accept (0-100)
            max_iterations: Maximum refinement iterations
            min_improvement: Minimum score improvement to continue (points)
        """
        self.security_threshold = security_threshold
        self.max_iterations = max_iterations
        self.min_improvement = min_improvement
        self.validator = CodeValidator()
        self.security_analyzer = SecurityAnalyzer()
    
    def should_refine(self, security_report: SecurityReport, validation: ValidationResult) -> bool:
        """
        Determine if code should be refined
        
        Args:
            security_report: Security analysis results
            validation: Code validation results
            
        Returns:
            True if refinement is needed
        """
        # Always refine if there are high severity issues
        if security_report.high_severity_count > 0:
            return True
        
        # Refine if security score is below threshold
        if security_report.score < self.security_threshold:
            return True
        
        # Refine if code has validation issues
        if not validation.is_valid:
            return True
        
        return False
    
    def refine(self,
               code: str,
               task: str,
               guidelines: List[str],
               code_generator,
               task_id: str = "unknown") -> RefinementResult:
        """
        Adaptively refine code until it meets quality standards
        
        Args:
            code: Initial code to refine
            task: Original task description
            guidelines: Security guidelines from RAG
            code_generator: Code generator instance for improvements
            task_id: Task identifier for logging
            
        Returns:
            RefinementResult with final code and metrics
        """
        # Initial analysis
        initial_validation = self.validator.validate(code)
        initial_security = self.security_analyzer.analyze(code, f"{task_id}_initial")
        initial_score = self._calculate_combined_score(initial_security, initial_validation)
        
        # Check if refinement is needed
        if not self.should_refine(initial_security, initial_validation):
            return RefinementResult(
                final_code=code,
                iterations=0,
                initial_score=initial_score,
                final_score=initial_score,
                improved=False,
                refinement_history=[]
            )
        
        # Refinement loop
        current_code = code
        current_score = initial_score
        history = []
        
        for iteration in range(self.max_iterations):
            print(f"  Refinement iteration {iteration + 1}/{self.max_iterations} for {task_id}")
            
            # Re-analyze current code
            validation = self.validator.validate(current_code)
            security = self.security_analyzer.analyze(current_code, f"{task_id}_iter{iteration}")
            
            # Generate targeted critique
            critique = self._generate_targeted_critique(
                current_code, 
                security, 
                validation,
                task
            )
            
            # Generate improvement prompt
            improvement_prompt = PromptTemplates.improvement_prompt(
                current_code,
                critique,
                task,
                guidelines
            )
            
            # Get improved code
            try:
                improved_response = code_generator.generate_response(
                    improvement_prompt,
                    f"{task_id}_refine{iteration}"
                )
                improved_code = PromptTemplates.extract_code_from_response(improved_response)
            except Exception as e:
                print(f"  Warning: Refinement failed at iteration {iteration + 1}: {e}")
                break
            
            # Validate improved code
            new_validation = self.validator.validate(improved_code)
            new_security = self.security_analyzer.analyze(improved_code, f"{task_id}_improved{iteration}")
            new_score = self._calculate_combined_score(new_security, new_validation)
            
            # Record history
            history.append({
                'iteration': iteration + 1,
                'score': new_score,
                'security_score': new_security.score,
                'quality_score': new_validation.quality_score,
                'issues_count': new_security.total_issues
            })
            
            # Check for improvement
            improvement = new_score - current_score
            
            if improvement < self.min_improvement:
                print(f"  No significant improvement ({improvement:.2f} points), stopping refinement")
                break
            
            # Update current code and score
            current_code = improved_code
            current_score = new_score
            
            print(f"  Improved score: {current_score:.2f} (+{improvement:.2f})")
            
            # Check if we've reached the threshold
            if new_security.score >= self.security_threshold and new_validation.is_valid:
                print(f"  Reached security threshold, refinement complete")
                break
        
        final_score = current_score
        
        return RefinementResult(
            final_code=current_code,
            iterations=len(history),
            initial_score=initial_score,
            final_score=final_score,
            improved=final_score > initial_score,
            refinement_history=history
        )
    
    def _calculate_combined_score(self, 
                                  security: SecurityReport, 
                                  validation: ValidationResult) -> float:
        """
        Calculate combined quality score
        
        Weights: 70% security, 30% code quality
        """
        if not validation.syntax_valid:
            return 0.0
        
        return 0.7 * security.score + 0.3 * validation.quality_score
    
    def _generate_targeted_critique(self,
                                    code: str,
                                    security: SecurityReport,
                                    validation: ValidationResult,
                                    task: str) -> str:
        """
        Generate a targeted critique based on specific issues found
        
        Args:
            code: Code to critique
            security: Security analysis results
            validation: Validation results
            task: Original task
            
        Returns:
            Formatted critique string
        """
        critique_parts = []
        
        # Security issues
        if security.issues:
            critique_parts.append("SECURITY ISSUES DETECTED:\n")
            for i, issue in enumerate(security.issues[:5], 1):  # Top 5 issues
                critique_parts.append(
                    f"{i}. [{issue.severity}] Line {issue.line_number}: {issue.issue_text}"
                )
                if issue.cwe_id:
                    critique_parts.append(f"   CWE: {issue.cwe_id}")
            critique_parts.append("")
        
        # Validation issues
        if validation.errors:
            critique_parts.append("CODE VALIDATION ERRORS:\n")
            for error in validation.errors:
                critique_parts.append(f"- {error}")
            critique_parts.append("")
        
        if validation.warnings:
            critique_parts.append("CODE WARNINGS:\n")
            for warning in validation.warnings[:5]:
                critique_parts.append(f"- {warning}")
            critique_parts.append("")
        
        if validation.dangerous_imports:
            critique_parts.append("DANGEROUS IMPORTS/PATTERNS:\n")
            for danger in validation.dangerous_imports:
                critique_parts.append(f"- {danger}")
            critique_parts.append("")
        
        # Summary
        critique_parts.append(f"\nOVERALL ASSESSMENT:")
        critique_parts.append(f"- Security Score: {security.score:.2f}/100")
        critique_parts.append(f"- Code Quality Score: {validation.quality_score:.2f}/100")
        critique_parts.append(f"- High Severity Issues: {security.high_severity_count}")
        critique_parts.append(f"- Medium Severity Issues: {security.medium_severity_count}")
        
        return "\n".join(critique_parts)


if __name__ == "__main__":
    # Test the refiner
    from code_generation.gemini import CodeGenerator
    
    test_code = """
import os

def process_file(filename):
    # Unsafe command execution
    os.system(f"cat {filename}")
    
def query_user(username):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return query
"""
    
    task = "Create functions to process files and query users"
    guidelines = []
    
    refiner = AdaptiveRefiner(security_threshold=80, max_iterations=2)
    validator = CodeValidator()
    analyzer = SecurityAnalyzer()
    
    validation = validator.validate(test_code)
    security = analyzer.analyze(test_code)
    
    print(f"Initial Security Score: {security.score:.2f}")
    print(f"Initial Quality Score: {validation.quality_score:.2f}")
    print(f"Should Refine: {refiner.should_refine(security, validation)}")
    
    # Note: Actual refinement would require a code generator instance
    # result = refiner.refine(test_code, task, guidelines, generator, "test")
