"""
RAG+CAG+RCI Pipeline: The Ultimate Hybrid Approach

This pipeline combines ALL three techniques:
1. RAG: Retrieves relevant security guidelines from vector database
2. CAG: Analyzes task context and identifies security domains
3. RCI: Iterative refinement through critique and improvement

Pipeline Flow:
Task → Context Analysis → Enhanced RAG Retrieval → Guideline Fusion →
Context-Aware Generation → Security Analysis → Adaptive Refinement → Final Code

This is the most comprehensive approach, combining:
- Knowledge retrieval (RAG)
- Context understanding (CAG)
- Iterative improvement (RCI)
- Automated security validation
"""

from code_generation.gemini import CodeGenerator
from context_analyzer import ContextAnalyzer
from vector_db_gen import load_vector_db, create_vector_db, query_vector_db
from adaptive_refiner import AdaptiveRefiner
from code_validator import CodeValidator
from security_analyzer import SecurityAnalyzer
from prompts import PromptTemplates
from config import config
import json
import time
import os


def read_Sallms_tasks(file_path: str):
    """Read tasks from SALLM dataset"""
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('prompt', '').strip())
    return security_eval_tasks


def read_SecurityEval_tasks(file_path: str):
    """Read tasks from SecurityEval dataset"""
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('Prompt', '').strip())
    return security_eval_tasks


def enhance_query_with_context(task: str, context) -> str:
    """Enhance RAG query with context information"""
    enhanced_query = task
    if context.security_domains:
        enhanced_query += " " + " ".join(context.security_domains)
    if context.potential_cwes:
        enhanced_query += " " + " ".join(context.potential_cwes)
    return enhanced_query


def merge_guidelines(context_guidelines: list, rag_guidelines: list) -> list:
    """Merge context-specific and RAG-retrieved guidelines"""
    rag_strings = []
    for doc in rag_guidelines:
        if hasattr(doc, 'page_content'):
            rag_strings.append(doc.page_content)
        else:
            rag_strings.append(str(doc))
    
    all_guidelines = context_guidelines + rag_strings
    
    # Deduplicate
    seen = set()
    unique_guidelines = []
    for guideline in all_guidelines:
        normalized = guideline.lower().strip()
        if normalized not in seen and len(normalized) > 10:
            seen.add(normalized)
            unique_guidelines.append(guideline)
    
    return unique_guidelines


def rag_cag_rci_generate(task: str, task_id: str, 
                         generator: CodeGenerator,
                         context_analyzer: ContextAnalyzer,
                         vector_db,
                         refiner: AdaptiveRefiner,
                         validator: CodeValidator,
                         security_analyzer: SecurityAnalyzer,
                         rci_iterations: int = 2):
    """
    Generate code using RAG+CAG+RCI approach
    
    Args:
        task: Coding task description
        task_id: Task identifier
        generator: Code generator instance
        context_analyzer: Context analyzer instance
        vector_db: Vector database for RAG
        refiner: Adaptive refiner instance
        validator: Code validator instance
        security_analyzer: Security analyzer instance
        rci_iterations: Number of RCI iterations
        
    Returns:
        Final generated code with metrics
    """
    log_file = f"output/rag_cag_rci_logs/{task_id}.txt"
    os.makedirs("output/rag_cag_rci_logs", exist_ok=True)
    
    with open(log_file, "w", encoding='utf-8') as log:
        log.write(f"RAG+CAG+RCI Pipeline Log\n")
        log.write(f"{'='*80}\n\n")
        log.write(f"TASK: {task}\n\n")
        
        # STEP 1: Context Analysis (CAG)
        print(f"  [1/5] Analyzing context...")
        context = context_analyzer.analyze_task(task)
        
        log.write(f"STEP 1: CONTEXT ANALYSIS\n")
        log.write(f"- Complexity: {context.complexity}\n")
        log.write(f"- Security Domains: {context.security_domains}\n")
        log.write(f"- Potential CWEs: {context.potential_cwes}\n")
        log.write(f"- Requires Validation: {context.requires_validation}\n")
        log.write(f"- Requires Sanitization: {context.requires_sanitization}\n")
        log.write(f"- Requires Encryption: {context.requires_encryption}\n")
        log.write(f"- Context Guidelines: {len(context.suggested_guidelines)}\n\n")
        
        # STEP 2: Enhanced RAG Retrieval
        print(f"  [2/5] Retrieving guidelines (RAG)...")
        enhanced_query = enhance_query_with_context(task, context)
        rag_guidelines = query_vector_db(enhanced_query, vector_db, k=10)
        
        log.write(f"STEP 2: RAG RETRIEVAL\n")
        log.write(f"- Enhanced Query: {enhanced_query}\n")
        log.write(f"- Retrieved Guidelines: {len(rag_guidelines)}\n\n")
        
        # STEP 3: Guideline Fusion
        print(f"  [3/5] Merging guidelines...")
        merged_guidelines = merge_guidelines(context.suggested_guidelines, rag_guidelines)
        
        log.write(f"STEP 3: GUIDELINE FUSION\n")
        log.write(f"- Total Merged Guidelines: {len(merged_guidelines)}\n\n")
        
        # STEP 4: Context-Aware Generation
        print(f"  [4/5] Generating initial code...")
        
        # Build comprehensive prompt
        prompt = f"""Generate secure Python code for the following task:

TASK:
{task}

CONTEXT ANALYSIS:
- Complexity: {context.complexity}
- Security Domains: {', '.join(context.security_domains) if context.security_domains else 'General'}
- Potential Vulnerabilities: {', '.join(context.potential_cwes) if context.potential_cwes else 'None identified'}

"""
        
        if context.requires_validation:
            prompt += "⚠️ CRITICAL: Implement robust input validation\n"
        if context.requires_sanitization:
            prompt += "⚠️ CRITICAL: Sanitize all user inputs\n"
        if context.requires_encryption:
            prompt += "⚠️ CRITICAL: Use strong encryption for sensitive data\n"
        
        prompt += "\nSECURITY GUIDELINES (Context + RAG):\n\n"
        for i, guideline in enumerate(merged_guidelines[:15], 1):
            prompt += f"{i}. {guideline}\n"
        
        prompt += "\nGenerate secure, production-ready Python code following all guidelines.\n"
        
        # Generate initial code
        initial_response = generator.generate_response(prompt, task_id)
        current_code = PromptTemplates.extract_code_from_response(initial_response)
        
        log.write(f"STEP 4: INITIAL GENERATION\n")
        log.write(f"Prompt length: {len(prompt)} chars\n")
        log.write(f"Generated code length: {len(current_code)} chars\n\n")
        log.write(f"INITIAL CODE:\n{current_code}\n\n")
        
        # Validate initial code
        initial_validation = validator.validate(current_code)
        initial_security = security_analyzer.analyze(current_code, f"{task_id}_initial")
        
        log.write(f"INITIAL VALIDATION:\n")
        log.write(f"- Syntax Valid: {initial_validation.syntax_valid}\n")
        log.write(f"- Security Score: {initial_security.score:.2f}\n")
        log.write(f"- High Severity Issues: {initial_security.high_severity_count}\n")
        log.write(f"- Medium Severity Issues: {initial_security.medium_severity_count}\n\n")
        
        # STEP 5: Adaptive RCI Refinement
        print(f"  [5/5] Refining code (RCI)...")
        
        # Check if refinement is needed
        if not refiner.should_refine(initial_security, initial_validation):
            log.write(f"STEP 5: REFINEMENT\n")
            log.write(f"No refinement needed - code meets quality threshold\n")
            return current_code, {
                'iterations': 0,
                'initial_score': initial_security.score,
                'final_score': initial_security.score,
                'improved': False
            }
        
        log.write(f"STEP 5: RCI REFINEMENT\n")
        log.write(f"Refinement needed - starting {rci_iterations} iterations\n\n")
        
        # RCI iterations
        for iteration in range(rci_iterations):
            print(f"    Iteration {iteration + 1}/{rci_iterations}...")
            
            # Analyze current code
            validation = validator.validate(current_code)
            security = security_analyzer.analyze(current_code, f"{task_id}_iter{iteration}")
            
            # Generate targeted critique
            critique_issues = [f"[{issue.severity}] Line {issue.line_number}: {issue.issue_text}" 
                             for issue in security.issues[:5]]
            
            critique_prompt = f"""Review this code for security issues, focusing on:
- Detected domains: {', '.join(context.security_domains)}
- Potential vulnerabilities: {', '.join(context.potential_cwes)}

CODE:
{current_code}

DETECTED ISSUES:
{chr(10).join(critique_issues)}

Provide specific, actionable security critique."""
            
            critique = generator.generate_response(critique_prompt, f"{task_id}_critique{iteration}")
            
            # Generate improvement
            improve_prompt = f"""Improve this code based on the security critique.

TASK: {task}

SECURITY GUIDELINES:
{chr(10).join(f'- {g}' for g in merged_guidelines[:10])}

CURRENT CODE:
{current_code}

CRITIQUE:
{critique}

Provide the complete improved code."""
            
            improved_response = generator.generate_response(improve_prompt, f"{task_id}_improve{iteration}")
            improved_code = PromptTemplates.extract_code_from_response(improved_response)
            
            # Validate improvement
            new_validation = validator.validate(improved_code)
            new_security = security_analyzer.analyze(improved_code, f"{task_id}_improved{iteration}")
            
            log.write(f"ITERATION {iteration + 1}:\n")
            log.write(f"- Security Score: {security.score:.2f} → {new_security.score:.2f}\n")
            log.write(f"- High Severity: {security.high_severity_count} → {new_security.high_severity_count}\n")
            log.write(f"- Syntax Valid: {new_validation.syntax_valid}\n\n")
            
            # Check for improvement
            if new_security.score > security.score:
                current_code = improved_code
                print(f"    Improved: {security.score:.2f} → {new_security.score:.2f}")
            else:
                print(f"    No improvement, keeping previous version")
                break
            
            # Check if threshold reached
            if new_security.score >= refiner.security_threshold and new_validation.is_valid:
                print(f"    Threshold reached, stopping refinement")
                break
        
        # Final analysis
        final_validation = validator.validate(current_code)
        final_security = security_analyzer.analyze(current_code, f"{task_id}_final")
        
        log.write(f"\nFINAL RESULTS:\n")
        log.write(f"- Security Score: {final_security.score:.2f}\n")
        log.write(f"- Quality Score: {final_validation.quality_score:.2f}\n")
        log.write(f"- Syntax Valid: {final_validation.syntax_valid}\n")
        log.write(f"- Total Issues: {final_security.total_issues}\n")
        log.write(f"- High Severity: {final_security.high_severity_count}\n\n")
        log.write(f"FINAL CODE:\n{current_code}\n")
        
        return current_code, {
            'iterations': iteration + 1 if 'iteration' in locals() else 0,
            'initial_score': initial_security.score,
            'final_score': final_security.score,
            'improved': final_security.score > initial_security.score
        }


if __name__ == "__main__":
    print("=" * 80)
    print("RAG+CAG+RCI Pipeline: Ultimate Hybrid Secure Code Generation")
    print("=" * 80)
    
    # Initialize all components
    generator = CodeGenerator()
    context_analyzer = ContextAnalyzer()
    refiner = AdaptiveRefiner(security_threshold=80, max_iterations=3)
    validator = CodeValidator()
    security_analyzer = SecurityAnalyzer()
    
    # Load vector database
    try:
        vector_db = load_vector_db()
        print("✓ Loaded existing vector database")
    except FileNotFoundError:
        print("Creating new vector database...")
        vector_db = create_vector_db()
        print("✓ Vector database created")
    
    # Read tasks
    tasks = read_Sallms_tasks(config.prompt_dataset_file)
    
    # Process each task
    count = 1
    time_in_seconds = 0
    total_iterations = 0
    total_improvement = 0
    
    for task in tasks:
        task_id = f"rag_cag_rci_{count}"
        print(f"\n[{count}/{len(tasks)}] Processing: {task[:60]}...")
        
        try:
            start_time = time.time()
            
            # Generate with RAG+CAG+RCI
            code, metrics = rag_cag_rci_generate(
                task, task_id, generator, context_analyzer, vector_db,
                refiner, validator, security_analyzer, rci_iterations=2
            )
            
            # Write code
            generator.write_code_to_file(task_id, code)
            
            end_time = time.time()
            elapsed = end_time - start_time
            time_in_seconds += elapsed
            
            total_iterations += metrics['iterations']
            if metrics['improved']:
                total_improvement += (metrics['final_score'] - metrics['initial_score'])
            
            print(f"  ✓ Completed in {elapsed:.2f}s")
            print(f"    Score: {metrics['initial_score']:.1f} → {metrics['final_score']:.1f}")
            print(f"    Iterations: {metrics['iterations']}")
            
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
            generator.write_code_to_file(task_id, f"# Error: {str(e)}")
        
        count += 1
    
    print(f"\n{'='*80}")
    print(f"PIPELINE STATISTICS:")
    print(f"- Total tasks: {len(tasks)}")
    print(f"- Total time: {time_in_seconds:.2f}s")
    print(f"- Average time per task: {time_in_seconds / len(tasks):.2f}s")
    print(f"- Average refinement iterations: {total_iterations / len(tasks):.2f}")
    print(f"- Average score improvement: {total_improvement / len(tasks):.2f} points")
    print(f"\nOutput directory: {config.code_output_dir}")
    print(f"Logs directory: output/rag_cag_rci_logs/")
