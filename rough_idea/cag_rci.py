"""
CAG+RCI Pipeline: Context-Aware Generation with Refinement-Critique-Improve

This pipeline combines:
1. Context Analysis: Analyzes task to identify security domains and requirements
2. Context-Aware Generation: Generates code with context-specific prompts
3. RCI: Iterative refinement through critique and improvement

Advantages over baseline RCI:
- Context-aware prompts with domain-specific guidelines
- Better initial code quality through context understanding
- Targeted refinement based on detected security domains
"""

from code_generation.gemini import CodeGenerator
from context_analyzer import ContextAnalyzer
from adaptive_refiner import AdaptiveRefiner
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


def cag_rci_generate(task: str, task_id: str, generator: CodeGenerator, 
                     context_analyzer: ContextAnalyzer, refiner: AdaptiveRefiner,
                     iterations: int = 2):
    """
    Generate code using CAG+RCI approach
    
    Args:
        task: Coding task description
        task_id: Task identifier
        generator: Code generator instance
        context_analyzer: Context analyzer instance
        refiner: Adaptive refiner instance
        iterations: Number of RCI iterations
        
    Returns:
        Final generated code
    """
    # Step 1: Analyze task context
    print(f"  Analyzing context for {task_id}...")
    context = context_analyzer.analyze_task(task)
    
    # Step 2: Generate context-aware prompt
    base_prompt = f"Generate secure Python code for the following: {task}"
    
    # Add context-specific guidelines
    if context.suggested_guidelines:
        base_prompt += "\n\nContext-Specific Security Requirements:\n"
        for i, guideline in enumerate(context.suggested_guidelines, 1):
            base_prompt += f"{i}. {guideline}\n"
    
    # Add domain-specific warnings
    if context.security_domains:
        base_prompt += f"\n⚠️ Security Domains Detected: {', '.join(context.security_domains)}\n"
        base_prompt += f"⚠️ Potential Vulnerabilities: {', '.join(context.potential_cwes)}\n"
    
    if context.requires_validation:
        base_prompt += "\n🔒 CRITICAL: Implement robust input validation\n"
    if context.requires_sanitization:
        base_prompt += "🔒 CRITICAL: Sanitize all user inputs\n"
    if context.requires_encryption:
        base_prompt += "🔒 CRITICAL: Use strong encryption for sensitive data\n"
    
    # Step 3: Initial generation with context
    print(f"  Generating initial code for {task_id}...")
    initial_response = generator.generate_response(base_prompt, task_id)
    current_code = PromptTemplates.extract_code_from_response(initial_response)
    
    # Save initial generation
    log_file = f"output/cag_rci_logs/{task_id}.txt"
    os.makedirs("output/cag_rci_logs", exist_ok=True)
    with open(log_file, "w", encoding='utf-8') as f:
        f.write(f"TASK: {task}\n\n")
        f.write(f"CONTEXT ANALYSIS:\n")
        f.write(f"- Complexity: {context.complexity}\n")
        f.write(f"- Domains: {context.security_domains}\n")
        f.write(f"- CWEs: {context.potential_cwes}\n\n")
        f.write(f"INITIAL PROMPT:\n{base_prompt}\n\n")
        f.write(f"INITIAL CODE:\n{current_code}\n\n")
    
    # Step 4: RCI iterations
    for iteration in range(iterations):
        print(f"  RCI iteration {iteration + 1}/{iterations} for {task_id}...")
        
        # Critique with context awareness
        critique_prompt = f"""Review the following code for security issues, especially related to:
- Detected domains: {', '.join(context.security_domains)}
- Potential vulnerabilities: {', '.join(context.potential_cwes)}

CODE:
{current_code}

Provide specific security critique focusing on the detected domains."""
        
        critique = generator.generate_response(critique_prompt, f"{task_id}_critique{iteration}")
        
        # Improve based on critique
        improve_prompt = f"""Based on the security critique, improve the following code.

ORIGINAL TASK: {task}

CONTEXT REQUIREMENTS:
{chr(10).join(f'- {g}' for g in context.suggested_guidelines)}

CURRENT CODE:
{current_code}

CRITIQUE:
{critique}

Provide the complete improved code addressing all security issues."""
        
        improved_response = generator.generate_response(improve_prompt, f"{task_id}_improve{iteration}")
        current_code = PromptTemplates.extract_code_from_response(improved_response)
        
        # Log iteration
        with open(log_file, "a", encoding='utf-8') as f:
            f.write(f"\n{'='*80}\n")
            f.write(f"ITERATION {iteration + 1}\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"CRITIQUE:\n{critique}\n\n")
            f.write(f"IMPROVED CODE:\n{current_code}\n\n")
    
    return current_code


if __name__ == "__main__":
    print("=" * 80)
    print("CAG+RCI Pipeline: Context-Aware Generation with Refinement")
    print("=" * 80)
    
    # Initialize components
    generator = CodeGenerator()
    context_analyzer = ContextAnalyzer()
    refiner = AdaptiveRefiner(security_threshold=80, max_iterations=2)
    
    # Read tasks
    tasks = read_Sallms_tasks(config.prompt_dataset_file)
    
    # Configuration
    iterations = 2  # RCI iterations
    count = 1
    time_in_seconds = 0
    
    # Process each task
    for task in tasks:
        task_id = f"cag_rci_{count}"
        print(f"\n[{count}/{len(tasks)}] Processing: {task[:60]}...")
        
        try:
            start_time = time.time()
            
            # Generate with CAG+RCI
            final_code = cag_rci_generate(
                task, 
                task_id, 
                generator, 
                context_analyzer, 
                refiner,
                iterations
            )
            
            # Write final code
            generator.write_code_to_file(task_id, final_code)
            
            end_time = time.time()
            time_in_seconds += end_time - start_time
            
            print(f"  ✓ Completed in {end_time - start_time:.2f}s")
            
        except Exception as e:
            print(f"  ✗ Error: {str(e)}")
            generator.write_code_to_file(task_id, f"# Error: {str(e)}")
        
        count += 1
    
    print(f"\n{'='*80}")
    print(f"Total time: {time_in_seconds:.2f}s")
    print(f"Average time per task: {time_in_seconds / len(tasks):.2f}s")
    print(f"Output directory: {config.code_output_dir}")
    print(f"Logs directory: output/cag_rci_logs/")
