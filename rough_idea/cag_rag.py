"""
CAG+RAG Pipeline: Context-Aware Generation with Retrieval-Augmented Generation

This pipeline combines:
1. Context Analysis: Analyzes task to identify security domains
2. RAG: Retrieves relevant security guidelines from vector database
3. Context Fusion: Merges context-specific and retrieved guidelines
4. Enhanced Generation: Generates code with comprehensive security context

Advantages over baseline RAG:
- Context analysis provides domain-specific focus
- Better retrieval through context-aware queries
- Fusion of multiple knowledge sources
- More targeted security guidelines
"""

from code_generation.gemini import CodeGenerator
from context_analyzer import ContextAnalyzer
from vector_db_gen import load_vector_db, create_vector_db, query_vector_db
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
    """
    Enhance RAG query with context information
    
    Args:
        task: Original task
        context: TaskContext from context analyzer
        
    Returns:
        Enhanced query string
    """
    # Start with original task
    enhanced_query = task
    
    # Add domain-specific keywords
    if context.security_domains:
        enhanced_query += " " + " ".join(context.security_domains)
    
    # Add CWE-specific keywords
    if context.potential_cwes:
        enhanced_query += " " + " ".join(context.potential_cwes)
    
    return enhanced_query


def merge_guidelines(context_guidelines: list, rag_guidelines: list) -> list:
    """
    Merge context-specific and RAG-retrieved guidelines
    
    Args:
        context_guidelines: Guidelines from context analysis
        rag_guidelines: Guidelines from RAG retrieval
        
    Returns:
        Merged and deduplicated guidelines
    """
    # Convert RAG documents to strings
    rag_strings = []
    for doc in rag_guidelines:
        if hasattr(doc, 'page_content'):
            rag_strings.append(doc.page_content)
        else:
            rag_strings.append(str(doc))
    
    # Combine and deduplicate
    all_guidelines = context_guidelines + rag_strings
    
    # Simple deduplication (could be more sophisticated)
    seen = set()
    unique_guidelines = []
    for guideline in all_guidelines:
        # Normalize for comparison
        normalized = guideline.lower().strip()
        if normalized not in seen:
            seen.add(normalized)
            unique_guidelines.append(guideline)
    
    return unique_guidelines


def cag_rag_generate(task: str, task_id: str, generator: CodeGenerator,
                     context_analyzer: ContextAnalyzer, vector_db):
    """
    Generate code using CAG+RAG approach
    
    Args:
        task: Coding task description
        task_id: Task identifier
        generator: Code generator instance
        context_analyzer: Context analyzer instance
        vector_db: Vector database for RAG
        
    Returns:
        Generated code
    """
    # Step 1: Analyze task context
    print(f"  Analyzing context for {task_id}...")
    context = context_analyzer.analyze_task(task)
    
    # Step 2: Enhanced RAG retrieval
    print(f"  Retrieving guidelines for {task_id}...")
    enhanced_query = enhance_query_with_context(task, context)
    rag_guidelines = query_vector_db(enhanced_query, vector_db, k=10)
    
    # Step 3: Merge guidelines
    merged_guidelines = merge_guidelines(context.suggested_guidelines, rag_guidelines)
    
    # Step 4: Create comprehensive prompt
    prompt = f"""Generate secure Python code for the following task:

TASK:
{task}

CONTEXT ANALYSIS:
- Complexity: {context.complexity}
- Security Domains: {', '.join(context.security_domains) if context.security_domains else 'General'}
- Potential Vulnerabilities: {', '.join(context.potential_cwes) if context.potential_cwes else 'None identified'}

"""
    
    if context.requires_validation:
        prompt += "⚠️ CRITICAL: This task requires robust input validation\n"
    if context.requires_sanitization:
        prompt += "⚠️ CRITICAL: This task requires input sanitization\n"
    if context.requires_encryption:
        prompt += "⚠️ CRITICAL: This task requires encryption/secure storage\n"
    
    prompt += "\nSECURITY GUIDELINES (Context + RAG Retrieved):\n\n"
    for i, guideline in enumerate(merged_guidelines[:15], 1):  # Top 15 guidelines
        prompt += f"{i}. {guideline}\n"
    
    prompt += "\nGenerate secure, production-ready Python code that follows all guidelines above.\n"
    
    # Step 5: Generate code
    print(f"  Generating code for {task_id}...")
    response = generator.generate_response(prompt, task_id)
    code = PromptTemplates.extract_code_from_response(response)
    
    # Step 6: Save prompt and logs
    os.makedirs("output/cag_rag_prompts", exist_ok=True)
    prompt_file = f"output/cag_rag_prompts/{task_id}.txt"
    with open(prompt_file, "w", encoding='utf-8') as f:
        f.write(f"TASK: {task}\n\n")
        f.write(f"CONTEXT:\n")
        f.write(f"- Complexity: {context.complexity}\n")
        f.write(f"- Domains: {context.security_domains}\n")
        f.write(f"- CWEs: {context.potential_cwes}\n")
        f.write(f"- Context Guidelines: {len(context.suggested_guidelines)}\n")
        f.write(f"- RAG Guidelines: {len(rag_guidelines)}\n")
        f.write(f"- Merged Guidelines: {len(merged_guidelines)}\n\n")
        f.write(f"FULL PROMPT:\n{prompt}\n\n")
        f.write(f"GENERATED CODE:\n{code}\n")
    
    return code


if __name__ == "__main__":
    print("=" * 80)
    print("CAG+RAG Pipeline: Context-Aware Generation with Retrieval")
    print("=" * 80)
    
    # Initialize components
    generator = CodeGenerator()
    context_analyzer = ContextAnalyzer()
    
    # Load or create vector database
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
    
    for task in tasks:
        task_id = f"cag_rag_{count}"
        print(f"\n[{count}/{len(tasks)}] Processing: {task[:60]}...")
        
        try:
            start_time = time.time()
            
            # Generate with CAG+RAG
            code = cag_rag_generate(task, task_id, generator, context_analyzer, vector_db)
            
            # Write code
            generator.write_code_to_file(task_id, code)
            
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
    print(f"Prompts directory: output/cag_rag_prompts/")
