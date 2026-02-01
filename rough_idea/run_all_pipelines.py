"""
Unified Pipeline Runner

Run all code generation pipelines with a single command:
- Baseline
- RAG
- RCI
- RCI+RAG
- CAG+RCI (NEW)
- CAG+RAG (NEW)
- RAG+CAG+RCI (NEW)

Usage:
    python run_all_pipelines.py --all                    # Run all pipelines
    python run_all_pipelines.py --pipeline rag_cag_rci   # Run specific pipeline
    python run_all_pipelines.py --compare                # Run all and compare
    python run_all_pipelines.py --limit 10               # Limit to 10 tasks
"""

import argparse
import json
import time
import os
from pathlib import Path
from typing import Dict, List, Tuple
import pandas as pd

# Import all pipeline modules
from code_generation.gemini import CodeGenerator
from context_analyzer import ContextAnalyzer
from vector_db_gen import load_vector_db, create_vector_db, query_vector_db
from adaptive_refiner import AdaptiveRefiner
from code_validator import CodeValidator
from security_analyzer import SecurityAnalyzer
from prompts import PromptTemplates
from config import config


class PipelineRunner:
    """Unified runner for all code generation pipelines"""
    
    PIPELINES = {
        'baseline': 'Baseline (Simple LLM)',
        'rag': 'RAG (Retrieval-Augmented Generation)',
        'rci': 'RCI (Refinement-Critique-Improve)',
        'rci_rag': 'RCI+RAG (Hybrid)',
        'cag_rci': 'CAG+RCI (Context-Aware + Refinement)',
        'cag_rag': 'CAG+RAG (Context-Aware + Retrieval)',
        'rag_cag_rci': 'RAG+CAG+RCI (Ultimate Hybrid)'
    }
    
    def __init__(self, dataset_file: str, limit: int = None):
        """
        Initialize the pipeline runner
        
        Args:
            dataset_file: Path to dataset file
            limit: Maximum number of tasks to process (None for all)
        """
        self.dataset_file = dataset_file
        self.dataset_name = Path(dataset_file).stem
        self.limit = limit
        self.tasks = self._load_tasks()
        self.results = {}
        
        # Initialize components
        self.generator = CodeGenerator()
        self.context_analyzer = ContextAnalyzer()
        self.refiner = AdaptiveRefiner(security_threshold=80, max_iterations=2)
        self.validator = CodeValidator()
        self.security_analyzer = SecurityAnalyzer(report_dir=Path("output"))
        
        # Load vector DB for RAG pipelines
        try:
            self.vector_db = load_vector_db()
            print("✓ Loaded existing vector database")
        except FileNotFoundError:
            print("Creating new vector database...")
            self.vector_db = create_vector_db()
            print("✓ Vector database created")
            
    def _setup_pipeline_dirs(self, pipeline_name: str) -> Tuple[Path, Path]:
        """Create and return (code_dir, report_dir) for a specific pipeline"""
        base_dir = Path("output") / self.dataset_name / pipeline_name
        code_dir = base_dir / "code"
        report_dir = base_dir / "reports"
        
        code_dir.mkdir(parents=True, exist_ok=True)
        report_dir.mkdir(parents=True, exist_ok=True)
        
        return code_dir, report_dir
    
    def _load_tasks(self) -> List[str]:
        """Load tasks from dataset file"""
        tasks = []
        
        if self.dataset_file.endswith('.jsonl'):
            with open(self.dataset_file, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    # Try both 'prompt' and 'Prompt' keys
                    task = data.get('prompt') or data.get('Prompt', '')
                    if task:
                        tasks.append(task.strip())
        else:
            # Plain text file
            with open(self.dataset_file, 'r') as f:
                tasks = [line.strip() for line in f if line.strip()]
        
        if self.limit:
            tasks = tasks[:self.limit]
        
        return tasks
    
    def run_baseline(self) -> Dict:
        """Run baseline pipeline"""
        print("\n" + "="*80)
        print("Running BASELINE Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'baseline',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('baseline')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"baseline_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                task_prompt = f"Generate secure Python code for the following: {task}"
                response = self.generator.generate_response(task_prompt, task_id)
                code = PromptTemplates.extract_code_from_response(response)
                self.generator.write_code_to_file(task_id, code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(code)
                security = self.security_analyzer.analyze(code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': task_prompt,
                    'generated_code': code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_rag(self) -> Dict:
        """Run RAG pipeline"""
        print("\n" + "="*80)
        print("Running RAG Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'rag',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('rag')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"rag_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Retrieve guidelines
                guidelines = query_vector_db(task, self.vector_db, k=10)
                
                # Create prompt
                task_prompt = f"Generate secure Python code for the following:\n{task}\n\n"
                task_prompt += "Here are some additional security guidelines to follow:\n"
                for j, doc in enumerate(guidelines, 1):
                    task_prompt += f"{j}. {doc.page_content}\n"
                
                response = self.generator.generate_response(task_prompt, task_id)
                code = PromptTemplates.extract_code_from_response(response)
                self.generator.write_code_to_file(task_id, code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(code)
                security = self.security_analyzer.analyze(code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': task_prompt,
                    'generated_code': code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results

    def run_rci(self, iterations: int = 2) -> Dict:
        """Run RCI pipeline"""
        print("\n" + "="*80)
        print("Running RCI Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'rci',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('rci')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"rci_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Initial generation
                initial_prompt = f"Generate secure Python code for the following: {task}"
                current_code = self.generator.generate_response(initial_prompt, task_id)
                
                # RCI iterations
                for iter_num in range(iterations):
                    critique_prompt = f"Review the following code and find security shortcomings: {current_code}"
                    critique = self.generator.generate_response(critique_prompt, f"{task_id}_critique{iter_num}")
                    
                    improve_prompt = f"Based on the critique: '{critique}', improve the following code: {current_code}"
                    current_code = self.generator.generate_response(improve_prompt, f"{task_id}_improve{iter_num}")
                
                code = PromptTemplates.extract_code_from_response(current_code)
                self.generator.write_code_to_file(task_id, code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(code)
                security = self.security_analyzer.analyze(code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': initial_prompt,
                    'generated_code': code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_rci_rag(self, iterations: int = 2) -> Dict:
        """Run RCI+RAG pipeline"""
        print("\n" + "="*80)
        print("Running RCI+RAG Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'rci_rag',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('rci_rag')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"rci_rag_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Retrieve guidelines
                guidelines = query_vector_db(task, self.vector_db, k=10)
                
                # Initial generation with RAG
                initial_prompt = f"Generate secure Python code for the following:\n{task}\n\n"
                initial_prompt += "Security guidelines:\n"
                for j, doc in enumerate(guidelines, 1):
                    initial_prompt += f"{j}. {doc.page_content}\n"
                
                current_code = self.generator.generate_response(initial_prompt, task_id)
                
                # RCI iterations
                for iter_num in range(iterations):
                    critique_prompt = f"Review the following code for security problems: {current_code}"
                    critique = self.generator.generate_response(critique_prompt, f"{task_id}_critique{iter_num}")
                    
                    improve_prompt = f"Based on the critique: '{critique}', improve the security of: {current_code}"
                    current_code = self.generator.generate_response(improve_prompt, f"{task_id}_improve{iter_num}")
                
                code = PromptTemplates.extract_code_from_response(current_code)
                self.generator.write_code_to_file(task_id, code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(code)
                security = self.security_analyzer.analyze(code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': initial_prompt,
                    'generated_code': code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_cag_rci(self, iterations: int = 2) -> Dict:
        """Run CAG+RCI pipeline"""
        print("\n" + "="*80)
        print("Running CAG+RCI Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'cag_rci',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('cag_rci')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"cag_rci_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Context analysis
                context = self.context_analyzer.analyze_task(task)
                
                # Context-aware initial generation
                initial_prompt = f"Generate secure Python code for: {task}\n\n"
                if context.suggested_guidelines:
                    initial_prompt += "Security Requirements:\n"
                    for j, guideline in enumerate(context.suggested_guidelines, 1):
                        initial_prompt += f"{j}. {guideline}\n"
                
                current_code = self.generator.generate_response(initial_prompt, task_id)
                current_code = PromptTemplates.extract_code_from_response(current_code)
                
                # RCI iterations
                for iter_num in range(iterations):
                    critique_prompt = f"Review for security issues in domains {context.security_domains}: {current_code}"
                    critique = self.generator.generate_response(critique_prompt, f"{task_id}_critique{iter_num}")
                    
                    improve_prompt = f"Improve based on critique: {critique}\nCode: {current_code}"
                    improved = self.generator.generate_response(improve_prompt, f"{task_id}_improve{iter_num}")
                    current_code = PromptTemplates.extract_code_from_response(improved)
                
                self.generator.write_code_to_file(task_id, current_code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(current_code)
                security = self.security_analyzer.analyze(current_code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': initial_prompt,
                    'generated_code': current_code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_cag_rag(self) -> Dict:
        """Run CAG+RAG pipeline"""
        print("\n" + "="*80)
        print("Running CAG+RAG Pipeline")
        print("="*80)
        
        results = {
            'pipeline': 'cag_rag',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('cag_rag')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"cag_rag_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Context analysis
                context = self.context_analyzer.analyze_task(task)
                
                # Enhanced RAG query
                enhanced_query = task
                if context.security_domains:
                    enhanced_query += " " + " ".join(context.security_domains)
                
                rag_guidelines = query_vector_db(enhanced_query, self.vector_db, k=10)
                
                # Merge guidelines
                all_guidelines = context.suggested_guidelines + [doc.page_content for doc in rag_guidelines]
                
                # Generate with merged guidelines
                prompt = f"Generate secure Python code for: {task}\n\n"
                prompt += f"Context: {', '.join(context.security_domains)}\n\n"
                prompt += "Security Guidelines:\n"
                for j, guideline in enumerate(all_guidelines[:15], 1):
                    prompt += f"{j}. {guideline}\n"
                
                response = self.generator.generate_response(prompt, task_id)
                code = PromptTemplates.extract_code_from_response(response)
                self.generator.write_code_to_file(task_id, code, output_dir=code_dir)
                
                # Validation and Security analysis
                validation = self.validator.validate(code)
                security = self.security_analyzer.analyze(code, f"{self.dataset_name}_{task_id}")
                
                total_security_score += security.score
                total_quality_score += validation.quality_score
                
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': prompt,
                    'generated_code': code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_rag_cag_rci(self, iterations: int = 2) -> Dict:
        """Run RAG+CAG+RCI pipeline (Ultimate Hybrid)"""
        print("\n" + "="*80)
        print("Running RAG+CAG+RCI Pipeline (Ultimate Hybrid)")
        print("="*80)
        
        results = {
            'pipeline': 'rag_cag_rci',
            'tasks_completed': 0,
            'tasks_failed': 0,
            'total_time': 0,
            'avg_time': 0,
            'avg_security_score': 0,
            'avg_quality_score': 0,
            'refinement_count': 0,
            'output_dir': config.code_output_dir,
            'detailed_results': []
        }
        
        start_total = time.time()
        total_security_score = 0
        total_quality_score = 0
        
        code_dir, _ = self._setup_pipeline_dirs('rag_cag_rci')
        
        for i, task in enumerate(self.tasks, 1):
            task_id = f"rag_cag_rci_{i}"
            print(f"[{i}/{len(self.tasks)}] Processing: {task[:60]}...")
            
            try:
                start = time.time()
                
                # Context analysis
                context = self.context_analyzer.analyze_task(task)
                
                # Enhanced RAG
                enhanced_query = task + " " + " ".join(context.security_domains)
                rag_guidelines = query_vector_db(enhanced_query, self.vector_db, k=10)
                
                # Merge guidelines
                all_guidelines = context.suggested_guidelines + [doc.page_content for doc in rag_guidelines]
                
                # Initial generation
                prompt = f"Generate secure Python code for: {task}\n\n"
                prompt += "Security Guidelines:\n"
                for j, guideline in enumerate(all_guidelines[:15], 1):
                    prompt += f"{j}. {guideline}\n"
                
                response = self.generator.generate_response(prompt, task_id)
                current_code = PromptTemplates.extract_code_from_response(response)
                
                # Initial Validation and Security analysis
                validation = self.validator.validate(current_code)
                security = self.security_analyzer.analyze(current_code, f"{self.dataset_name}_{task_id}")
                
                # Adaptive refinement
                if self.refiner.should_refine(security, validation):
                    for iter_num in range(iterations):
                        critique_issues = [f"[{issue.severity}] {issue.issue_text}" for issue in security.issues[:5]]
                        critique_prompt = f"Review for {context.security_domains}: {current_code}\nIssues: {critique_issues}"
                        critique = self.generator.generate_response(critique_prompt, f"{task_id}_critique{iter_num}")
                        
                        improve_prompt = f"Improve: {current_code}\nCritique: {critique}"
                        improved = self.generator.generate_response(improve_prompt, f"{task_id}_improve{iter_num}")
                        improved_code = PromptTemplates.extract_code_from_response(improved)
                        
                        new_security = self.security_analyzer.analyze(improved_code, f"{self.dataset_name}_{task_id}_iter{iter_num}")
                        if new_security.score > security.score:
                            current_code = improved_code
                            security = new_security
                            validation = self.validator.validate(current_code) # Re-validate
                            results['refinement_count'] += 1
                        else:
                            break
                
                self.generator.write_code_to_file(task_id, current_code, output_dir=code_dir)
                total_security_score += security.score
                total_quality_score += validation.quality_score
                elapsed = time.time() - start
                
                results['detailed_results'].append({
                    'task_id': task_id,
                    'task': task,
                    'prompt': prompt,
                    'generated_code': current_code,
                    'security_score': security.score,
                    'quality_score': validation.quality_score,
                    'syntax_valid': validation.syntax_valid,
                    'vulnerabilities': "; ".join([f"{i.severity}: {i.issue_text}" for i in security.issues]),
                    'raw_issues': [vars(i) for i in security.issues],
                    'time_taken': elapsed
                })
                
                results['tasks_completed'] += 1
                print(f"  ✓ Completed in {elapsed:.2f}s (Security: {security.score:.1f}, Quality: {validation.quality_score:.1f})")
            except Exception as e:
                results['tasks_failed'] += 1
                print(f"  ✗ Error: {str(e)}")
        
        results['total_time'] = time.time() - start_total
        if results['tasks_completed'] > 0:
            results['avg_time'] = results['total_time'] / results['tasks_completed']
            results['avg_security_score'] = total_security_score / results['tasks_completed']
            results['avg_quality_score'] = total_quality_score / results['tasks_completed']
        
        return results
    
    def run_pipeline(self, pipeline_name: str) -> Dict:
        """Run a specific pipeline by name"""
        pipeline_methods = {
            'baseline': self.run_baseline,
            'rag': self.run_rag,
            'rci': self.run_rci,
            'rci_rag': self.run_rci_rag,
            'cag_rci': self.run_cag_rci,
            'cag_rag': self.run_cag_rag,
            'rag_cag_rci': self.run_rag_cag_rci
        }
        
        if pipeline_name not in pipeline_methods:
            raise ValueError(f"Unknown pipeline: {pipeline_name}")
        
        return pipeline_methods[pipeline_name]()
    
    def run_all(self) -> Dict[str, Dict]:
        """Run all pipelines and return results"""
        all_results = {}
        
        for pipeline_name in self.PIPELINES.keys():
            results = self.run_pipeline(pipeline_name)
            all_results[pipeline_name] = results
            self.results = all_results
        
        return all_results
    
    def generate_comparison_report(self, results: Dict[str, Dict]) -> str:
        """Generate a comparison report of all pipeline results"""
        report = "\n" + "="*80 + "\n"
        report += "PIPELINE COMPARISON REPORT\n"
        report += "="*80 + "\n\n"
        
        # Create comparison table
        data = []
        for pipeline_name, result in results.items():
            data.append({
                'Pipeline': self.PIPELINES[pipeline_name],
                'Completed': result['tasks_completed'],
                'Failed': result['tasks_failed'],
                'Security Score': f"{result.get('avg_security_score', 0):.1f}",
                'Quality Score': f"{result.get('avg_quality_score', 0):.1f}",
                'Total Time (s)': f"{result['total_time']:.2f}"
            })
        
        df = pd.DataFrame(data)
        report += df.to_string(index=False)
        report += "\n\n"
        
        # Summary
        report += "SUMMARY:\n"
        report += f"- Total tasks: {len(self.tasks)}\n"
        report += f"- Dataset: {self.dataset_file}\n"
        report += f"- Pipelines run: {len(results)}\n"
        
        return report
    
    def save_results(self, results: Dict[str, Dict], output_file: str = "pipeline_results.json"):
        """Save results to JSON file"""
        output_path = Path("output") / output_file
        output_path.parent.mkdir(exist_ok=True)
        
        with open(output_path, 'w') as f:
            # Create a serializable copy (detailed_results might be large)
            serializable_results = {}
            for k, v in results.items():
                serializable_results[k] = {ik: iv for ik, iv in v.items() if ik != 'detailed_results'}
            
            json.dump(serializable_results, f, indent=2)
        
        print(f"\n✓ Results summary saved to: {output_path}")

    def save_to_excel(self, results: Dict[str, Dict], filename: str):
        """Save detailed results to Excel file with multiple sheets"""
        output_path = Path("output") / filename
        output_path.parent.mkdir(exist_ok=True)
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            # 1. Comparison Sheet
            comparison_data = []
            for name, res in results.items():
                comparison_data.append({
                    'Pipeline': self.PIPELINES.get(name, name),
                    'Completed': res['tasks_completed'],
                    'Failed': res['tasks_failed'],
                    'Avg Security Score': round(res.get('avg_security_score', 0), 2),
                    'Avg Quality Score': round(res.get('avg_quality_score', 0), 2),
                    'Total Time (sec)': round(res['total_time'], 2),
                    'Avg Time per Task': round(res['avg_time'], 2)
                })
            df_comp = pd.DataFrame(comparison_data)
            df_comp.to_excel(writer, sheet_name='Comparison', index=False)
            
            # 2. Detailed Sheets for each pipeline
            for pipeline_name, res in results.items():
                if 'detailed_results' in res:
                    sheet_name = pipeline_name[:31]  # Excel sheet name limit
                    df_detailed = pd.DataFrame(res['detailed_results'])
                    # Reorder columns for better readability
                    cols = ['task_id', 'security_score', 'quality_score', 'syntax_valid', 'time_taken', 'vulnerabilities', 'task', 'generated_code']
                    existing_cols = [c for c in cols if c in df_detailed.columns]
                    other_cols = [c for c in df_detailed.columns if c not in cols]
                    df_detailed = df_detailed[existing_cols + other_cols]
                    df_detailed.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"✓ Detailed Excel report saved to: {output_path}")

    def save_security_reports(self, results: Dict[str, Dict], dataset_name: str):
        """Save detailed security findings to consolidated JSON files"""
        security_report = []
        bandit_report = []
        semgrep_report = []
        
        for pipeline_name, res in results.items():
            if 'detailed_results' in res:
                for task_res in res['detailed_results']:
                    # Consolidated report entries
                    report_entry = {
                        'pipeline': pipeline_name,
                        'task_id': task_res.get('task_id'),
                        'security_score': task_res.get('security_score'),
                        'vulnerabilities': task_res.get('vulnerabilities', '').split('; ')
                    }
                    security_report.append(report_entry)
                    
                    # Split by tool if raw_issues available
                    if 'raw_issues' in task_res:
                        for issue in task_res['raw_issues']:
                            tool = issue.get('tool', 'Unknown')
                            issue_with_meta = {
                                'dataset': dataset_name,
                                'pipeline': pipeline_name,
                                'task_id': task_res.get('task_id'),
                                **issue
                            }
                            if tool == 'Bandit':
                                bandit_report.append(issue_with_meta)
                            elif tool == 'Semgrep':
                                semgrep_report.append(issue_with_meta)
        
        # Save comprehensive report
        output_path = Path("output") / f"security_analysis_{dataset_name}.json"
        with open(output_path, 'w') as f:
            json.dump(security_report, f, indent=2)
        print(f"✓ Comprehensive security report saved to: {output_path}")
        
        # Save Bandit specific report
        bandit_path = Path("output") / "bandit" / f"compiled_bandit_{dataset_name}.json"
        bandit_path.parent.mkdir(parents=True, exist_ok=True)
        with open(bandit_path, 'w') as f:
            json.dump(bandit_report, f, indent=2)
        print(f"✓ Consolidated Bandit report saved to: {bandit_path}")
        
        # Save Semgrep specific report
        semgrep_path = Path("output") / "semgrep" / f"compiled_semgrep_{dataset_name}.json"
        semgrep_path.parent.mkdir(parents=True, exist_ok=True)
        with open(semgrep_path, 'w') as f:
            json.dump(semgrep_report, f, indent=2)
        print(f"✓ Consolidated Semgrep report saved to: {semgrep_path}")


def main():
    parser = argparse.ArgumentParser(description='Run code generation pipelines')
    parser.add_argument('--pipeline', type=str, choices=list(PipelineRunner.PIPELINES.keys()),
                       help='Specific pipeline to run')
    parser.add_argument('--all', action='store_true',
                       help='Run all pipelines')
    parser.add_argument('--compare', action='store_true',
                       help='Run all pipelines and generate comparison report')
    parser.add_argument('--limit', type=int, default=5,
                       help='Limit number of tasks to process (default: 5)')
    parser.add_argument('--dataset', type=str, default=None,
                       help='Path to dataset file (runs all default if not specified)')
    parser.add_argument('--all-datasets', action='store_true',
                       help='Explicitly run all 3 main datasets')
    
    args = parser.parse_args()
    
    # Define default datasets
    default_datasets = [
        "dataset/LLMSecEval.txt",
        "dataset/SALLM.jsonl",
        "dataset/SecurityEval.jsonl"
    ]
    
    datasets_to_run = []
    if args.dataset:
        datasets_to_run = [args.dataset]
    elif args.all_datasets or args.all:
        datasets_to_run = default_datasets
    else:
        datasets_to_run = [config.prompt_dataset_file]

    for dataset_path in datasets_to_run:
        dataset_name = Path(dataset_path).stem
        print("\n" + "#"*80)
        print(f"PROCESSING DATASET: {dataset_name}")
        print("#"*80)
        
        # Initialize runner
        runner = PipelineRunner(dataset_path, args.limit)
        
        print(f"Tasks to process: {len(runner.tasks)}")
        print("="*80)
        
        results = {}
        # Run pipelines
        if args.all or args.compare:
            results = runner.run_all()
            
            if args.compare:
                report = runner.generate_comparison_report(results)
                print(report)
                
                # Save report
                report_path = Path("output") / f"comparison_report_{dataset_name}.txt"
                with open(report_path, 'w') as f:
                    f.write(report)
                print(f"✓ Comparison report saved to: {report_path}")
            
            runner.save_results(results, output_file=f"pipeline_results_{dataset_name}.json")
            runner.save_to_excel(results, filename=f"detailed_results_{dataset_name}.xlsx")
            runner.save_security_reports(results, dataset_name)
            
        elif args.pipeline:
            result = runner.run_pipeline(args.pipeline)
            results = {args.pipeline: result}
            print(f"\n{'='*80}")
            print(f"Pipeline: {PipelineRunner.PIPELINES[args.pipeline]}")
            print(f"Completed: {result['tasks_completed']}/{len(runner.tasks)}")
            print(f"Failed: {result['tasks_failed']}")
            print(f"Total time: {result['total_time']:.2f}s")
            if 'avg_security_score' in result:
                print(f"Avg security score: {result['avg_security_score']:.2f}")
            print(f"{'='*80}")
            
            runner.save_results(results, output_file=f"pipeline_results_{dataset_name}_{args.pipeline}.json")
            runner.save_to_excel(results, filename=f"detailed_results_{dataset_name}_{args.pipeline}.xlsx")
    
    if not args.all and not args.compare and not args.pipeline:
        parser.print_help()
        print("\nAvailable pipelines:")
        for name, desc in PipelineRunner.PIPELINES.items():
            print(f"  - {name}: {desc}")


if __name__ == "__main__":
    main()
