import os
import logging
from datasets import load_dataset
import time
import pandas as pd

# Suppress noisy warnings from Transformers/Hugging Face
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub.utils._validators").setLevel(logging.ERROR)
logging.getLogger("huggingface_hub.hub_layout").setLevel(logging.ERROR)

from src.curation_pipeline import SecGuideCurationPipeline
from src.retrieval_pipeline import RAGRetrievalPipeline
from src.experiment_wf import SecureCodeGenerationPipeline
from src.remediation_pipeline import SecurityAnalysisPipeline
from src.context_pipeline import CAGGenerationPipeline
from src.reporting import generate_pdf_report
from src.latex_generator import generate_latex_report

def main():
    results = []
    # Load Real Dataset 
    ds = load_dataset("XuanwuAI/SecEval", split='train')
    
    # Load HF_TOKEN if specified in environment or .env file
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                if line.startswith("HF_TOKEN="):
                    os.environ["HF_TOKEN"] = line.split("=")[1].strip()

    api_key = "AIzaSyCGDe2wdT4OV-aN4ugnNEpzyuF49PDAezI"
    
    # Pipeline 1: Curation
    curator = SecGuideCurationPipeline(ds)
    sec_guide = curator.run_pipeline()
    
    # Setup Engines
    gen_engine = SecureCodeGenerationPipeline(api_key)
    rag_engine = RAGRetrievalPipeline(sec_guide)
    cag_engine = CAGGenerationPipeline(gen_engine, sec_guide)
    analyzer = SecurityAnalysisPipeline()
    
    # Create organized output directories
    if not os.path.exists("output"):
        os.makedirs("output")
    for approach in ["Baseline", "RAG", "RCI", "CAG"]:
        approach_dir = os.path.join("output", approach)
        if not os.path.exists(approach_dir):
            os.makedirs(approach_dir)
    
    # Benchmarking a subset (e.g., first 5 tasks)
    for i in range(5):
        task = ds[i]['question']
        for approach in ["Baseline", "RAG", "RCI", "CAG"]:
            start = time.time()
            
            if approach == "RAG":
                guidelines = rag_engine.query(task)
                code = gen_engine.generate_code(f"Guidelines:\n{guidelines}\n\nTask: Generate secure Python code for: {task}")
            elif approach == "CAG":
                code = cag_engine.execute(task)
            elif approach == "RCI":
                code = gen_engine.rci_loop(task)
            else:
                code = gen_engine.generate_code(f"Generate secure Python code for: {task}")
                
            latency = time.time() - start
            filename = os.path.join("output", approach, f"output_task_{i}.py")
            with open(filename, "w") as f: f.write(code)
            
            # Pipeline 4: Security Analysis
            vuln_count, density = analyzer.analyze(filename)
            
            results.append({
                "Task": i, "Approach": approach, 
                "Latency": round(latency, 2), 
                "Weaknesses": vuln_count, "Density": density
            })

    # Save Results
    df = pd.DataFrame(results)
    df.to_csv("benchmark_results.csv")
    print(df)
    
    # Bulk Scan all pipelines
    analyzer.scan_entire_output()
    
    # Generate PDF Report
    generate_pdf_report()
    
    # Generate LaTeX Report
    generate_latex_report()

if __name__ == "__main__":
    main()