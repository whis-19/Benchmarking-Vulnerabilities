import subprocess
import json
import os

class SecurityAnalysisPipeline:
    def __init__(self, output_dir="output/"):
        self.output_dir = output_dir
        self.bandit_dir = "bandit_output"
        self.semgrep_dir = "sem_grep_output"
        
        for d in [self.bandit_dir, self.semgrep_dir]:
            if not os.path.exists(d):
                os.makedirs(d)

    def run_bandit(self, file_path):
        # Bandit detects CWE IDs and locations [cite: 196]
        cmd = ["bandit", "-r", file_path, "-f", "json", "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Save raw output
        parts = file_path.split(os.sep)
        approach = parts[-2] if len(parts) >= 2 else "default"
        save_dir = os.path.join(self.bandit_dir, approach)
        if not os.path.exists(save_dir): os.makedirs(save_dir)
        
        base_name = os.path.basename(file_path).replace(".py", ".json")
        with open(os.path.join(save_dir, base_name), "w") as f:
            f.write(result.stdout)

        try:
            return json.loads(result.stdout).get('results', [])
        except:
            return []

    def run_semgrep(self, file_path):
        # Semgrep provides additional security coverage [cite: new requirement]
        cmd = ["semgrep", "scan", "--config=p/python", "--json", "-q", file_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Save raw output
        parts = file_path.split(os.sep)
        approach = parts[-2] if len(parts) >= 2 else "default"
        save_dir = os.path.join(self.semgrep_dir, approach)
        if not os.path.exists(save_dir): os.makedirs(save_dir)
        
        base_name = os.path.basename(file_path).replace(".py", ".json")
        with open(os.path.join(save_dir, base_name), "w") as f:
            f.write(result.stdout)

        try:
            return json.loads(result.stdout).get('results', [])
        except:
            return []

    def scan_entire_output(self, target_dir="output"):
        # Bulk scan for all pipelines
        print(f"Running bulk security scan on: {target_dir}")
        
        # Bandit bulk scan
        bandit_cmd = ["bandit", "-r", target_dir, "-f", "json", "-o", os.path.join(self.bandit_dir, "all_pipelines.json"), "-q"]
        subprocess.run(bandit_cmd)
        
        # Semgrep bulk scan
        semgrep_cmd = ["semgrep", "scan", "--config=p/python", "--json", "-o", os.path.join(self.semgrep_dir, "all_pipelines.json"), "-q", target_dir]
        subprocess.run(semgrep_cmd)
        
        print(f"Bulk scan reports saved to {self.bandit_dir}/all_pipelines.json and {self.semgrep_dir}/all_pipelines.json")

    def analyze(self, file_path):
        bandit_issues = self.run_bandit(file_path)
        semgrep_issues = self.run_semgrep(file_path)
        
        with open(file_path, 'r') as f:
            loc = len(f.readlines())
        
        # Merge issues by line number to avoid double counting similar detections
        unique_lines = set()
        for issue in bandit_issues:
            unique_lines.add(issue.get('line_number'))
        for issue in semgrep_issues:
            unique_lines.add(issue.get('start', {}).get('line'))
        
        vuln_count = len(unique_lines)
        density = vuln_count / loc if loc > 0 else 0
        return vuln_count, density