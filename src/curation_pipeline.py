import re

class SecGuideCurationPipeline:
    def __init__(self, dataset):
        self.dataset = dataset

    def granularize_text(self, text):
        return [u.strip() for u in re.split(r'(?<=[.!?])\s+', text) if u]

    def standardize_guideline(self, unit):
        # Standardizing as per paper: "The code unit should..." [cite: 247]
        return f"The code unit should ensure {unit.lower()}"

    def run_pipeline(self):
        curated_database = []
        for sample in self.dataset:
            cwe_id = str(sample.get('topics', ['Unknown']))
            # Extracting descriptions and potential mitigations [cite: 225]
            raw_content = sample.get('question', '')
            
            units = self.granularize_text(raw_content)
            for unit in units:
                curated_database.append({
                    "CWE_ID": cwe_id,
                    "Precondition": f"Task involves {cwe_id} related functionality.",
                    "Guideline": self.standardize_guideline(unit),
                    "is_top_25": True # SecEval focuses on high-risk CWEs [cite: 83]
                })
        return curated_database