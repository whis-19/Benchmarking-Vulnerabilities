class CAGGenerationPipeline:
    def __init__(self, generator, sec_guide):
        self.generator = generator
        # CAG provides all guidelines at once instead of dynamic retrieval
        self.full_context = "\n".join([f"- {g['Guideline']}" for g in sec_guide])

    def execute(self, task):
        prompt = (
            f"Always follow these security rules:\n{self.full_context}\n\n"
            f"Generate secure Python code for: {task}"
        )
        return self.generator.generate_code(prompt)