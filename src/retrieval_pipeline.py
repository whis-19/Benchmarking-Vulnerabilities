import chromadb
from sentence_transformers import SentenceTransformer

class RAGRetrievalPipeline:
    def __init__(self, sec_guide):
        self.model = SentenceTransformer('all-MiniLM-L6-v2')
        self.client = chromadb.Client()
        # Clean existing collection if it exists
        try: self.client.delete_collection("sec_guide")
        except: pass
        self.collection = self.client.create_collection(name="sec_guide")
        self._populate(sec_guide)

    def _populate(self, sec_guide):
        for i, entry in enumerate(sec_guide):
            text = f"Precondition: {entry['Precondition']} Guideline: {entry['Guideline']}"
            self.collection.add(
                embeddings=[self.model.encode(text).tolist()],
                documents=[text],
                metadatas=[{"cwe": entry['CWE_ID']}],
                ids=[f"guideline_{i}"]
            )

    def query(self, task_content, n=10):
        # Retrieves the top 10 most relevant guidelines [cite: 129]
        task_embedding = self.model.encode(task_content).tolist()
        results = self.collection.query(
            query_embeddings=[task_embedding],
            n_results=n
        )
        return "\n".join(results['documents'][0])