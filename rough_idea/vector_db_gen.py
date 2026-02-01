from langchain_community.document_loaders import CSVLoader
import google.generativeai as genai
from langchain_community.vectorstores import Chroma
from langchain.schema import Document
from config import config
import pandas as pd
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
genai.configure(api_key=os.environ.get("GOOGLE_API_KEY"))

class GeminiEmbeddings:
    """Custom embedding class for Gemini models"""
    def __init__(self, model_name="models/text-embedding-004"):
        self.model_name = model_name
        
    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        # Single API call for lists is more efficient
        result = genai.embed_content(
            model=self.model_name,
            content=texts,
            task_type="retrieval_document"
        )
        return result['embedding']
        
    def embed_query(self, text: str) -> list[float]:
        result = genai.embed_content(
            model=self.model_name,
            content=text,
            task_type="retrieval_query"
        )
        return result['embedding']


def create_vector_db():
    # Check if database already exists
    if os.path.exists(os.path.join(config.persist_dir, "chroma.sqlite3")):
        print("Database already exists. Loading existing database...")
        return load_vector_db()

    print("Creating new database...")
    embeddings = GeminiEmbeddings(model_name=config.embedding_model)

    # Read CSV and create documents
    df = pd.read_csv(config.guidelinescsv_file)
    documents = []

    for idx, row in df.iterrows():
        text = f"Preconditions: {row['Preconditions']}"
        doc = Document(
            page_content=text,
            metadata={
                "id": row["ID"],
                "guidelines": row["Secure Coding Guidelines"],
                "cwe_id": row["CWE-IDs"]
            }
        )
        documents.append(doc)

    # Create and persist vector store
    vectordb = Chroma.from_documents(
        documents=documents,
        embedding=embeddings,
        persist_directory=config.persist_dir
    )
    vectordb.persist()
    return vectordb


def load_vector_db():
    if not os.path.exists(os.path.join(config.persist_dir, "chroma.sqlite3")):
        raise FileNotFoundError(
            f"No existing database found in {config.persist_dir}")

    print("Loading existing database...")
    embeddings = GeminiEmbeddings(model_name=config.embedding_model)
    return Chroma(
        persist_directory=config.persist_dir,
        embedding_function=embeddings
    )


def query_vector_db(query: str, db, k: int = 10):

    results = db.similarity_search(query, k=k)
    for doc in results:
        doc.page_content += f"\nGuidelines: {doc.metadata['guidelines']}"
    return results


def read_Sallms_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('prompt', '').strip())
    return security_eval_tasks


def read_SecurityEval_tasks(file_path: str):
    security_eval_tasks = []
    with open(file_path, 'r') as file:
        for line in file:
            data = json.loads(line)
            security_eval_tasks.append(data.get('Prompt', '').strip())
    return security_eval_tasks


def prompt_template(task: str, preconditions_guidelines: list[str]):
    # task_prompt = f"Generate secure Python code for the following:\n {task}"
    task_prompt = f"{task}\n"
    # additional_info = "\nHere are some additional security guidelines to follow if the coding task satisfies the specific preconditions:\n"
    guideline_num = 1
    info = ""
    for pair in preconditions_guidelines:
        # Access the page_content attribute of the Document object
        content = pair.page_content
        info += f"#{guideline_num}\n{content}\n"
        guideline_num += 1
    return task_prompt + info
