from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_core.documents import Document

import os

RUNBOOK_PATH = "data/runbooks/ssis_runbook.md"
PERSIST_DIR = "data/vector_store"

def main():
    if not os.path.exists(RUNBOOK_PATH):
        raise FileNotFoundError(f"Runbook not found at {RUNBOOK_PATH}")

    with open(RUNBOOK_PATH, "r", encoding="utf-8") as f:
        text = f.read()

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=800,
        chunk_overlap=150
    )

    chunks = splitter.split_text(text)
    documents = [Document(page_content=chunk) for chunk in chunks]

    embeddings = HuggingFaceEmbeddings(
        model_name="all-MiniLM-L6-v2"
    )

    vectordb = Chroma.from_documents(
        documents,
        embedding=embeddings,
        persist_directory=PERSIST_DIR
    )

    vectordb.persist()
    print("Vector DB built successfully.")

if __name__ == "__main__":
    main()

