FROM raven-base-gpu:1.0
RUN pip install sentence-transformers==3.3.1 fastapi==0.115.5 "uvicorn[standard]==0.32.1"
COPY services/embedder/ /app/
USER raven
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
