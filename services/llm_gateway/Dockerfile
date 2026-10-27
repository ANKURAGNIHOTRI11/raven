FROM raven-base-cpu:1.0
RUN pip install fastapi==0.115.5 "uvicorn[standard]==0.32.1"
COPY services/llm_gateway/ /app/
USER raven
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
