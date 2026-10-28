FROM raven-base-cpu:1.0
RUN pip install httpx==0.27.2
COPY services/enrichment_worker/ /app/
USER raven
ENTRYPOINT ["python", "main.py"]
