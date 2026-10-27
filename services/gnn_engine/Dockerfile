FROM raven-base-gpu:1.0
RUN pip install torch-geometric==2.6.1 neo4j==5.26.0 networkx==3.4.2
COPY services/gnn_engine/ /app/
USER raven
CMD ["python", "main.py"]
