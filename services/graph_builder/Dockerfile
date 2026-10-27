FROM raven-base-cpu:1.0
RUN pip install neo4j==5.26.0
COPY services/graph_builder/ /app/
USER raven
CMD ["python", "main.py"]
