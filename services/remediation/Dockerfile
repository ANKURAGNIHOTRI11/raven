FROM raven-base-cpu:1.0
RUN pip install pyyaml==6.0.2
COPY services/remediation/ /app/
USER raven
CMD ["python", "main.py"]
