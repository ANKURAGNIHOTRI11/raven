# Disposable patch-validation sandbox. No network route to production, no
# privileged capabilities, read-only root filesystem at runtime.
FROM raven-base-cpu:1.0
RUN pip install fastapi==0.115.5 "uvicorn[standard]==0.32.1" pyyaml==6.0.2
COPY services/sandbox/ /app/
USER raven
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090"]
