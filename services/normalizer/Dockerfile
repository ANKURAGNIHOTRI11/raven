FROM raven-base-gpu:1.0
RUN pip install transformers==4.46.3 sentencepiece==0.2.0 protobuf==5.28.3 \
    accelerate==1.1.1 httpx==0.27.2
COPY services/normalizer/ /app/
USER raven
CMD ["python", "main.py"]
