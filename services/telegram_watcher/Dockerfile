FROM raven-base-cpu:1.0
RUN pip install telethon==1.36.0
COPY services/telegram_watcher/ /app/
USER raven
CMD ["python", "main.py"]
