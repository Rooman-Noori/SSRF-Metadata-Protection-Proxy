FROM python:3.12-slim

WORKDIR /app
ENV HOST=0.0.0.0
ENV PORT=5000

COPY requirements.txt ./
RUN pip install --no-cache-dir --default-timeout=300 --retries=10 -r requirements.txt "prowler==5.49.0"
COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
