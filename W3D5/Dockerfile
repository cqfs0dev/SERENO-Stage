FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y curl && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./scan.py ./scan.py

ENTRYPOINT ["python", "scan.py"]