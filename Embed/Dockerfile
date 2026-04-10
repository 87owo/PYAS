FROM python:3.10-slim

RUN apt-get update && apt-get install -y \
    build-essential \
    libfuzzy-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-u", "predict_onnx_linux.py"]