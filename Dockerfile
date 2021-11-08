FROM python:3.9.6-alpine

WORKDIR /usr/src/app
COPY requirements.txt .

RUN apk add --no-cache \
    gcc \
    python3-dev \
    musl-dev \
    libffi-dev \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del gcc
COPY . .

COPY docker/entrypoint.sh /entrypoint.sh

CMD ["./entrypoint.sh"]
