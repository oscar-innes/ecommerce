FROM python:3.13.3-alpine

WORKDIR /app

RUN apk add --no-cache \
    build-base \
    gcc \
    g++ \
    git \
    musl-dev \
    libffi-dev \
    python3-dev

ENV DJANGO_SETTINGS_MODULE=web_project.settings
ENV DEBUG=False

COPY requirements.txt ./
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 9001/tcp

CMD ["python", "manage.py", "runserver", "localhost:9001"]
