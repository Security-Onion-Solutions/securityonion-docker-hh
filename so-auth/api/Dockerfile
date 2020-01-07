FROM python:latest
LABEL maintainer="william.wernert@securityonionsolutions.com"

ENV REFRESH_TOKEN_TIMEOUT=30
ENV TOKEN_TIMEOUT=60
RUN mkdir -p /data
ENV DB_URI="sqlite:////data/db.sqlite"

ENV BASE_PATH=""
ENV DOMAIN="localhost"
ENV HOMEPAGE="localhost:8080"

RUN mkdir -p /app/api
WORKDIR /app/api

COPY . .

RUN python setup.py -q install
RUN pip install gunicorn

EXPOSE 5656

WORKDIR /app/api/api
ENTRYPOINT [ "gunicorn", "-b", "0.0.0.0:5656", "api:gunicorn_app" ]

RUN useradd -u 8888 so-auth
USER so-auth
