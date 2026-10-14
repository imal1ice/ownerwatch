FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY ownerwatch ./ownerwatch
RUN pip install --no-cache-dir .
VOLUME ["/app/state"]
ENTRYPOINT ["ownerwatch"]
CMD ["run", "--config", "/app/config.yaml"]
