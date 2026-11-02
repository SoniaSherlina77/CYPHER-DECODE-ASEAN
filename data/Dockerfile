# Small, non-root image. Build: docker build -t scam-aware-assistant .
# Run the demo: docker run --rm scam-aware-assistant demo
FROM python:3.13-slim AS build
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir build \
 && python -m build --wheel --outdir /dist

FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 SCAMAWARE_LOG_FORMAT=json
RUN useradd --create-home --uid 10001 app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl
USER app
ENTRYPOINT ["scamaware"]
CMD ["demo"]
