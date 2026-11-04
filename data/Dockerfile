FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY data ./data
RUN pip install --no-cache-dir .
ENV SCAMHELPER_DATA=/app/data
EXPOSE 8080
ENTRYPOINT ["scamhelper"]
CMD ["check", "--help"]
