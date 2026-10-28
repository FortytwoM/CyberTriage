# Linux image: works on Linux, macOS and Windows Docker Desktop (Linux containers).
# MSI/JAR/CAB editing uses msitools + gcab + 7-Zip; no Windows APIs are needed.
FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        default-jdk-headless \
        msitools \
        gcab \
        p7zip-full \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

ENTRYPOINT ["python", "/app/tools/cybertriage-license/issue.py", "--input-dir", "/data/input", "--output-dir", "/data/output", "--licenses-dir", "/app/licenses"]
