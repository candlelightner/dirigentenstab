FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS build
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://github.com/apache/cloudstack-cloudmonkey/releases/download/6.6.0/cmk.linux.x86-64 -o /cmk \
    && echo '9f4f92ebc3b1e6139d81a2b3f9e7f7c663d1806234ae0ab27cf77753c553d76b  /cmk' | sha256sum -c - \
    && chmod 755 /cmk
COPY requirements.lock pyproject.toml ./
COPY dirigentenstab ./dirigentenstab
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.lock \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps .

FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70
LABEL org.opencontainers.image.source="https://github.com/candlelightner/dirigentenstab" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="CloudStack-backed hierarchical AI agent manager"
RUN useradd --uid 10001 --create-home dirigent && mkdir /data && chown 10001:10001 /data
COPY --from=build /opt/venv /opt/venv
COPY --from=build /cmk /usr/local/bin/cmk
ENV PATH="/opt/venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /home/dirigent
EXPOSE 8088
CMD ["dirigentenstab"]
