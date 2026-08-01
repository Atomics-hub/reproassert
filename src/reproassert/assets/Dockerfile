FROM python:3.12.13-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.lock /tmp/reproassert-requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes \
      -r /tmp/reproassert-requirements.lock \
    && rm -f /tmp/reproassert-requirements.lock

WORKDIR /workspace
USER 65532:65532
