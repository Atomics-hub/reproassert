FROM python:3.12.13-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b

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
