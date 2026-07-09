FROM python:3.14.6-slim-bookworm@sha256:4ff4b92a68355dbdb52584ab3391dff8d371a61d4e063468bfd0130e3189c6d9

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
