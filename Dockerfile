FROM python:3.13-slim AS base

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

ENV VIRTUAL_ENV=/venv
RUN python -m venv $VIRTUAL_ENV

ENV PATH=$VIRTUAL_ENV/bin/:$PATH

WORKDIR /opt/netcup-foip-operator
COPY pyproject.toml .
COPY uv.lock .
RUN uv sync --compile-bytecode --active --no-install-project

COPY src ./src/
COPY README.md .
COPY LICENSE .
RUN uv sync --compile-bytecode --active
