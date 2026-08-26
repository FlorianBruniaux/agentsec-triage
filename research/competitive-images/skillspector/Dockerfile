# syntax=docker/dockerfile:1.7

FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b AS builder
COPY --from=ghcr.io/astral-sh/uv:0.10.9@sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82 /uv /usr/local/bin/uv
WORKDIR /build
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_LINK_MODE=copy
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project \
    && uv pip install --python /opt/venv/bin/python hatchling==1.31.0
COPY . .
RUN --network=none uv pip install --python /opt/venv/bin/python \
    --offline --no-deps --no-build-isolation .

FROM python:3.12-slim-bookworm@sha256:8a7e7cc04fd3e2bd787f7f24e22d5d119aa590d429b50c95dfe12b3abe52f48b
COPY --from=builder /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
ENTRYPOINT ["skillspector"]
