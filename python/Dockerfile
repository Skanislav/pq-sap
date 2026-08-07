# syntax=docker/dockerfile:1

# Stage 1: build liboqs (audited backend for the cross-check verifier
# and the benchmark KEM sweep). Pin matches liboqs-python.
FROM python:3.12-slim AS liboqs
ARG LIBOQS_VERSION=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        git cmake ninja-build build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build

FROM python:3.12-slim
COPY --from=liboqs /opt/liboqs/ /usr/local/
RUN ldconfig
WORKDIR /app
COPY pyproject.toml README.md ./
COPY pq_stealth/ pq_stealth/
COPY tests/ tests/
COPY vectors/ vectors/
COPY benchmarks/ benchmarks/
RUN pip install --no-cache-dir -e ".[dev,audit,bench]"
CMD ["pytest", "-q"]
