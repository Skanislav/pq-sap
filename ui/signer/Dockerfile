# Blinded-key signer service (ui/scripts/signer-service.mjs + the Python
# helpers) as a container, for Railway or any Docker host.
#
# Build context is the staging directory assembled by ui/scripts/deploy-signer.mjs:
#   Dockerfile, python/scripts/, ui/scripts/signer-service.mjs
# ETHDILITHIUM's pythonref is not tracked in this repo (js-client/contracts/lib
# is gitignored), so it is fetched here at the same commit the UI is vendored on.

FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG ETHDILITHIUM_REV=df999ed4f8032d26d9d3d22748407afbb7978ae7
RUN git init -q /opt/ETHDILITHIUM \
    && git -C /opt/ETHDILITHIUM fetch -q --depth 1 https://github.com/ZKNoxHQ/ETHDILITHIUM ${ETHDILITHIUM_REV} \
    && git -C /opt/ETHDILITHIUM checkout -q FETCH_HEAD \
    && rm -rf /opt/ETHDILITHIUM/.git

# pythonref deps (pycryptodome, eth_abi, numpy, polyntt from git) + kyber-py for the hybrid helper
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /opt/ETHDILITHIUM/pythonref/requirements.txt kyber-py

WORKDIR /app
COPY python/scripts python/scripts
COPY ui/scripts/signer-service.mjs ui/scripts/signer-service.mjs

ENV PQ_PYTHON=/opt/venv/bin/python \
    ZKNOX_PYTHONREF=/opt/ETHDILITHIUM/pythonref \
    SIGNER_HOST=0.0.0.0 \
    PORT=8546
EXPOSE 8546

CMD ["node", "ui/scripts/signer-service.mjs"]
