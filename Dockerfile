# Trust & Risk Layer — Team Zetabyte
#
# Two-stage build. The first stage installs the Python dependencies, including a
# CPU-only PyTorch (the default wheel pulls ~2 GB of CUDA libraries this project has
# no use for). The second stage copies the resulting site-packages and the source.
#
#   docker compose build
#   docker compose run --rm verify
#   docker compose up dashboard
#
# Detector models are NOT baked into the image. They are ~750 MB, they are what makes
# the difference between a structural result and a measurement, and downloading them
# at build time would silently produce two classes of image that behave differently
# and look identical. `docker compose run --rm fetch-models` downloads them into a
# named volume instead, so the decision is explicit and the cache survives rebuilds.

# ---------------------------------------------------------------------------
# Stage 1 — dependencies
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS deps

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential is needed by a few wheels that lack a manylinux build for slim.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /install

COPY requirements.txt .

# torch and requirements.txt are installed in ONE pip invocation, deliberately.
#
# The obvious arrangement -- install CPU-only torch from the PyTorch index, then
# install requirements.txt in a second command -- does not work with
# `--prefix`. A prefix install lands outside the interpreter's sys.path, so the
# second pip cannot see the torch the first one installed. It reads torch as an
# unsatisfied dependency of sentence-transformers, resolves it against the
# default index, and downloads a second, larger torch wheel (~550 MB) on top of
# the CPU one. Both end up in the image; the CPU-only intent is silently lost,
# and every cold build pays for two torch downloads.
#
# One invocation gives the resolver a single view: torch appears once, and the
# CPU index is primary so that is the wheel it picks. PyPI stays available as an
# extra index for everything else, which the PyTorch index does not carry.
RUN pip install --prefix=/install/deps \
      --index-url https://download.pytorch.org/whl/cpu \
      --extra-index-url https://pypi.org/simple \
      torch -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2 — runtime
# ---------------------------------------------------------------------------
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Trust & Risk Layer for Healthcare Threat-Intel RAG" \
      org.opencontainers.image.description="Detects attacker-induced hallucination (corpus poisoning) in retrieval-augmented generation pipelines." \
      org.opencontainers.image.authors="Team Zetabyte, Manipal University Jaipur" \
      org.opencontainers.image.version="1.0.0"

COPY --from=deps /install/deps /usr/local

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    # Keep every model download inside the mounted cache volume rather than the
    # container's writable layer, so it survives `docker compose down`.
    HF_HOME=/models \
    TRANSFORMERS_CACHE=/models \
    SENTENCE_TRANSFORMERS_HOME=/models \
    # Streamlit defaults to phoning home and to an interactive first-run prompt.
    # Neither is wanted in a container that may be demonstrated offline.
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0

# A non-root user. The mounted volumes below are chowned to match.
RUN useradd --create-home --uid 1000 zetabyte \
 && mkdir -p /models /app \
 && chown -R zetabyte:zetabyte /models /app

WORKDIR /app

COPY --chown=zetabyte:zetabyte corpus/     ./corpus/
COPY --chown=zetabyte:zetabyte pipeline/   ./pipeline/
COPY --chown=zetabyte:zetabyte detectors/  ./detectors/
COPY --chown=zetabyte:zetabyte fusion/     ./fusion/
COPY --chown=zetabyte:zetabyte reports/    ./reports/
COPY --chown=zetabyte:zetabyte logs/       ./logs/
COPY --chown=zetabyte:zetabyte dashboard/  ./dashboard/
COPY --chown=zetabyte:zetabyte eval/       ./eval/
COPY --chown=zetabyte:zetabyte docs/       ./docs/
COPY --chown=zetabyte:zetabyte README.md requirements.txt ./

# These four are volume mount points. Docker seeds an empty named volume from the
# image's directory at that path, INCLUDING its ownership — but only if the
# directory exists. If it does not, Docker creates it owned by root and the
# non-root user cannot write there, which surfaces as a permission error part-way
# through `build_index` rather than at startup.
RUN mkdir -p /app/pipeline/index /app/logs /app/eval/results /app/fusion/artifacts \
 && chown -R zetabyte:zetabyte /app/pipeline/index /app/logs /app/eval/results \
                               /app/fusion/artifacts

USER zetabyte

EXPOSE 8501

# Distinguishes "the container is up" from "the container can actually work": the
# packages import and the corpus is present. Deliberately does not require the
# detector models, since running on fallbacks is a supported (and clearly labelled)
# mode rather than an unhealthy one.
HEALTHCHECK --interval=30s --timeout=20s --start-period=40s --retries=3 \
    CMD python -c "import sys, pathlib; \
import fusion, reports, logs.audit, dashboard.service; \
n = len(list(pathlib.Path('/app/corpus/clean').glob('*.json'))); \
sys.exit(0 if n > 1 else 1)" || exit 1

CMD ["python", "-m", "pipeline.check_backends"]
