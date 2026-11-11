# cvescan image: Python standard library only, plus one pinned osv-scanner
# binary. No git, no compilers, no package managers are used at run time:
# the scan only parses files and never executes anything from the project.
#
# There is deliberately no "# syntax=" line: it would make every build pull
# an unpinned frontend image, and nothing here needs more than the built-in one.
#
# A release build should pin the base image by digest:
#   docker build --build-arg PYTHON_IMAGE=python:3.13-slim@sha256:<digest> ...
ARG PYTHON_IMAGE=python:3.13-slim

FROM ${PYTHON_IMAGE} AS scanner
ARG TARGETARCH
ARG OSV_SCANNER_VERSION=2.7.1
# From osv-scanner_SHA256SUMS of the v2.7.1 release.
ARG OSV_SCANNER_SHA256_AMD64=fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8
ARG OSV_SCANNER_SHA256_ARM64=983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81
ADD https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${TARGETARCH} /osv-scanner
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sum="${OSV_SCANNER_SHA256_AMD64}" ;; \
      arm64) sum="${OSV_SCANNER_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "${sum}  /osv-scanner" | sha256sum -c -; \
    chmod 0755 /osv-scanner

FROM ${PYTHON_IMAGE}
COPY --from=scanner /osv-scanner /usr/local/bin/osv-scanner
COPY core/cvescan_core /opt/cvescan/cvescan_core
# COPY keeps the permissions of the checkout. With a umask such as 077 the
# files would be readable by root only, and the scan runs as the caller's uid.
RUN chmod -R a+rX /opt/cvescan
ENV PYTHONPATH=/opt/cvescan \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8
# The wrapper overrides the user with the caller's uid; this is only the default.
USER 65534:65534
ENTRYPOINT ["python3", "-m", "cvescan_core"]
