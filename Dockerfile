# rbac-auditor — snapshots Kubernetes RBAC to a committable JSON file and
# diffs two snapshots under a policy that decides the exit code.
ARG KUBECTL_VERSION=1.33.2

FROM alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS fetch
ARG KUBECTL_VERSION
ARG TARGETOS=linux
ARG TARGETARCH=amd64
# busybox wget over the base image's ssl_client and CA bundle: no apk add,
# so no unpinned package versions in the build.
# pipefail so the checksum comparison below can't be silently skipped
SHELL ["/bin/ash", "-o", "pipefail", "-c"]
RUN wget -qO /kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/${TARGETOS}/${TARGETARCH}/kubectl" \
 && wget -qO /kubectl.sha256 "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/${TARGETOS}/${TARGETARCH}/kubectl.sha256" \
 && echo "$(cat /kubectl.sha256)  /kubectl" | sha256sum -c - \
 && chmod 0755 /kubectl

FROM python:3.14-alpine3.22@sha256:6b91e66ab2a880ce9ca5a1b91c70f45963ff71ff68268df056336e1a657d5efd
LABEL org.opencontainers.image.title="rbac-auditor" \
      org.opencontainers.image.description="Snapshot Kubernetes RBAC and diff it under a policy" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/fabiocicerchia/rbac-auditor"
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt \
 && adduser -D -u 10001 auditor
COPY NOTICE /NOTICE
COPY --from=fetch /kubectl /usr/local/bin/kubectl
COPY rbac_audit.py /usr/local/bin/rbac-audit
# Beside the script: Python puts the script's directory on sys.path.
COPY rbac_audit_policy.py /usr/local/bin/rbac_audit_policy.py
USER 10001
# A one-shot CLI, not a daemon: there is nothing to probe.
HEALTHCHECK NONE
# hardener: run this image with `docker run --read-only` for a read-only rootfs
ENTRYPOINT ["python", "/usr/local/bin/rbac-audit"]
CMD ["snapshot"]
