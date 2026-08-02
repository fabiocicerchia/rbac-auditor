# rbac-auditor — dumps and diffs Kubernetes RBAC into readable reports:
# who-can queries, unused ServiceAccounts, wildcard grants.
ARG KUBECTL_VERSION=1.33.2

FROM alpine:3.22 AS fetch
ARG KUBECTL_VERSION
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN apk add --no-cache curl ca-certificates
RUN curl -fsSLo /kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/${TARGETOS}/${TARGETARCH}/kubectl" \
 && chmod 0755 /kubectl

FROM python:3.13-alpine3.22
LABEL org.opencontainers.image.title="rbac-auditor" \
      org.opencontainers.image.description="Dump and diff Kubernetes RBAC into readable reports" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/fabiocicerchia/rbac-auditor"
RUN pip install --no-cache-dir pyyaml==6.0.2 \
 && adduser -D -u 10001 auditor
COPY --from=fetch /kubectl /usr/local/bin/kubectl
COPY rbac_audit.py /usr/local/bin/rbac-audit
USER 10001
ENTRYPOINT ["python", "/usr/local/bin/rbac-audit"]
CMD ["report"]
