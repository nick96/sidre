# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.145.1/containers/rust/.devcontainer/base.Dockerfile

FROM mcr.microsoft.com/vscode/devcontainers/rust:0-1

RUN curl -L https://github.com/rust-analyzer/rust-analyzer/releases/latest/download/rust-analyzer-linux -o /usr/bin/rust-analyzer \
    && chmod +x /usr/bin/rust-analyzer

# [Optional] Uncomment this section to install additional packages.
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends \
        pkg-config libssl-dev build-essential xml-security-c-utils libxmlsec1-dev libclang-dev clang llvm libxml2-dev
