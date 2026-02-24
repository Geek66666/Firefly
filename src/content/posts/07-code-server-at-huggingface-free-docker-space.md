---
title: 使用Huggingface的免费Docker空间运行Code Server
published: 2026-02-24
description: 使用Huggingface的免费Docker空间部署一个含有Python，Java，C++等常用编程语言的Code Server，并同时安装并部署Codex使用
image: ./covers/cover7.webp
tags: [软件开发, Codex, Code Server, Docker, Huggingface]
category: 软件开发
draft: false
---

## 部署教程

### 1.进入Huggingface，创建Docker Space
**前置条件：1.自备魔法上网 2.拥有Huggingface账号**
按照下图的方式新建一个Docker Space，选择Docker，Docker template为Blank
![alt text](image-26.png)

![alt text](image-27.png)

![alt text](image-28.png)

其他的不用修改，直接创建Space

### 2.进入Space，新建两个文件
![alt text](image-29.png)

#### 新建一个名为`Dockerfile`的文件，内容如下：
```Dockerfile
FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC
ENV PORT=7860
ENV HOME=/home/coder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

ARG CODE_SERVER_VERSION=4.109.2

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git bash sudo tini jq procps unzip \
    # C/C++ 基础工具链 + 头文件
    build-essential gcc g++ make cmake ninja-build gdb clang clangd \
    libc6-dev linux-libc-dev pkg-config \
    # Java + Node
    openjdk-17-jdk-headless maven \
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# 安装 code-server（固定版本）
RUN curl -fsSL "https://github.com/coder/code-server/releases/download/v${CODE_SERVER_VERSION}/code-server_${CODE_SERVER_VERSION}_amd64.deb" -o /tmp/code-server.deb \
    && dpkg -i /tmp/code-server.deb \
    && rm -f /tmp/code-server.deb

# Python 核心依赖（精简）
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir \
    numpy pandas scipy scikit-learn matplotlib \
    jupyterlab ipykernel notebook \
    requests httpx aiohttp pyyaml python-dotenv tqdm rich \
    fastapi uvicorn[standard] pydantic flask \
    sqlalchemy alembic psycopg2-binary redis \
    pytest black isort ruff mypy

# Codex CLI
RUN npm install -g @openai/codex && npm cache clean --force

# 创建用户
RUN useradd -m -u 1000 -s /bin/bash coder \
    && echo "coder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && mkdir -p /home/coder/.config/code-server /home/coder/.codex \
    && chown -R coder:coder /home/coder

# 快速验证 C 编译环境（构建期）
RUN printf '#include <stdio.h>\nint main(){puts("ok");return 0;}\n' > /tmp/t.c \
    && gcc /tmp/t.c -o /tmp/t \
    && /tmp/t | grep -q ok \
    && rm -f /tmp/t.c /tmp/t

COPY --chown=coder:coder start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

USER coder
WORKDIR /home/coder

EXPOSE 7860
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/start.sh"]
```


#### 新建一个名为`start.sh`的文件，内容如下
本方法的Codex使用三方api，因此需要配置api_key
有关Codex的相关配置在脚本`config.toml`部分，可使用环境变量的方式修改API_KEY和BASE_URL
`config.toml`的配置教程可参考上一篇文章，也可参考你自己模型提供商的教程
```start.sh
#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-7860}"

if [[ -z "${PASSWORD:-}" && -z "${HASHED_PASSWORD:-}" ]]; then
  echo "[ERROR] Missing PASSWORD/HASHED_PASSWORD secret."
  exit 1
fi

if [[ -d "/data" ]]; then
  WORKDIR="/data/workspace"
  EXT_DIR="/data/code-server/extensions"
  USER_DATA_DIR="/data/code-server/user-data"
  CODEX_DIR="/data/.codex"
else
  WORKDIR="${HOME}/workspace"
  EXT_DIR="${HOME}/.local/share/code-server/extensions"
  USER_DATA_DIR="${HOME}/.local/share/code-server/user-data"
  CODEX_DIR="${HOME}/.codex"
fi

mkdir -p "$WORKDIR" "$EXT_DIR" "$USER_DATA_DIR" "${HOME}/.config/code-server" "$CODEX_DIR"

cat > "${HOME}/.config/code-server/config.yaml" <<EOF
bind-addr: 0.0.0.0:${PORT}
auth: password
cert: false
EOF

if [[ -n "${HASHED_PASSWORD:-}" ]]; then
  echo "hashed-password: ${HASHED_PASSWORD}" >> "${HOME}/.config/code-server/config.yaml"
else
  echo "password: ${PASSWORD}" >> "${HOME}/.config/code-server/config.yaml"
fi

# Codex config.toml
: "${CODEX_MODEL_PROVIDER:=sub2api}"
: "${CODEX_MODEL:=gpt-5.3-codex}"
: "${CODEX_REASONING_EFFORT:=high}"
: "${CODEX_NETWORK_ACCESS:=enabled}"
: "${CODEX_DISABLE_RESPONSE_STORAGE:=true}"
: "${CODEX_WSL_ACK:=true}"
: "${CODEX_VERBOSITY:=high}"
: "${CODEX_PROVIDER_NAME:=sub2api}"
: "${CODEX_BASE_URL:=https://ai.qaq.al}"
: "${CODEX_WIRE_API:=responses}"
: "${CODEX_REQUIRES_OPENAI_AUTH:=true}"

cat > "${CODEX_DIR}/config.toml" <<EOF
model_provider = "${CODEX_MODEL_PROVIDER}"
model = "${CODEX_MODEL}"
model_reasoning_effort = "${CODEX_REASONING_EFFORT}"
network_access = "${CODEX_NETWORK_ACCESS}"
disable_response_storage = ${CODEX_DISABLE_RESPONSE_STORAGE}
windows_wsl_setup_acknowledged = ${CODEX_WSL_ACK}
model_verbosity = "${CODEX_VERBOSITY}"
[model_providers.${CODEX_PROVIDER_NAME}]
name = "${CODEX_PROVIDER_NAME}"
base_url = "${CODEX_BASE_URL}"
wire_api = "${CODEX_WIRE_API}"
requires_openai_auth = ${CODEX_REQUIRES_OPENAI_AUTH}
EOF

if [[ -n "${CODEX_AUTH_JSON:-}" ]]; then
  printf '%s\n' "${CODEX_AUTH_JSON}" > "${CODEX_DIR}/auth.json"
elif [[ -n "${OPENAI_API_KEY:-}" ]]; then
  cat > "${CODEX_DIR}/auth.json" <<EOF
{
  "OPENAI_API_KEY": "${OPENAI_API_KEY}"
}
EOF
fi

chmod 600 "${CODEX_DIR}/config.toml" 2>/dev/null || true
chmod 600 "${CODEX_DIR}/auth.json" 2>/dev/null || true

if [[ "${CODEX_DIR}" != "${HOME}/.codex" ]]; then
  rm -rf "${HOME}/.codex"
  ln -s "${CODEX_DIR}" "${HOME}/.codex"
fi

# 首次启动安装扩展（幂等）
EXT_MARKER="${USER_DATA_DIR}/.extensions_installed"
if [[ ! -f "${EXT_MARKER}" ]]; then
  echo "[INFO] Installing extensions on first boot..."

  install_ext() {
    code-server --extensions-dir "${EXT_DIR}" --install-extension "$1" || true
  }

  # 你指定的（尽量装）
  install_ext ms-vscode.cpptools
  install_ext ms-vscode.cpptools-themes
  install_ext ms-vscode.cpp-devtools
  install_ext ms-vscode.cmake-tools
  install_ext danielpinto8zz6.c-cpp-compile-run
  install_ext redhat.java
  install_ext vscjava.vscode-java-debug
  install_ext vscjava.vscode-java-test
  install_ext vscjava.vscode-maven
  install_ext vscjava.vscode-gradle
  install_ext vscjava.vscode-java-dependency
  

  # Codex
  install_ext openai.chatgpt

  # 若微软扩展不可用，装稳定替代
  install_ext llvm-vs-code-extensions.vscode-clangd
  install_ext ms-vscode.makefile-tools
  install_ext vadimcn.vscode-lldb

  touch "${EXT_MARKER}"
fi

echo "[INFO] Java:   $(java -version 2>&1 | head -n1 || true)"
echo "[INFO] Python: $(python --version || true)"
echo "[INFO] Pip:    $(pip --version || true)"
echo "[INFO] Node:   $(node --version || true)"
echo "[INFO] g++:    $(g++ --version | head -n1 || true)"

exec code-server "$WORKDIR" \
  --extensions-dir "$EXT_DIR" \
  --user-data-dir "$USER_DATA_DIR" \
  --disable-telemetry \
  --disable-update-check \
  --log warn
```

进入`README.md`,开放端口7860
![alt text](image-30.png)

等待程序开始构建（首次部署时间比较久）

### 3.进入Space Settings，新建两个Secret
**注意：一定是要Secret，确保API_KEY的安全性**
![alt text](image-31.png)
```
PASSWORD: 你自己设置的密码
API_KEY: 你在你的Codex渠道获取的API_KEY，具体可见上一篇文章
```
### 4.等待部署完成，开始愉快的使用


## 免责声明
**使用本教程产生的一切不良后果与本人无关，此方法可能会导致Huggingface账号被封禁，请自行承担风险使用本方法造成。另外，此部署方式文件缺少持久化存储，容器重启就会丢失，请配合保活使用**