# Local inference

The optional two-network Compose overlay requires Docker Compose 2.33.1 or newer. It assigns the management network the higher gateway priority so CloudStack and guest traffic use the application's approved management address.

Dirigentenstab connects to an existing OpenAI-compatible inference service. It does
not install one inside the application image. In **Model providers**, select
**Chat Completions**, enter the server's `/v1` base URL and API key, and run
**Test provider**. Success requires the model to execute a nonce tool call and
continue the conversation. Model discovery is optional; manual model IDs work.

The following CPU-only example uses upstream
[llama.cpp Docker images](https://github.com/ggml-org/llama.cpp/blob/master/docs/docker.md)
and the official [Qwen3-0.6B GGUF model](https://huggingface.co/Qwen/Qwen3-0.6B-GGUF).
The model is Apache-2.0 licensed and is small enough for a connectivity PoC.
It is not a recommendation for unattended infrastructure administration: choose
and evaluate a model suitable for your workloads before relying on its decisions.

## Reproduce the acceptance provider

These pins were tested on an x86-64 Ubuntu host using three CPU threads, without
access to its NVIDIA GPU or existing VM storage:

- llama.cpp `b11854`, source revision `8e5a58df87ab59dfceb5b961ae26691e39f30c24`.
- Image digest `sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44`.
- Model repository revision `23749fefcc72300e3a2ad315e1317431b06b590a`.
- `Qwen3-0.6B-Q8_0.gguf`, 639,446,688 bytes.
- Model SHA256 `9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031`.

Run from the cloned repository. Store model data outside the checkout and keep
the generated API key in the ignored `secrets/` directory:

```sh
MODEL_DIR="$HOME/.local/share/dirigentenstab-models"
mkdir -p "$MODEL_DIR" secrets
chmod 700 secrets
curl -fL --retry 3 \
  https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/23749fefcc72300e3a2ad315e1317431b06b590a/Qwen3-0.6B-Q8_0.gguf \
  -o "$MODEL_DIR/Qwen3-0.6B-Q8_0.gguf"
echo "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031  $MODEL_DIR/Qwen3-0.6B-Q8_0.gguf" | sha256sum --check
python3 - <<'PY'
import os
import secrets
fd = os.open('secrets/inference-api-key', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, 'w') as key:
    key.write(secrets.token_urlsafe(32) + '\n')
PY
docker network create dirigentenstab-inference
docker run -d --name dirigentenstab-inference --restart unless-stopped \
  --network dirigentenstab-inference --network-alias inference \
  -p 127.0.0.1:18081:8080 --cpus 3 --memory 2g --pids-limit 128 \
  --user "$(id -u):$(id -g)" --cap-drop ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=128m \
  --mount "type=bind,src=$MODEL_DIR,dst=/models,readonly" \
  --mount "type=bind,src=$PWD/secrets/inference-api-key,dst=/run/secrets/inference-api-key,readonly" \
  ghcr.io/ggml-org/llama.cpp@sha256:20c4196fc08b459a34ef78aaa05b101333b2fac687e30ec99f37b3c9dc071b44 \
  -m /models/Qwen3-0.6B-Q8_0.gguf --host 0.0.0.0 --port 8080 \
  --alias qwen3-0.6b --threads 3 --threads-batch 3 --parallel 1 -c 8192 -n 512 -ngl 0 \
  --jinja --reasoning off --no-ui --no-agent --no-slots \
  --cors-origins http://127.0.0.1:18081 --no-cors-credentials \
  --api-key-file /run/secrets/inference-api-key
```

The published port accepts host-local connections only. The application can reach
the server as `http://inference:8080/v1` after joining its private Docker network.
The optional overlay preserves the application's management network and adds
this external inference network:

```sh
docker compose -f compose.yaml -f compose.inference.yaml up -d
```

Use both Compose files for subsequent container updates. A one-time
`docker network connect` is sufficient for testing but is lost when Compose
replaces the application container. Host-native testing can use
`http://127.0.0.1:18081/v1` directly.

Use the API key from `secrets/inference-api-key` when saving the provider and model
ID `qwen3-0.6b`. Do not send this key in chat. The application encrypts the provider
key in SQLite. The inference server receives only the conversation and tool
results required by configured agent operations. No built-in llama.cpp host shell
or file tools are enabled.

`curl http://127.0.0.1:18081/health` checks server readiness. It does not test tool
calling. Stop the optional server with `docker stop dirigentenstab-inference`;
remove it with `docker rm dirigentenstab-inference`. Its model and key files remain
available for an explicit restart or upgrade.

## Recorded acceptance result

The pinned server and model above passed the application's real `test_provider`
test with generated local credentials:

```json
{
  "reachable": true,
  "authenticated": true,
  "model_available": true,
  "tool_calling": true,
  "error": null
}
```

The model called a Pydantic AI `probe` function with the server-generated nonce,
received its result, and completed the response. This tests actual model tool
calling; it does not by itself certify infrastructure changes or delegation
quality. On the acceptance host, generation ran at approximately 26 tokens per
second. No commercial provider credentials or existing conversations were used.
