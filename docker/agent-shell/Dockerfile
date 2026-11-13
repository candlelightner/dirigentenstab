# Per-agent shell container for Dirigentenstab "Agent shells". Build on the shell host:
#   docker build -t dirigentenstab-shell:latest docker/agent-shell
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive DISABLE_AUTOUPDATER=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git sudo tmux less vim-tiny openssh-client \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# Harnesses live outside /home/dev (a persistent volume) so rebuilding the image updates them.
RUN npm install -g @openai/codex opencode-ai && npm cache clean --force
RUN HOME=/opt/claude curl -fsSL https://claude.ai/install.sh | HOME=/opt/claude bash \
    && ln -s /opt/claude/.local/bin/claude /usr/local/bin/claude && chmod -R a+rX /opt/claude
# Google Antigravity ("agy") has no public Linux installer to pin here; add it once one exists.
RUN userdel -r ubuntu 2>/dev/null; useradd -m -u 1000 -s /bin/bash dev && echo 'dev ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/dev
# Mount point of the shared logins volume; Docker copies this ownership into the empty volume on first use.
RUN install -d -o dev -g dev -m 700 /home/dev/.logins
COPY dirigentenstab.sh /etc/profile.d/dirigentenstab.sh
USER dev
WORKDIR /home/dev
ENTRYPOINT ["sleep", "infinity"]
