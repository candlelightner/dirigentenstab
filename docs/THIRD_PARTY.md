# Third-party components

Dirigentenstab's source uses the MIT license in the repository root. Dependencies retain their respective licenses; they are not relicensed by this project.

Principal components: Apache CloudStack and Apache CloudMonkey (Apache-2.0), NiceGUI (MIT), Pydantic AI and the MCP Python SDK (MIT), AsyncSSH (EPL-2.0 or GPL-2.0-or-later), cryptography (Apache-2.0 or BSD-3-Clause), httpx (BSD-3-Clause), and SQLite (public domain). Consult the license shipped with each pinned dependency and its transitive dependencies when redistributing images.

The container includes the unmodified CloudMonkey 6.6.0 binary downloaded from its Apache repository and verified by SHA-256. CloudStack is installed separately using its upstream-linked signed convenience package repository. Documentation links to upstream installation material; it does not copy and execute upstream installers.

Optional llama.cpp and model weights are separate downloads, not included in the Dirigentenstab image. Consult their respective licenses before use or redistribution.
