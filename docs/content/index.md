---
title: "bwssh"
description: "Bitwarden-backed SSH agent for Linux"
---

::u-page-hero{class="hero-animate"}
---
title: "Bitwarden-backed SSH agent for Linux"
description: "Keep SSH keys in Bitwarden and sign through a local agent. bwssh uses polkit for approvals, systemd for lifecycle, and speaks the OpenSSH agent protocol."
---
<div class="hero-links">
  <a class="hero-link" href="/getting-started/introduction">
    Get started <span class="hero-link-arrow">&rarr;</span>
  </a>
  <a class="hero-link" href="/guide/configuration">
    View configuration <span class="hero-link-arrow">&rarr;</span>
  </a>
</div>
::

::u-page-section
---
title: "At a glance"
description: "A clean setup flow and a predictable socket path."
---
::::u-page-card{title="CLI quickstart" icon="i-heroicons-command-line"}
```bash
uv sync
uv run bwssh install --user-systemd
uv run bwssh start
uv run bwssh unlock
```
::::
::::u-page-card{title="SSH_AUTH_SOCK" icon="i-heroicons-link"}
```bash
export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/bwssh/agent.sock
ssh -T git@github.com
```
::::
::

::u-page-section
---
title: "Security-first defaults"
description: "Process-aware prompts and forwarding protection are built in."
---
:::u-page-feature{title="Process-aware approvals" icon="i-heroicons-identification"}
Sign requests include pid, executable path, and command line details in polkit.
:::
:::u-page-feature{title="Forwarding guardrails" icon="i-heroicons-shield-exclamation"}
Block forwarded agent requests by default to reduce abuse.
:::
:::u-page-feature{title="In-memory keys" icon="i-heroicons-lock-closed"}
Private key material stays in memory for the daemon lifetime only.
:::
::

::u-page-section
---
title: "How it works"
---
<div class="grid gap-6 lg:grid-cols-3">
  <div class="rounded-2xl border border-neutral-200/70 dark:border-neutral-800/70 bg-white/70 dark:bg-neutral-950/40 p-6 backdrop-blur">
    <p class="text-sm font-semibold text-emerald-700 dark:text-emerald-300">1. Connect</p>
    <p class="mt-2 text-base text-neutral-700 dark:text-neutral-200">
      OpenSSH connects to the bwssh agent socket instead of reading keys from disk.
    </p>
  </div>
  <div class="rounded-2xl border border-neutral-200/70 dark:border-neutral-800/70 bg-white/70 dark:bg-neutral-950/40 p-6 backdrop-blur">
    <p class="text-sm font-semibold text-emerald-700 dark:text-emerald-300">2. Approve</p>
    <p class="mt-2 text-base text-neutral-700 dark:text-neutral-200">
      polkit prompts include process metadata so you know who is requesting access.
    </p>
  </div>
  <div class="rounded-2xl border border-neutral-200/70 dark:border-neutral-800/70 bg-white/70 dark:bg-neutral-950/40 p-6 backdrop-blur">
    <p class="text-sm font-semibold text-emerald-700 dark:text-emerald-300">3. Sign</p>
    <p class="mt-2 text-base text-neutral-700 dark:text-neutral-200">
      The daemon signs using Bitwarden-held keys and returns the signature to SSH.
    </p>
  </div>
</div>
::

::u-page-section
---
title: "Integrations"
description: "Designed to match the tools you already use."
---
:::u-page-feature{title="Bitwarden CLI" icon="i-heroicons-key"}
Fetch SSH key material directly from your vault items.
:::
:::u-page-feature{title="systemd user services" icon="i-heroicons-cpu-chip"}
Start on login with standard user units and socket activation.
:::
:::u-page-feature{title="polkit policy" icon="i-heroicons-shield-check"}
Approve sign requests with rich context and caching modes.
:::
::
