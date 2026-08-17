# LoopsVault

**A local, encrypted vault that lets AI coding agents use your API keys without ever seeing them.**

Status: **design complete, not yet built.** Start at [`HANDOFF.md`](HANDOFF.md).

---

## The problem

You run several projects. Each has a `.env` file holding the same handful of provider keys. That
gives you four problems at once:

- The same key is copied into many files, so rotating it means editing many files.
- Coding agents blocked from reading `.env` do not know what exists or what to do instead, so they
  waste turns writing workaround scripts.
- Agents that *can* read `.env` pull secrets into a context window that gets uploaded to a model
  API and stored in a transcript.
- One shared key across many projects means no idea which project is spending what.

## The approach

The agent never holds the key. It sends a request with a placeholder to a local daemon; the daemon
injects the real credential and forwards it upstream; the response comes back normally. The key is
never in the agent's memory, terminal, or context.

`ssh-agent` has worked this way since 1995. It holds your private key and answers challenges. No
SSH client has ever seen the key.

Alongside that, LoopsVault publishes a **plaintext catalog** of what keys exist, what each is for,
when it expires, and which projects may use it. Agents read that freely. They learn what is
available without any privileged operation.

## What makes it different

Credential-injection proxies exist. None of them do these:

- **A cross-project catalog** with purpose, owner, expiry, shape, and project scoping
- **Per-project cost attribution** on a single shared provider key, metered from the response body
- **Per-project spend caps**, which providers cannot offer on a shared key
- **Honeytokens** with a zero-false-positive alarm
- **Harness adapters** for Claude Code, Codex and OpenClaw, where a denial names the next step
  instead of dead-ending
- **Brokering for non-HTTP secrets**, where the daemon performs the operation and returns only the
  result

## Design

- **Daemon:** Rust. Runs as a background service account, so the store is protected by the kernel
  rather than by policy. Runs headless on Linux servers too.
- **App:** Swift + SwiftUI, macOS menu bar. Secure Enclave key wrapping and Touch ID.
- **Store:** encrypted SQLite, master key wrapped by a Secure Enclave key that requires a live
  fingerprint to unwrap.
- **Write-only by design:** once saved, a value is never displayed again. To change one, replace
  it.

## Platform

macOS first. Touch ID and Secure Enclave are required for the biometric path, and both are present
on Apple Silicon and on Intel Macs with the T2 chip (2018 to 2020). The daemon itself runs
anywhere Rust does.

## License

MIT. See [`LICENSE`](LICENSE).
