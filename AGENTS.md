# Dave — Agent Guide

> Start here if you're an LLM agent working on this project.

## What is Dave?

Dave is a **multi-protocol document server** implemented as a Ruby gem mono-repo. It provides both WebDAV (HTTP) and SMB2 (native file sharing) access to the same underlying storage through shared pluggable providers.

| Gem | Module | Purpose |
|-----|--------|---------|
| `dave-server` | `Dave::Server` | WebDAV Rack application — parses WebDAV requests, routes to providers, generates responses. Also defines shared interfaces (`FileSystemInterface`, `SecurityInterface`, `Resource`, `Principal`). |
| `dave-filesystem` | `Dave::FileSystemProvider` | Default storage backend — wraps local filesystem |
| `dave-security` | `Dave::SecurityConfiguration` | Default auth/authz — YAML config with bcrypt passwords and path ACLs |
| `samba-dave` | `SambaDave::Server` | SMB2 TCP server — binary protocol, NTLM auth, file sharing via native OS clients (Finder, Explorer) |

## Quick Orientation

```
dave/
├── AGENTS.md              ← YOU ARE HERE
├── CLAUDE.md              ← Symlink to this file
├── README.md              ← Human-friendly overview
├── docs/
│   ├── WEBDAV-SPEC.md     ← WebDAV RFC 4918 distilled reference
│   ├── SMB-SPEC.md        ← SMB2 protocol distilled reference
│   ├── IMPLEMENTATION-PLAN.md ← WebDAV build plan (phases, interfaces, agent workflow)
│   ├── SAMBA-DAVE-IMPLEMENTATION-PLAN.md ← SMB build plan (phases, auth, architecture)
│   └── ARCHITECTURE.md    ← System design, gem boundaries, multi-protocol data flow
├── dave-server/           ← WebDAV Rack app + shared interface definitions
│   ├── README.md
│   ├── docs/
│   ├── lib/dave/server.rb
│   └── spec/
├── dave-filesystem/       ← Default filesystem provider (shared by WebDAV + SMB)
│   ├── README.md
│   ├── docs/
│   ├── lib/dave/file_system_provider.rb
│   └── spec/
├── dave-security/         ← Default security provider (shared by WebDAV + SMB)
│   ├── README.md
│   ├── docs/
│   ├── lib/dave/security_configuration.rb
│   └── spec/
└── samba-dave/            ← SMB2 TCP server
    ├── README.md
    ├── lib/samba_dave/server.rb
    └── spec/
```

## What to Read When

| Task | Read |
|------|------|
| Understanding the WebDAV protocol | `docs/WEBDAV-SPEC.md` |
| Understanding the SMB2 protocol | `docs/SMB-SPEC.md` |
| Planning WebDAV work | `docs/IMPLEMENTATION-PLAN.md` |
| Planning SMB work | `docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md` |
| Understanding system design | `docs/ARCHITECTURE.md` |
| Working on the WebDAV server | `dave-server/README.md` + `dave-server/docs/` |
| Working on the SMB server | `samba-dave/README.md` + `docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md` |
| Working on filesystem provider | `dave-filesystem/README.md` + `dave-filesystem/docs/` |
| Working on security provider | `dave-security/README.md` + `dave-security/docs/` |

## Key Design Decisions

1. **Pluggable providers** — FileSystem and Security are interfaces. Default implementations provided but replaceable.
2. **No global state** — everything scoped to `Dave::Server` instance
3. **Pure Rack** — no framework dependencies. Mountable in Rails, Hanami, or standalone.
4. **Compliance test suites** — provider implementers include shared RSpec examples to verify their implementation.
5. **Thread-safe** — designed for concurrent request handling (Puma, etc.)

## Development

```bash
# Run all tests
cd dave-server && bundle exec rspec
cd dave-filesystem && bundle exec rspec
cd dave-security && bundle exec rspec

# Or from root with the Rakefile
bundle exec rake spec
```

## Implementation Status

### WebDAV (dave-server) — `docs/IMPLEMENTATION-PLAN.md`

| Phase | Status | Description |
|-------|--------|-------------|
| 0 | 🚧 | Project skeleton |
| 1 | ✅ | Core read/write (GET, PUT, DELETE, MKCOL, HEAD) |
| 2 | ✅ | Properties (PROPFIND, PROPPATCH) |
| 3 | ✅ | Namespace ops (COPY, MOVE) |
| 4 | ✅ | Locking (LOCK, UNLOCK) |
| 5 | ✅ | Authentication & authorisation |
| 6 | ✅ | Compliance & hardening |

### SMB (samba-dave) — `docs/SAMBA-DAVE-IMPLEMENTATION-PLAN.md`

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | 🔲 | TCP skeleton + dialect negotiation |
| 2 | 🔲 | Authentication (NTLM + SPNEGO) |
| 3 | 🔲 | Tree connect + directory listing |
| 4 | 🔲 | Read/write file operations |
| 5 | 🔲 | Client compatibility (Windows/macOS) |
| 6 | 🔲 | Hardening + SMB 2.1 dialect |

## Agent Workflow

See `docs/IMPLEMENTATION-PLAN.md` § Multi-Agent TDD Workflow for the full process.

### Invocation

All coding agents MUST be invoked via the **Claude Code CLI** (not as OpenClaw subagents) to get plugin access:

```bash
claude --print --permission-mode bypassPermissions --model <model> -p "<task prompt>"
```

### Required Plugins

Installed at `~/.claude/plugins/cache/claude-plugins-official/superpowers/5.0.2/`:

| Plugin Skill | Requirement |
|-------------|-------------|
| `test-driven-development` | **MANDATORY** — no production code without failing test first |
| `subagent-driven-development` | **PRIMARY workflow** — dispatch per task with two-stage review |
| `writing-plans` | Use for planning phases |
| `dispatching-parallel-agents` | Use for concurrent story execution |
| `finishing-a-development-branch` | Use before completing any branch |
| `verification-before-completion` | Use before marking any task done |

**Code Review Plugin:** Run `/code-review` after each story branch (4 parallel reviewers, ≥80 confidence gate).

### Process

1. **Planner** breaks phase into stories (uses `writing-plans` skill)
2. **Developer** implements via `subagent-driven-development` + strict `test-driven-development`
3. **Tester** writes integration tests and runs compliance suites
4. **Code Review** via `/code-review` — resolve all ≥80 confidence issues before merge
