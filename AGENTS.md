---
ward:
  workflow: merge-remote-main
---
# Agent instructions

Workspace conventions load globally via `~/.claude/CLAUDE.md`. This file covers only what is specific to this repo.

## Scope

A single tiny Python service: a FastMCP server (`src/node_stats_mcp/server.py`) wrapping `psutil` reads as MCP tools, served over streamable-HTTP.

## Project shape

No frontend, no database, no in-game mods. `src/node_stats_mcp/` holds the server and its entrypoint; `tests/` covers the tool logic and the file-read security envelope. One image, one process.

## Repo boundaries

The deploy surface lives in [coilyco-bridge/deploy](https://forgejo.coilysiren.me/coilyco-bridge/deploy) `services/node-stats-mcp`, not here (source -> deploy layer invariant). This repo builds and publishes the image; the deploy repo rolls it.

## Commands

Route every command through just, never bare `uv` / `pytest`. Verbs are declared in the [`justfile`](justfile). Run them as `just <verb>`.

## Validation

`just lint` (ruff + ruff-format + mypy) and `just test` (pytest). `just check-views` renders the MCP Apps views in a real browser (needs `just browser-install` once). `just precommit` runs the full pre-commit suite, including the agentic-os catalog hooks. Validate before pushing.

## Safety

- **Every tool is read-only.** Never add a tool that writes, restarts, or mutates the host. Mutation belongs to operator surfaces, not this MCP.
- **File reads stay prefix-allowlisted.** `stat_path` / `read_text_head` resolve the real path and refuse anything outside `NODE_STATS_READABLE_ROOTS`. Keep that check on any new file-touching tool - never accept a raw path and open it.
- **Node view depends on the deployment.** Process and network tools reflect the node only when the pod runs hostPID + hostNetwork; say so in the tool docstring rather than assuming it.

## Cross-repo contracts

The image is published privately to
`forgejo.coilysiren.me/coilyco-flight-deck/node-stats-mcp:<full-source-sha>` by
[`.forgejo/workflows/build-publish.yml`](.forgejo/workflows/build-publish.yml)
on every push to main. The `test` job also runs on pull requests to main, and `publish` runs only from `main`, for any event. The trusted publisher uses a package-write credential.
The deploy repo receives only the package-read credential and rolls the same
immutable reference. Keep the dependency surface tiny (psutil + mcp). A new
dependency needs a reason.

## Release

Push to main. CI tests, publishes one source-SHA image to Forgejo OCI, and
proves the remote manifest exists. There is no version bump or moving tag.
Deferred cleanup gets a Forgejo issue, never a silent skip.

## Agent rules

<!-- BEGIN managed by agentic-os/scripts/apply-git-workflow.py -->
### Git workflow

**This repo runs the `merge-remote-main` lane**, declared as `ward.workflow` in this file's frontmatter. The agent commits, pushes straight to `main`, and closes the issue. Pushing `main` here is the expected path, not an escalation.

The fleet runs two lanes, and both authorize the same core actions:

* `merge-remote-main` - the agent commits, pushes to `main`, and closes the issue. No branch and no pull request.
* `pull-request-and-merge` - the agent commits to a task branch, pushes it, opens a pull request, and merges that pull request itself once it is green.

**Every lane slug names what the AGENT does, never what someone else does.** `pull-request-and-merge` carries the merge because the agent that authored the code merges its own pull request. `pull-request` drops `-and-merge` because the author stops at the pull request and the director merge lane takes over. Reading `pull-request-and-merge` as "someone else merges it later" inverts the two lanes and leaves finished work sitting unmerged.

**These actions are pre-authorized on every lane, and the agent MUST take them without asking first.** Committing, creating a branch, pushing a branch, pushing the lane's own destination, and opening a pull request are ordinary reversible work, not the destructive wall that earns a question. Stopping to ask is how a turn ends with the work stranded in a dirty worktree.

* **ALWAYS commit** in-scope work and **ALWAYS push** it to the canonical remote before pausing, reporting a checkpoint, handing off, or ending a turn. A local-only commit is not a checkpoint.
* **ALWAYS open the pull request** in the same turn as the branch's first push, on every lane except `remote-branch-only`. A pushed branch with no pull request is litter nobody reviews.
* **NEVER `--no-verify`** and **NEVER force-push**. Those two are the real walls, and they stay closed.
* **ALWAYS merge your own pull request on `pull-request-and-merge`**, in the same turn, as soon as it is green. Reporting it as open and awaiting someone is the failure this lane exists to prevent.
* **NEVER merge on `pull-request` or `remote-branch-only`.** Those two stop where they stop, and the director merge lane carries a `pull-request` from there.
<!-- END managed by agentic-os/scripts/apply-git-workflow.py -->

Name the actor in action sentences.

## Checkout residency

This repo is not in Agent Compose's `repository-plan.yaml`, so it has no
resident checkout under `~/projects/<owner>/`. That is intentional. Work it
from a task-scoped temporary clone, and remove that clone once the work lands.

A temporary root can be purged at any time, so commit and push before pausing,
switching tasks, or ending a session. The remote is the only durable artifact.

## See also

- [README.md](README.md) - human-facing intro.
- [docs/FEATURES.md](docs/FEATURES.md) - inventory of what ships today.
- [.ward/ward.yaml](.ward/ward.yaml) - allowlisted commands + catalog block.

Cross-reference convention from [features-release-tooling.md](docs/features-release-tooling.md).
