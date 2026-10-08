# Per-repo task manifest. Run `just` (or `just --list`) to see every verb.
#
# Recipes take trailing arguments directly: `just <verb> a b`, where the
# retired form was `ward exec <verb> -- a b`.
#
# One line of comment per recipe on purpose: just reads only the LAST comment
# line above a recipe, so a wrapped description silently truncates to its tail.
#
# `ward exec` is retired. `.ward/ward.yaml` survives carrying catalog metadata
# only, because the catalog hooks upstream in agentic-os pin that exact path.

set positional-arguments

# Default target: list every available recipe.
default:
    @just --list --unsorted

# uv lock + uv sync with dev deps.
sync *ARGS:
    @uv sync --group dev "$@"

# Run the pytest suite.
test *ARGS:
    @uv run pytest "$@"

# ruff check + ruff format --check + mypy on src/ and tests/.
lint *ARGS:
    @bash scripts/ward-quality.sh check "$@"

# Download the Chromium that check-views drives (--with-deps adds its system libraries on Linux).
browser-install *ARGS:
    @uv run playwright install {{ if os() == "linux" { "--with-deps" } else { "" } }} chromium "$@"

# Render the disk and memory MCP Apps views in a real browser and assert on the DOM.
check-views *ARGS:
    @uv run pytest -m browser "$@"

# Apply ruff fixes and formatting in place.
fmt *ARGS:
    @bash scripts/ward-quality.sh format "$@"

# Run all pre-commit hooks against every file.
precommit *ARGS:
    @uv run pre-commit run --all-files "$@"

# Build the node-stats-mcp docker image locally.
build-docker *ARGS:
    @docker build -t node-stats-mcp:local . "$@"

# Prove the built image can import the production server entrypoint.
smoke-docker *ARGS:
    @docker run --rm --entrypoint python node-stats-mcp:local -c "import node_stats_mcp.server" "$@"

# Validate the trusted Forgejo OCI publisher shell contract.
check-publish *ARGS:
    @bash -n scripts/publish-image.sh "$@"

# Run the MCP server locally over streamable-HTTP on :8080.
run *ARGS:
    @uv run node-stats-mcp "$@"
