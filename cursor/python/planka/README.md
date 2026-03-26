# Planka board clone

Small CLI tool to **create a new board on your [Planka](https://github.com/plankanban/planka) instance** by copying an existing board: lists, labels, and cards (including cards in the archive list). It uses [plankapy](https://pypi.org/project/plankapy/) (v2) to talk to the Planka API.

## How it works

Planka’s API and plankapy expose **per-card** duplication (`Card.duplicate`), not a single “duplicate board” call. This script therefore:

1. Creates an empty board in the target project.
2. Clears the default lists Planka creates, then recreates lists and labels to match the template.
3. Duplicates each card into the matching list (and archived cards into the new board’s archive list).

Card membership is taken from the board’s `getBoard` payload (grouping by `listId`), not from per-list API calls. That avoids `GET /api/lists/{id}` calls that some servers reject even when the list id is valid on the board.

The new board’s title defaults to `<source name> (copy)` unless you pass `--new-name`.

## Requirements

- **Python 3.13+**
- Network access to your Planka server
- A Planka user with permission to read the source board and create boards in the target project (typically project manager on that project)

## Installation

From the repository root:

```bash
python3.13 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

Alternatively, install dependencies only:

```bash
pip install plankapy
```

## Configuration and secrets

There is **no** `.env` file or dotenv loading. You provide everything via **arguments** or **interactive prompts**.

- **Passwords and API keys** are read with `getpass` when prompting (nothing is echoed). They are **not** logged.
- **Avoid** passing `--api-key` on the command line in shared environments: other users can often see process arguments. Prefer interactive prompts, or use `--api-key` only in locked-down automation.

### Connection options

| Argument | Description |
|----------|-------------|
| `--url` | Planka base URL (e.g. `https://planka.example.com`) |
| `--api-key` | API key (non-interactive; visible in process list on some systems) |
| `--username` | Username or email (use with password via prompt or stdin; do not combine with `--api-key`) |
| `--accept-terms` | Accept terms of service on first login (username/password) |
| `--terms-lang` | Language code for terms (e.g. `en-US`) |
| `--insecure` | Disable TLS certificate verification (see **TLS / self-signed HTTPS** below) |

### Interactive mode

If you run the script from a terminal **without** the required values, it will prompt for:

1. Planka base URL (if `--url` omitted)
2. API key **or** username/password (secrets via `getpass`)
3. Whether to accept terms (username/password only), and optional terms language
4. Source board (id, or name plus optional project scope)
5. Optional target project and new board name

Run with no arguments to walk through everything:

```bash
python scripts/clone_planka_board.py
```

### Non-interactive mode (automation / CI)

A TTY is required for hidden prompts. Without it, you must pass at least:

- `--url`
- Either `--api-key`, **or** `--username` with **one line of password on stdin** (no prompt)

Example (`password.txt` must contain a single line with the password):

```bash
python scripts/clone_planka_board.py \
  --url https://planka.example.com \
  --username user@example.com \
  --source-board-id 1234567890 \
  < password.txt
```

Using an API key only (no stdin password):

```bash
python scripts/clone_planka_board.py \
  --url https://planka.example.com \
  --api-key "$PLANKA_API_KEY" \
  --source-board-id 1234567890 \
  --dry-run
```

## Usage

Run from the project root (the script adds the project root to `sys.path` so `services` imports work):

```bash
python scripts/clone_planka_board.py --help
```

### Source board

You must identify the template board **either** by id **or** by name:

- `--source-board-id <id>` — preferred, unambiguous.
- `--source-board-name <name>` — must match exactly one board in the search scope (see below).

### Other clone options

| Argument | Description |
|----------|-------------|
| `--source-project-id` / `--source-project-name` | Narrow `--source-board-name` to a single project when the name could match multiple boards. |
| `--target-project-id` / `--target-project-name` | Where to create the new board. **Default:** same project as the source board (omit both flags). Interactive mode does not ask for a target project; use these flags only to clone into another project. |
| `--new-name` | Title for the new board (default: `<source name> (copy)`). |
| `--dry-run` | Log what would happen; **no** board is created. |
| `--log-level` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` (default: `INFO`). |
| `--no-color` | Plain text logs (no ANSI colors). Colors are also off if `stderr` is not a TTY or the `NO_COLOR` environment variable is set. |

On a color-capable terminal, log lines are tinted: **INFO** (and **DEBUG** as cyan), **WARNING** yellow, **ERROR** / **CRITICAL** red.

### Examples

Interactive (prompts for URL, credentials, and source board):

```bash
python scripts/clone_planka_board.py
```

Dry run with explicit arguments:

```bash
python scripts/clone_planka_board.py \
  --url https://planka.example.com \
  --api-key YOUR_KEY \
  --source-board-id 1234567890 \
  --dry-run
```

Create the copy for real, same project as the source:

```bash
python scripts/clone_planka_board.py \
  --url https://planka.example.com \
  --api-key YOUR_KEY \
  --source-board-id 1234567890
```

Create in another project by name:

```bash
python scripts/clone_planka_board.py \
  --url https://planka.example.com \
  --api-key YOUR_KEY \
  --source-board-name "Sprint template" \
  --source-project-name "My team" \
  --target-project-name "Other project" \
  --new-name "Sprint 42"
```

## TLS / self-signed HTTPS

If you see `CERTIFICATE_VERIFY_FAILED` or `self-signed certificate in certificate chain`, Python does not trust your server’s TLS certificate (common for internal hostnames like `planka.company.local`).

**Preferred:** Install your organization’s root CA into the system or Python trust store so verification succeeds without disabling TLS.

**Quick workaround (lab only):** pass `--insecure` to skip certificate verification. This is **unsafe** on untrusted networks; only use for hosts you fully trust.

```bash
python scripts/clone_planka_board.py --url https://planka.example.local --insecure ...
```

## Troubleshooting

- **Authentication errors**: Check URL, API key or username/password, and use `--accept-terms` (or the interactive prompt) if Planka requires terms acceptance on first login.
- **TLS / certificate errors**: See **TLS / self-signed HTTPS** above, or use `--insecure` for trusted internal servers with self-signed certs.
- **403 / “Use single sign-on” / password login fails**: Your Planka may allow only SSO for the web UI. Use a **personal API key** from Planka (account settings) with `--api-key` instead of `--username` / password.
- **404 during clone**: A list or related object returned 404 (often stale or deleted list data). Reload the board in the browser and retry; if it persists, the template board may need a quick edit/save in Planka to refresh metadata.
- **Ambiguous board or project name**: Use `--source-board-id` or `--target-project-id` instead of names.
- **Non-interactive failures**: Ensure `--url` is set and you use `--api-key` or pipe a one-line password when using `--username`.
- **Large boards**: Cloning issues one API request per card; timeouts are set generously on the HTTP client, but very large boards may take a while.

## Project layout

| Path | Role |
|------|------|
| `scripts/clone_planka_board.py` | CLI entry point |
| `services/board_clone.py` | Connection, resolution, and clone logic |

## License

This project uses dependencies that are AGPL-licensed (e.g. plankapy). Check your compliance obligations when distributing or combining this tool with other software.
