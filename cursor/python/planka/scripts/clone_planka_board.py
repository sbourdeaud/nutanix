#!/usr/bin/env python3
"""CLI: create a Planka board from an existing board (template-style clone)."""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import sys
from pathlib import Path

# Allow `python scripts/clone_planka_board.py` from repo root without install
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import httpx
from httpx import HTTPStatusError

from services.board_clone import BoardCloneError, parse_terms_lang, run_clone

logger = logging.getLogger(__name__)


class _ColorFormatter(logging.Formatter):
    """ANSI colors for terminal log lines (respect ``NO_COLOR`` / ``--no-color``)."""

    _RESET = "\033[0m"
    _COLORS: dict[int, str] = {
        logging.DEBUG: "\033[36m",  # cyan
        logging.INFO: "\033[32m",  # green
        logging.WARNING: "\033[33m",  # yellow
        logging.ERROR: "\033[31m",  # red
        logging.CRITICAL: "\033[1;31m",  # bold red
    }

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: str = "%",
        *,
        use_color: bool = True,
    ) -> None:
        super().__init__(fmt, datefmt, style)
        self._use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        line = super().format(record)
        if not self._use_color:
            return line
        prefix = self._COLORS.get(record.levelno, self._RESET)
        return f"{prefix}{line}{self._RESET}"


def _stderr_supports_color() -> bool:
    return sys.stderr.isatty()


def _use_ansi_colors(explicit_no_color: bool) -> bool:
    """True unless disabled by flag, ``NO_COLOR``, or non-TTY stderr."""
    if explicit_no_color:
        return False
    if os.environ.get("NO_COLOR", "").strip():
        return False
    return _stderr_supports_color()


def _configure_logging(level: int, *, use_color: bool) -> None:
    """Configure root logging with optional colored stderr output."""
    fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(_ColorFormatter(fmt, use_color=use_color))
    logging.basicConfig(level=level, handlers=[handler], force=True)


def _interactive() -> bool:
    """True if the session can prompt on a TTY (best-effort)."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Create a new Planka board by copying lists, labels, and cards from a template board. "
            "Pass connection and clone options as arguments, or run with no / partial arguments "
            "to be prompted interactively. Passwords and API keys are never echoed; avoid passing "
            "secrets on the command line when possible (other users may see argv via process list)."
        ),
    )
    conn = p.add_argument_group("Planka connection")
    conn.add_argument(
        "--url",
        dest="base_url",
        metavar="URL",
        help="Planka base URL (e.g. https://planka.example.com)",
    )
    conn.add_argument(
        "--api-key",
        dest="api_key",
        help="API key (non-interactive automation; visible in process list)",
    )
    conn.add_argument(
        "--username",
        help="Username or email (use with password prompt or stdin; not used with --api-key)",
    )
    conn.add_argument(
        "--accept-terms",
        action="store_true",
        help="Accept terms of service on first login (username/password auth)",
    )
    conn.add_argument(
        "--terms-lang",
        metavar="CODE",
        help="Language for terms when accepting (e.g. en-US)",
    )
    conn.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS certificate verification (for self-signed/private CA HTTPS only; "
            "unsafe on untrusted networks)"
        ),
    )

    src = p.add_argument_group("source (template) board")
    src.add_argument(
        "--source-board-id",
        help="ID of the board to copy from (preferred)",
    )
    src.add_argument(
        "--source-board-name",
        help="Name of the board to copy from (must be unique in search scope)",
    )
    src.add_argument(
        "--source-project-id",
        help="If set, restrict --source-board-name lookup to this project id",
    )
    src.add_argument(
        "--source-project-name",
        help="If set, restrict --source-board-name lookup to this project name",
    )

    dst = p.add_argument_group(
        "target project (new board location; omit both to use the same project as the source board)"
    )
    dst.add_argument(
        "--target-project-id",
        help="Project id for the new board (default: source board's project)",
    )
    dst.add_argument(
        "--target-project-name",
        help="Project name for the new board (default: source board's project; must be unique if set)",
    )

    p.add_argument(
        "--new-name",
        help="Title for the new board (default: '<source name> (copy)')",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Log what would be done without creating a board",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in log output (colors also off if stderr is not a TTY or NO_COLOR is set)",
    )
    return p


def _read_password_stdin() -> str:
    """Read a single line as password from stdin (no echo; for non-interactive use)."""
    line = sys.stdin.readline()
    if not line:
        return ""
    return line.rstrip("\n\r")


def _optional_prompt_value(raw: str) -> str | None:
    """Normalize optional interactive input: empty, whitespace, or a lone '=' means 'skip'."""
    t = raw.strip()
    if not t or t == "=":
        return None
    return t


def _ensure_connection_and_auth(args: argparse.Namespace) -> None:
    """Fill ``base_url``, ``api_key``, ``username``, ``password`` via prompts or validation."""
    if args.base_url:
        args.base_url = args.base_url.strip().rstrip("/")

    if args.api_key and args.username:
        raise BoardCloneError("Use either --api-key or --username, not both")

    if _interactive():
        if not args.base_url:
            args.base_url = input("Planka base URL: ").strip().rstrip("/")

        has_key = bool(args.api_key and args.api_key.strip())
        has_user = bool(args.username and args.username.strip())

        if not has_key and not has_user:
            logger.info("Authentication: enter API key, or press Enter to use username/password")
            key = getpass.getpass("API key (optional): ")
            if key.strip():
                args.api_key = key.strip()
            else:
                args.username = input("Username or email: ").strip()
                if not args.username:
                    raise BoardCloneError("Username is required when no API key is provided")
                args.password = getpass.getpass("Password: ")
        elif has_user and not args.password:
            args.password = getpass.getpass("Password: ")

        if args.api_key:
            args.api_key = args.api_key.strip()

        uses_password = bool(args.username and args.password)
        if uses_password and not args.accept_terms:
            yn = input("Accept terms of service if the server requires it? [y/N]: ").strip().lower()
            args.accept_terms = yn in ("y", "yes")

        if uses_password and not args.terms_lang:
            lang = input("Terms language code [en-US] (Enter to skip): ").strip()
            args.terms_lang = lang or None
        return

    # Non-interactive
    if not args.base_url:
        raise BoardCloneError("Non-interactive mode requires --url")

    if args.api_key and args.api_key.strip():
        args.api_key = args.api_key.strip()
        return

    if args.username and args.username.strip():
        args.username = args.username.strip()
        if args.password is None:
            if sys.stdin.isatty():
                args.password = getpass.getpass("Password: ")
            else:
                args.password = _read_password_stdin()
        if not args.password:
            raise BoardCloneError(
                "Non-interactive username login requires a password (pipe one line to stdin)"
            )
        return

    raise BoardCloneError(
        "Non-interactive mode requires --api-key or both --username and a password "
        "(pipe password as one line on stdin)"
    )


def _ensure_clone_targets(args: argparse.Namespace) -> None:
    """Ensure source board and optional fields are set; prompt if interactive."""
    if _interactive():
        if not args.source_board_id and not args.source_board_name:
            bid = _optional_prompt_value(
                input("Source board id (leave empty to search by name): ")
            )
            if bid:
                args.source_board_id = bid
            else:
                sn = _optional_prompt_value(input("Source board name: "))
                args.source_board_name = sn or ""
                if not args.source_board_name:
                    raise BoardCloneError("A source board id or name is required")

        if args.source_board_name and not args.source_project_id and not args.source_project_name:
            spid = _optional_prompt_value(
                input("Restrict search to source project id (optional, Enter to skip): ")
            )
            if spid:
                args.source_project_id = spid
            else:
                spn = _optional_prompt_value(
                    input(
                        "Restrict search to source project name (optional, Enter to skip): "
                    )
                )
                if spn:
                    args.source_project_name = spn

        # Target project: default is the source board's project (handled in run_clone).
        # Pass --target-project-id / --target-project-name only to clone into a different project.

        if not args.new_name:
            nn = _optional_prompt_value(
                input(
                    "New board name (optional, Enter for default '<source> (copy)'): "
                )
            )
            if nn:
                args.new_name = nn
        return

    if not args.source_board_id and not args.source_board_name:
        raise BoardCloneError(
            "Non-interactive mode requires --source-board-id or --source-board-name"
        )


def main() -> int:
    args = _build_parser().parse_args()
    log_level = getattr(logging, args.log_level)
    _configure_logging(
        log_level,
        use_color=_use_ansi_colors(explicit_no_color=args.no_color),
    )

    # Password is never a CLI flag (avoid argv leakage); set only after prompts.
    args.password = None

    try:
        _ensure_connection_and_auth(args)
        _ensure_clone_targets(args)
    except BoardCloneError as e:
        logger.error("%s", e)
        return 2

    terms_lang = parse_terms_lang(args.terms_lang)

    if args.insecure:
        logger.warning(
            "TLS certificate verification is disabled (--insecure); use only for trusted servers"
        )

    try:
        result = run_clone(
            base_url=args.base_url,
            api_key=args.api_key if args.api_key else None,
            username=args.username if args.username else None,
            password=args.password,
            accept_terms=bool(args.accept_terms),
            terms_lang=terms_lang,
            verify_ssl=not args.insecure,
            target_project_id=args.target_project_id,
            target_project_name=args.target_project_name,
            source_board_id=args.source_board_id,
            source_board_name=args.source_board_name,
            source_project_id=args.source_project_id,
            source_project_name=args.source_project_name,
            new_name=args.new_name if args.new_name else None,
            dry_run=args.dry_run,
        )
    except BoardCloneError as e:
        logger.error("%s", e)
        return 1
    except httpx.ConnectError as e:
        logger.error("Cannot connect to Planka: %s", e)
        err = str(e).lower()
        if "certificate" in err or "ssl" in err:
            logger.error(
                "TLS verification failed. For a self-signed or internal CA certificate, "
                "retry with --insecure (only if you trust this host)."
            )
        return 1
    except HTTPStatusError as e:
        code = e.response.status_code
        logger.error("Planka HTTP error: %s", code)
        if code == 404:
            logger.error(
                "A requested resource was not found (list, board, or project). "
                "Refresh the board in the Planka UI and retry; if it persists, the server "
                "data may be inconsistent."
            )
        return 1

    if result.dry_run:
        logger.info(
            "Dry run finished; would create board %r in project %s",
            result.new_board_name,
            result.target_project_id,
        )
    else:
        logger.info(
            "Clone finished: new board id=%s name=%r (lists=%s, cards=%s)",
            result.new_board_id,
            result.new_board_name,
            result.lists_copied,
            result.cards_copied,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
