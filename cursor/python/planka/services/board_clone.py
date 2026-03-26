"""Create a Planka board from an existing board using plankapy.

Planka and plankapy do not expose ``Board.duplicate()`` (only ``Card.duplicate``).
This module creates a new board, recreates lists and labels, then duplicates
each card (including archived cards) onto the new board.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, cast, get_args

import httpx
from httpx import HTTPStatusError
from plankapy.v2 import Planka
from plankapy.v2.models import Board, Card, List, Project
from plankapy.v2.models._helpers import POSITION_GAP
from plankapy.v2.models._literals import Language, UserListType

logger = logging.getLogger(__name__)


class BoardCloneError(Exception):
    """Raised when board resolution or cloning cannot proceed."""


@dataclass(frozen=True)
class CloneResult:
    """Outcome of a clone operation."""

    source_board_id: str
    new_board_id: str | None
    new_board_name: str
    target_project_id: str
    target_project_name: str
    lists_copied: int
    cards_copied: int
    dry_run: bool


def parse_terms_lang(raw: str | None) -> Language | None:
    """Return a valid ``Language`` code or ``None`` if unset or invalid."""
    if not raw:
        return None
    if raw in get_args(Language):
        return cast(Language, raw)
    logger.warning("Ignoring invalid terms language %r (not a known language code)", raw)
    return None


def create_planka_client(base_url: str, *, verify_ssl: bool = True) -> Planka:
    """Build a ``Planka`` client with connect/read timeouts.

    Args:
        base_url: Planka instance base URL.
        verify_ssl: If ``False``, TLS certificate verification is disabled (insecure;
            use only with self-signed or private-CA servers you trust).

    Returns:
        Configured ``Planka`` instance (not yet logged in).

    Raises:
        BoardCloneError: If ``base_url`` is empty.
    """
    if not base_url or not base_url.strip():
        raise BoardCloneError("Planka base URL is required")
    url = base_url.strip().rstrip("/")
    timeout = httpx.Timeout(connect=5.0, read=120.0, write=30.0, pool=5.0)
    client = httpx.Client(timeout=timeout, verify=verify_ssl)
    return Planka(url, client=client)


def login_with_credentials(
    planka: Planka,
    *,
    api_key: str | None,
    username: str | None,
    password: str | None,
    accept_terms: bool,
    terms_lang: Language | None,
) -> None:
    """Authenticate with an API key or username and password.

    Secrets must be supplied by the caller; they are never read from the environment
    by this function and must not be logged.

    Args:
        planka: Client to authenticate.
        api_key: API key (preferred when set).
        username: Account username or email (used when ``api_key`` is not set).
        password: Account password (required with ``username``).
        accept_terms: Pass ``True`` if the server may require accepting terms of service.
        terms_lang: Language code for terms, when applicable.

    Raises:
        BoardCloneError: If credentials are missing or login fails.
    """
    key = (api_key or "").strip()
    user = (username or "").strip()
    pw = password or ""

    try:
        if key:
            planka.login(api_key=key)
        elif user and pw:
            try:
                planka.login(
                    username=user,
                    password=pw,
                    accept_terms=accept_terms,
                    terms_lang=terms_lang,
                )
            except KeyError as e:
                # plankapy may raise KeyError when a 403 response lacks ``pendingToken`` (e.g. SSO).
                raise BoardCloneError(
                    "Planka login failed: password login may be disabled (e.g. single sign-on "
                    "only). Create an API key in Planka and use --api-key instead of "
                    "username/password."
                ) from e
        else:
            raise BoardCloneError(
                "Authentication requires either an API key or both username and password"
            )
    except HTTPStatusError as e:
        raise BoardCloneError("Planka authentication failed (check credentials)") from e
    except PermissionError as e:
        raise BoardCloneError(str(e)) from e


def _project_by_id(planka: Planka, project_id: str) -> Project:
    for p in planka.projects:
        if p.id == project_id:
            return p
    raise BoardCloneError(f"No project with id {project_id!r}")


def _projects_by_name(planka: Planka, name: str) -> list[Project]:
    return [p for p in planka.projects if p.name == name]


def resolve_target_project(
    planka: Planka,
    *,
    project_id: str | None,
    project_name: str | None,
) -> Project:
    """Resolve the project that will own the new board.

    Args:
        planka: Logged-in client.
        project_id: Exact project id (preferred when set).
        project_name: Project name (must be unique among visible projects).

    Returns:
        Matching ``Project``.

    Raises:
        BoardCloneError: If nothing matches or the name is ambiguous.
    """
    if project_id:
        return _project_by_id(planka, project_id)
    if project_name:
        matches = _projects_by_name(planka, project_name)
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise BoardCloneError(f"No project named {project_name!r}")
        raise BoardCloneError(
            f"Multiple projects named {project_name!r}; use --target-project-id to disambiguate"
        )
    raise BoardCloneError("Internal error: target project not specified")


def resolve_source_board(
    planka: Planka,
    *,
    board_id: str | None,
    board_name: str | None,
    source_project_id: str | None,
    source_project_name: str | None,
) -> Board:
    """Resolve the template board to copy from.

    Args:
        planka: Logged-in client.
        board_id: Exact board id (preferred).
        board_name: Board title; requires a unique match within the search scope.
        source_project_id: If set, only consider boards in this project.
        source_project_name: If set (and id is not), restrict to this project name.

    Returns:
        The source ``Board``.

    Raises:
        BoardCloneError: If arguments are inconsistent or the board is not found.
    """
    if board_id:
        try:
            board = Board(planka.endpoints.getBoard(board_id)["item"], planka)
        except HTTPStatusError as e:
            if e.response.status_code == 404:
                raise BoardCloneError(f"No board with id {board_id!r}") from e
            raise BoardCloneError("Failed to load source board") from e
        if source_project_id and board.project.id != source_project_id:
            raise BoardCloneError(
                f"Board {board_id!r} belongs to project {board.project.id!r}, "
                f"not {source_project_id!r}"
            )
        if source_project_name and board.project.name != source_project_name:
            raise BoardCloneError(
                f"Board {board_id!r} belongs to project {board.project.name!r}, "
                f"not {source_project_name!r}"
            )
        return board

    if not board_name:
        raise BoardCloneError("Provide a source board id or source board name")

    if source_project_id:
        projects = [_project_by_id(planka, source_project_id)]
    elif source_project_name:
        pm = _projects_by_name(planka, source_project_name)
        if len(pm) != 1:
            raise BoardCloneError(
                f"Expected exactly one project named {source_project_name!r}, found {len(pm)}"
            )
        projects = pm
    else:
        projects = list(planka.projects)

    matches: list[Board] = []
    for project in projects:
        for b in project.boards:
            if b.name == board_name:
                matches.append(b)

    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise BoardCloneError(f"No board named {board_name!r} in the selected scope")
    raise BoardCloneError(
        f"Multiple boards named {board_name!r}; use a source board id "
        "or narrow with source project id / name"
    )


def _sorted_lists(board: Board) -> list[List]:
    """Kanban lists (active + closed) ordered by position."""
    return sorted(board.lists, key=lambda lst: lst.position)


def _cards_on_list(board: Board, list_id: str) -> list[Card]:
    """Cards belonging to a list, using only the board payload (``getBoard`` ``included``).

    Important: Do **not** use ``List.cards`` from plankapy here: that property calls
    ``GET /api/lists/{id}``, which some Planka deployments return 404 for even when
    the list appears in the board ``included`` data. ``board.cards`` is built from
    the same response without per-list fetches.
    """
    matched = [c for c in board.cards if c.schema.get("listId") == list_id]
    return sorted(matched, key=lambda c: c.position)


def _archived_cards(board: Board) -> list[Card]:
    """Cards in archive lists, derived from board ``included`` only (no ``List.cards``)."""
    archive_ids = {lst.id for lst in board.all_lists if lst.type == "archive"}
    matched = [c for c in board.cards if c.schema.get("listId") in archive_ids]
    return sorted(matched, key=lambda c: c.position)


def _sorted_labels(board: Board):
    return sorted(board.labels, key=lambda lb: lb.position)


def _clear_user_lists(board: Board) -> None:
    """Remove default active/closed lists so we can recreate the template layout."""
    to_clear = list(board.active_lists) + list(board.closed_lists)
    for lst in to_clear:
        board.remove_list(lst)


def _apply_board_settings(source: Board, target: Board) -> None:
    s = source.schema
    target.update(
        defaultView=s["defaultView"],
        defaultCardType=s["defaultCardType"],
        limitCardTypesToDefaultOne=s["limitCardTypesToDefaultOne"],
        alwaysDisplayCardCreator=s["alwaysDisplayCardCreator"],
        expandTaskListsByDefault=s["expandTaskListsByDefault"],
    )


def _recreate_labels(source: Board, target: Board) -> None:
    for lb in _sorted_labels(source):
        nl = target.create_label(name=lb.name, position="bottom", color=lb.color)
        logger.debug("Created label %s (%s)", nl.name, nl.id)


def _duplicate_cards_to_list(
    cards: list[Card],
    *,
    dest_board: Board,
    dest_list: List,
) -> int:
    """Duplicate cards using the REST API directly.

    Avoids ``Card.duplicate()`` from plankapy, which calls ``get_position(self.list.cards,
    ...)`` and forces ``GET /api/lists/{sourceListId}`` on the **source** list — the same
    per-list request that can 404 on some servers.
    """
    endpoints = dest_board.session.endpoints
    count = 0
    for i, card in enumerate(cards):
        position = (i + 1) * POSITION_GAP
        endpoints.duplicateCard(
            card.id,
            boardId=dest_board.id,
            listId=dest_list.id,
            position=position,
            name=card.name,
        )
        count += 1
    return count


def clone_board_from_template(
    *,
    source_board: Board,
    target_project: Project,
    new_name: str | None,
    dry_run: bool,
) -> CloneResult:
    """Create a new board in ``target_project`` by copying ``source_board``.

    Args:
        source_board: Board to use as template.
        target_project: Project that will contain the new board.
        new_name: Name for the new board; defaults to ``{source} (copy)``.
        dry_run: If True, log the intended action and do not call mutating APIs
            (except reads used for resolution).

    Returns:
        ``CloneResult`` describing what was done or would be done.

    Raises:
        BoardCloneError: On invalid state or API errors during cloning.
    """
    resolved_name = new_name if new_name else f"{source_board.name} (copy)"

    if dry_run:
        logger.info(
            "DRY RUN: would create board %r in project %r (%s) from board %s (%s)",
            resolved_name,
            target_project.name,
            target_project.id,
            source_board.name,
            source_board.id,
            extra={
                "target_project_id": target_project.id,
                "source_board_id": source_board.id,
                "new_board_name": resolved_name,
            },
        )
        return CloneResult(
            source_board_id=source_board.id,
            new_board_id=None,
            new_board_name=resolved_name,
            target_project_id=target_project.id,
            target_project_name=target_project.name,
            lists_copied=0,
            cards_copied=0,
            dry_run=True,
        )

    lists_src = _sorted_lists(source_board)
    archived_src = _archived_cards(source_board)

    try:
        new_board = target_project.create_board(name=resolved_name, position="top")
        new_board.sync()
        _clear_user_lists(new_board)
        _apply_board_settings(source_board, new_board)
        _recreate_labels(source_board, new_board)

        list_map: dict[str, List] = {}
        lists_copied = 0
        for sl in lists_src:
            utype = cast(UserListType, sl.type)
            nl = new_board.create_list(
                name=sl.name,
                type=cast(Literal["active", "closed"], utype),
                position="bottom",
            )
            if sl.color != nl.color:
                nl.color = sl.color
            list_map[sl.id] = nl
            lists_copied += 1

        cards_copied = 0
        for sl in lists_src:
            nl = list_map[sl.id]
            cards_copied += _duplicate_cards_to_list(
                _cards_on_list(source_board, sl.id),
                dest_board=new_board,
                dest_list=nl,
            )

        if archived_src:
            dest_archive = new_board.archive_list
            cards_copied += _duplicate_cards_to_list(
                sorted(archived_src, key=lambda c: c.position),
                dest_board=new_board,
                dest_list=dest_archive,
            )

        logger.info(
            "Created board %r id=%s in project %s (lists=%s, cards=%s)",
            new_board.name,
            new_board.id,
            target_project.id,
            lists_copied,
            cards_copied,
            extra={
                "new_board_id": new_board.id,
                "target_project_id": target_project.id,
                "lists_copied": lists_copied,
                "cards_copied": cards_copied,
            },
        )

        return CloneResult(
            source_board_id=source_board.id,
            new_board_id=new_board.id,
            new_board_name=new_board.name,
            target_project_id=target_project.id,
            target_project_name=target_project.name,
            lists_copied=lists_copied,
            cards_copied=cards_copied,
            dry_run=False,
        )
    except HTTPStatusError as e:
        raise BoardCloneError(f"Planka API error during clone: {e.response.status_code}") from e
    except httpx.RequestError as e:
        raise BoardCloneError("Network error while talking to Planka") from e


def run_clone(
    *,
    base_url: str,
    api_key: str | None,
    username: str | None,
    password: str | None,
    accept_terms: bool,
    terms_lang: Language | None,
    verify_ssl: bool = True,
    target_project_id: str | None,
    target_project_name: str | None,
    source_board_id: str | None,
    source_board_name: str | None,
    source_project_id: str | None,
    source_project_name: str | None,
    new_name: str | None,
    dry_run: bool,
) -> CloneResult:
    """Connect with explicit credentials, resolve entities, and run the clone.

    If neither ``target_project_id`` nor ``target_project_name`` is set, the
    new board is created in the same project as the source board.

    Args:
        base_url: Planka instance base URL.
        api_key: API key, or ``None`` if using username/password.
        username: Username or email when not using an API key.
        password: Password when not using an API key.
        accept_terms: Whether to accept terms of service on first login.
        terms_lang: Language for terms when applicable.
        target_project_id: Destination project id.
        target_project_name: Destination project name.
        source_board_id: Template board id.
        source_board_name: Template board name.
        source_project_id: Optional scope for name lookup / validation.
        source_project_name: Optional scope for name lookup.
        new_name: New board title.
        dry_run: Skip mutating calls when True.
        verify_ssl: Whether to verify HTTPS certificates (set ``False`` only for
            trusted lab hosts with self-signed TLS).

    Returns:
        ``CloneResult`` for the operation.

    Raises:
        BoardCloneError: On configuration or resolution errors.
    """
    planka = create_planka_client(base_url, verify_ssl=verify_ssl)
    login_with_credentials(
        planka,
        api_key=api_key,
        username=username,
        password=password,
        accept_terms=accept_terms,
        terms_lang=terms_lang,
    )

    source = resolve_source_board(
        planka,
        board_id=source_board_id,
        board_name=source_board_name,
        source_project_id=source_project_id,
        source_project_name=source_project_name,
    )

    if target_project_id or target_project_name:
        target = resolve_target_project(
            planka,
            project_id=target_project_id,
            project_name=target_project_name,
        )
    else:
        target = source.project
        logger.info(
            "Target project not specified; using the same project as the source board (%r, %s)",
            target.name,
            target.id,
            extra={"target_project_id": target.id, "same_as_source": True},
        )

    return clone_board_from_template(
        source_board=source,
        target_project=target,
        new_name=new_name,
        dry_run=dry_run,
    )
