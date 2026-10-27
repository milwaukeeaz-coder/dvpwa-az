"""Credential authentication aligned to the Application Security STIG.

V-222542: only a per-user PBKDF2-HMAC-SHA256 verifier is stored.
V-222432: three consecutive invalid logons inside 15 minutes lock the account
for 15 minutes.
V-222606: username and password are checked for type, length, and character
set before they are used. Query values are bound parameters, so a
submitted value cannot change the SQL statement.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import sqlite3
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator, NamedTuple, Optional

logger = logging.getLogger(__name__)

DB_PATH = "users.db"

# NIST SP 800-132 / OWASP floor for PBKDF2-HMAC-SHA256. SHA-256 is a FIPS
# hash; PBKDF2 is the iterated salted construction V-222542 describes.
PBKDF2_ITERATIONS = 600_000
PBKDF2_ITERATIONS_MAX = 2_000_000
_SALT_BYTES = 16
_DIGEST_BYTES = 32
_SCHEME = "pbkdf2_sha256"

MAX_FAILED_ATTEMPTS = 3
FAILURE_WINDOW = timedelta(minutes=15)
LOCKOUT_DURATION = timedelta(minutes=15)

USERNAME_MAX_LENGTH = 64
PASSWORD_MAX_LENGTH = 128
_USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")

_CREATE_USERS = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    failed_window_start TEXT,
    locked_until TEXT
)
"""

_SELECT_USER = """
SELECT id, username, password_hash, failed_attempts, failed_window_start, locked_until
FROM users
WHERE username = ?
"""

_UPDATE_SUCCESS = """
UPDATE users
SET failed_attempts = 0,
    failed_window_start = NULL,
    locked_until = NULL
WHERE id = ?
"""

_UPDATE_FAILURE = """
UPDATE users
SET failed_attempts = ?,
    failed_window_start = ?,
    locked_until = ?
WHERE id = ?
"""

_INSERT_USER = """
INSERT INTO users (username, password_hash, failed_attempts)
VALUES (?, ?, 0)
"""


class AuthResult(NamedTuple):
    status: str
    http_status: int
    message: str


INVALID = AuthResult("invalid", 400, "Invalid username or password format.")
FAILURE = AuthResult("failure", 401, "Invalid credentials.")
LOCKED = AuthResult("locked", 423, "Account is temporarily locked.")
SUCCESS = AuthResult("success", 200, "Authenticated.")
UNAVAILABLE = AuthResult("error", 500, "Authentication is unavailable.")


def _dummy_verifier() -> str:
    return hash_password("dummy-password-not-a-credential")


def hash_password(password: str) -> str:
    """Return a salted iterated verifier. The plaintext is not retained."""
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=_DIGEST_BYTES,
    )
    encoded_salt = base64.b64encode(salt).decode("ascii")
    encoded_digest = base64.b64encode(digest).decode("ascii")
    return "$".join((_SCHEME, str(PBKDF2_ITERATIONS), encoded_salt, encoded_digest))


_DUMMY_PASSWORD_HASH = _dummy_verifier()


def verify_password(password: str, stored: str) -> bool:
    """Compare password to a stored verifier.

    The digest comparison uses secrets.compare_digest. Malformed, unsalted,
    or non-iterated values never match, so leftover plaintext and bare
    hashes are rejected.
    """
    try:
        scheme, rounds_text, salt_text, digest_text = stored.split("$")
        rounds = int(rounds_text)
        if scheme != _SCHEME or not (PBKDF2_ITERATIONS <= rounds <= PBKDF2_ITERATIONS_MAX):
            return False
        salt = base64.b64decode(salt_text, validate=True)
        expected = base64.b64decode(digest_text, validate=True)
        if len(salt) < _SALT_BYTES or len(expected) < _DIGEST_BYTES:
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            rounds,
            dklen=len(expected),
        )
    except (ValueError, UnicodeEncodeError):
        return False
    return secrets.compare_digest(actual, expected)


def _valid_username(username: object) -> bool:
    return (
        isinstance(username, str)
        and len(username) <= USERNAME_MAX_LENGTH
        and _USERNAME_RE.fullmatch(username) is not None
    )


def _valid_password(password: object) -> bool:
    if not isinstance(password, str) or not (1 <= len(password) <= PASSWORD_MAX_LENGTH):
        return False
    return all(not unicodedata.category(char).startswith("C") for char in password)


def _credentials_valid(username: object, password: object) -> bool:
    return _valid_username(username) and _valid_password(password)


def _as_utc(now: Optional[datetime]) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return now.astimezone(timezone.utc)


def _format_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@contextmanager
def _connect(db_path: str) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(db_path, timeout=5, isolation_level=None)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        # Zero deleted record bytes so a dropped plaintext password cannot
        # be recovered from a freed page.
        connection.execute("PRAGMA secure_delete = ON")
        yield connection
    finally:
        connection.close()


def _column_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("PRAGMA table_info(users)").fetchall()
    return {row["name"] for row in rows}


def _table_exists(connection: sqlite3.Connection) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        ("users",),
    ).fetchone()
    return row is not None


# Identifiers cannot be bound as parameters. These statements are fixed
# literals, never built from request data.
_ADD_COLUMNS = (
    ("password_hash", "ALTER TABLE users ADD COLUMN password_hash TEXT"),
    ("failed_attempts", "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0"),
    ("failed_window_start", "ALTER TABLE users ADD COLUMN failed_window_start TEXT"),
    ("locked_until", "ALTER TABLE users ADD COLUMN locked_until TEXT"),
)


def _add_missing_columns(connection: sqlite3.Connection, columns: set[str]) -> None:
    for name, statement in _ADD_COLUMNS:
        if name not in columns:
            connection.execute(statement)
            columns.add(name)


def _rollback(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        connection.execute("ROLLBACK")


def _migrate_plaintext(connection: sqlite3.Connection, columns: set[str]) -> None:
    """Replace a legacy plaintext password column with a salted verifier."""
    _add_missing_columns(connection, columns)

    rows = connection.execute("SELECT id, password, password_hash FROM users").fetchall()
    for row in rows:
        plaintext = row["password"]
        if not plaintext:
            continue
        verifier = row["password_hash"] or hash_password(plaintext)
        try:
            connection.execute(
                "UPDATE users SET password_hash = ?, password = NULL WHERE id = ?",
                (verifier, row["id"]),
            )
        except sqlite3.IntegrityError:
            # Some legacy schemas declare the plaintext column NOT NULL.
            # Clear it in place; the rebuild below drops the column.
            connection.execute(
                "UPDATE users SET password_hash = ?, password = ? WHERE id = ?",
                (verifier, "", row["id"]),
            )

    connection.execute(
        """
        CREATE TABLE users_compliant (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            failed_window_start TEXT,
            locked_until TEXT
        )
        """
    )
    connection.execute(
        """
        INSERT INTO users_compliant (
            id, username, password_hash, failed_attempts, failed_window_start, locked_until
        )
        SELECT id, username, password_hash, COALESCE(failed_attempts, 0),
               failed_window_start, locked_until
        FROM users
        WHERE password_hash IS NOT NULL
        """
    )
    connection.execute("DROP TABLE users")
    connection.execute("ALTER TABLE users_compliant RENAME TO users")


def _ensure_schema(connection: sqlite3.Connection) -> None:
    migrated = False
    connection.execute("BEGIN IMMEDIATE")
    try:
        if not _table_exists(connection):
            connection.execute(_CREATE_USERS)
        else:
            columns = _column_names(connection)
            if "password" in columns:
                _migrate_plaintext(connection, columns)
                migrated = True
            else:
                _add_missing_columns(connection, columns)
        connection.execute("COMMIT")
    except Exception:
        _rollback(connection)
        raise
    # VACUUM cannot run inside a transaction. It rewrites the file so
    # freed pages from the plaintext column are not left on disk.
    if migrated:
        connection.execute("VACUUM")


def _find_user(connection: sqlite3.Connection, username: str) -> Optional[sqlite3.Row]:
    return connection.execute(_SELECT_USER, (username,)).fetchone()


def _is_locked(row: sqlite3.Row, now: datetime) -> bool:
    locked_until = _parse_ts(row["locked_until"])
    return locked_until is not None and now < locked_until


def _finish(connection: sqlite3.Connection, row: sqlite3.Row, password_ok: bool, now: datetime) -> AuthResult:
    if _is_locked(row, now):
        return LOCKED

    if password_ok:
        connection.execute(_UPDATE_SUCCESS, (row["id"],))
        return SUCCESS

    window_start = _parse_ts(row["failed_window_start"])
    if window_start is None or now - window_start >= FAILURE_WINDOW:
        attempts = 1
        window_start = now
    else:
        attempts = int(row["failed_attempts"] or 0) + 1

    locked_until = None
    if attempts >= MAX_FAILED_ATTEMPTS:
        attempts = MAX_FAILED_ATTEMPTS
        locked_until = now + LOCKOUT_DURATION
        logger.warning("account locked after repeated invalid logons")

    connection.execute(
        _UPDATE_FAILURE,
        (
            attempts,
            _format_ts(window_start),
            _format_ts(locked_until) if locked_until is not None else None,
            row["id"],
        ),
    )
    if locked_until is not None:
        return LOCKED
    return FAILURE


def create_user(username: str, password: str, db_path: Optional[str] = None) -> int:
    """Store a new account. The password is hashed before it is written."""
    if db_path is None:
        db_path = DB_PATH
    if not _credentials_valid(username, password):
        raise ValueError("username or password does not meet input requirements")
    verifier = hash_password(password)
    with _connect(db_path) as connection:
        _ensure_schema(connection)
        connection.execute("BEGIN IMMEDIATE")
        try:
            cursor = connection.execute(_INSERT_USER, (username, verifier))
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            _rollback(connection)
            raise ValueError("username is already registered") from None
        except Exception:
            _rollback(connection)
            raise
        return int(cursor.lastrowid)


def authenticate(
    username: object,
    password: object,
    db_path: Optional[str] = None,
    now: Optional[datetime] = None,
) -> AuthResult:
    """Validate credentials, then apply the lockout policy.

    A correct password does not unlock an account that is still inside
    its lockout interval. Unknown usernames take the same verifier path
    and return the same failure as a wrong password.
    """
    if db_path is None:
        db_path = DB_PATH
    current_time = _as_utc(now)
    if (
        not isinstance(username, str)
        or not isinstance(password, str)
        or not _credentials_valid(username, password)
    ):
        return INVALID

    with _connect(db_path) as connection:
        _ensure_schema(connection)
        row = _find_user(connection, username)

    if row is None or not row["password_hash"]:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return FAILURE

    password_ok = verify_password(password, row["password_hash"])
    seen_hash = row["password_hash"]

    with _connect(db_path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            current = _find_user(connection, username)
            if current is None or not current["password_hash"]:
                verify_password(password, _DUMMY_PASSWORD_HASH)
                result = FAILURE
            elif _is_locked(current, current_time):
                result = LOCKED
            else:
                if current["password_hash"] != seen_hash:
                    password_ok = verify_password(password, current["password_hash"])
                result = _finish(connection, current, password_ok, current_time)
            connection.execute("COMMIT")
            return result
        except Exception:
            _rollback(connection)
            raise


def authenticate_user():
    """Flask entry point. Form fields are validated by authenticate()."""
    from flask import jsonify, request

    try:
        result = authenticate(request.form.get("username"), request.form.get("password"))
    except sqlite3.Error:
        logger.exception("authentication failed because the user database is unavailable")
        result = UNAVAILABLE
    body = {"status": result.status, "message": result.message}
    return jsonify(body), result.http_status
