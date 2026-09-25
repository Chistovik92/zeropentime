-- SPDX-License-Identifier: AGPL-3.0-only
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT OR IGNORE INTO meta(key, value) VALUES ('version', 1), ('schema', 1);

CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY,
    login      TEXT NOT NULL UNIQUE,
    pass_hash  TEXT NOT NULL,
    is_admin   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf       TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id             TEXT PRIMARY KEY,
    ed_key         BLOB NOT NULL UNIQUE,
    box_key        BLOB NOT NULL,
    name           TEXT NOT NULL,
    public_ip      TEXT NOT NULL DEFAULT '',
    udp_port       INTEGER NOT NULL DEFAULT 0,
    locals         TEXT NOT NULL DEFAULT 'null',
    client_version TEXT NOT NULL DEFAULT '',
    last_seen      INTEGER NOT NULL,
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    subnet      TEXT NOT NULL,
    secret      BLOB NOT NULL,
    sign_key    BLOB NOT NULL,
    owner_id    INTEGER NOT NULL REFERENCES users(id),
    join_policy TEXT NOT NULL DEFAULT 'manual',
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS members (
    room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    node_id    TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    wg_key     BLOB NOT NULL,
    ip         TEXT NOT NULL,
    tags       TEXT NOT NULL DEFAULT 'null',
    status     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (room_id, node_id),
    UNIQUE (room_id, ip)
);
CREATE INDEX IF NOT EXISTS members_node ON members(node_id);

CREATE TABLE IF NOT EXISTS invites (
    id           INTEGER PRIMARY KEY,
    room_id      TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    token_hash   BLOB NOT NULL UNIQUE,
    uses_left    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    auto_approve INTEGER NOT NULL DEFAULT 0,
    note         TEXT NOT NULL DEFAULT '',
    created_by   INTEGER NOT NULL,
    created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL,
    target  TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);
