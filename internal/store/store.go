// SPDX-License-Identifier: AGPL-3.0-only

// Package store is the controller database (SQLite, pure Go, no CGO).
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schema string

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the database.
type Store struct {
	db *sql.DB
}

// Open opens (and creates or migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows one writer; a single connection avoids SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrations upgrade the base schema (schema.sql, version 1). Entry i
// brings the database to version i+2. Never edit an entry once released.
var migrations = []string{
	// 2 (0.2.0): how nodes are seen from the internet.
	`ALTER TABLE nodes ADD COLUMN nat_type  TEXT NOT NULL DEFAULT '';
	 ALTER TABLE nodes ADD COLUMN reflexive TEXT NOT NULL DEFAULT 'null';
	 ALTER TABLE nodes ADD COLUMN portmap   TEXT NOT NULL DEFAULT '';`,
	// 3 (0.2.1): path discovery between nodes.
	`ALTER TABLE nodes ADD COLUMN disco_key BLOB;`,
	// 4 (0.2.2): relay.
	`CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL);
	 ALTER TABLE nodes ADD COLUMN relay TEXT NOT NULL DEFAULT '';
	 CREATE INDEX nodes_disco ON nodes(disco_key);`,
	// 5 (0.2.3): LAN broadcast sharing per room.
	`ALTER TABLE rooms ADD COLUMN broadcast TEXT NOT NULL DEFAULT 'on';`,
	// 6 (0.3.0): subnet routers — offered by nodes, approved per member.
	`ALTER TABLE nodes ADD COLUMN routes TEXT NOT NULL DEFAULT 'null';
	 ALTER TABLE members ADD COLUMN routes TEXT NOT NULL DEFAULT 'null';`,
	// 7 (0.3.1): exit nodes — offered by nodes, approved per member; the
	// exit a room admin picked for a member.
	`ALTER TABLE nodes ADD COLUMN exit_offer INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE members ADD COLUMN exit INTEGER NOT NULL DEFAULT 0;
	 ALTER TABLE members ADD COLUMN use_exit TEXT NOT NULL DEFAULT '';`,
	// 8 (0.3.2): the exit node answers DNS queries of its users.
	`ALTER TABLE nodes ADD COLUMN exit_dns INTEGER NOT NULL DEFAULT 0;`,
	// 9 (0.3.4): the room's own DNS servers.
	`ALTER TABLE rooms ADD COLUMN dns TEXT NOT NULL DEFAULT 'null';`,
}

// SchemaVersion is the version a fully migrated database has.
var SchemaVersion = 1 + len(migrations)

func migrate(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`SELECT value FROM meta WHERE key = 'schema'`).Scan(&v); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if v > SchemaVersion {
		return fmt.Errorf("database schema %d is newer than this controller supports (%d): update zpt-controller", v, SchemaVersion)
	}
	for ; v < SchemaVersion; v++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v-1]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate schema to %d: %w", v+1, err)
		}
		if _, err := tx.Exec(`UPDATE meta SET value = ? WHERE key = 'schema'`, v+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Tx runs fn in a transaction.
func (s *Store) Tx(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(&Tx{tx: tx}); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Tx is a database transaction.
type Tx struct{ tx *sql.Tx }

// Read runs fn in a transaction that is always rolled back.
func (s *Store) Read(ctx context.Context, fn func(*Tx) error) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return fn(&Tx{tx: tx})
}

func now() int64 { return time.Now().Unix() }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ---- meta ----

// BumpVersion increments and returns the global change counter.
func (t *Tx) BumpVersion() (int64, error) {
	var v int64
	err := t.tx.QueryRow(`UPDATE meta SET value = value + 1 WHERE key = 'version' RETURNING value`).Scan(&v)
	return v, err
}

// Version returns the global change counter.
func (t *Tx) Version() (int64, error) {
	var v int64
	err := t.tx.QueryRow(`SELECT value FROM meta WHERE key = 'version'`).Scan(&v)
	return v, err
}

// ---- users ----

type User struct {
	ID       int64
	Login    string
	PassHash string
	IsAdmin  bool
	Created  time.Time
}

func (t *Tx) CreateUser(login, passHash string, admin bool) (int64, error) {
	res, err := t.tx.Exec(`INSERT INTO users(login, pass_hash, is_admin, created_at) VALUES(?,?,?,?)`, login, passHash, admin, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var created int64
	if err := row.Scan(&u.ID, &u.Login, &u.PassHash, &u.IsAdmin, &created); err != nil {
		return nil, notFound(err)
	}
	u.Created = time.Unix(created, 0)
	return &u, nil
}

const userCols = `id, login, pass_hash, is_admin, created_at`

func (t *Tx) UserByLogin(login string) (*User, error) {
	return scanUser(t.tx.QueryRow(`SELECT `+userCols+` FROM users WHERE login = ?`, login))
}

func (t *Tx) UserByID(id int64) (*User, error) {
	return scanUser(t.tx.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (t *Tx) ListUsers() ([]User, error) {
	rows, err := t.tx.Query(`SELECT ` + userCols + ` FROM users ORDER BY login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (t *Tx) CountUsers() (int, error) {
	var n int
	err := t.tx.QueryRow(`SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func (t *Tx) SetPassword(id int64, passHash string) error {
	_, err := t.tx.Exec(`UPDATE users SET pass_hash = ? WHERE id = ?`, passHash, id)
	return err
}

func (t *Tx) DeleteUser(id int64) error {
	_, err := t.tx.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// ---- sessions ----

type Session struct {
	UserID  int64
	CSRF    string
	Expires time.Time
}

func (t *Tx) CreateSession(tokenHash []byte, userID int64, csrf string, expires time.Time) error {
	_, err := t.tx.Exec(`INSERT INTO sessions(token_hash, user_id, csrf, expires_at) VALUES(?,?,?,?)`, tokenHash, userID, csrf, expires.Unix())
	return err
}

func (t *Tx) SessionByToken(tokenHash []byte) (*Session, error) {
	var s Session
	var exp int64
	err := t.tx.QueryRow(`SELECT user_id, csrf, expires_at FROM sessions WHERE token_hash = ?`, tokenHash).Scan(&s.UserID, &s.CSRF, &exp)
	if err != nil {
		return nil, notFound(err)
	}
	s.Expires = time.Unix(exp, 0)
	return &s, nil
}

func (t *Tx) DeleteSession(tokenHash []byte) error {
	_, err := t.tx.Exec(`DELETE FROM sessions WHERE token_hash = ? OR expires_at < ?`, tokenHash, now())
	return err
}

// ---- nodes ----

type Node struct {
	ID        string
	EdKey     []byte
	BoxKey    []byte
	Name      string
	PublicIP  netip.Addr
	UDPPort   uint16
	Locals    []netip.AddrPort
	Version   string
	LastSeen  time.Time
	CreatedAt time.Time
	// Reachability reported by the node (netcheck, port mapping).
	NAT       string
	Reflexive []netip.AddrPort
	PortMap   netip.AddrPort
	DiscoKey  []byte
	Relay     string
	Routes    []netip.Prefix // offered by the node
	Exit      bool           // offers to be an exit node
	ExitDNS   bool           // as an exit, answers DNS on its room address
}

// Reach is what a node reports about how it can be reached.
type Reach struct {
	PublicIP  netip.Addr
	UDPPort   uint16
	Locals    []netip.AddrPort
	Reflexive []netip.AddrPort
	NAT       string
	PortMap   netip.AddrPort
	DiscoKey  []byte
	Relay     string
	Routes    []netip.Prefix
	Exit      bool
	ExitDNS   bool
	Version   string
}

func (t *Tx) UpsertNode(n *Node) error {
	_, err := t.tx.Exec(`INSERT INTO nodes(id, ed_key, box_key, name, public_ip, udp_port, locals, client_version, last_seen, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET box_key = excluded.box_key, name = excluded.name, last_seen = excluded.last_seen`,
		n.ID, n.EdKey, n.BoxKey, n.Name, addrString(n.PublicIP), n.UDPPort, jsonString(n.Locals), n.Version, now(), now())
	return err
}

// UpdateNodeEndpoints records where the node can be reached. It reports
// whether anything peers care about changed.
func (t *Tx) UpdateNodeEndpoints(id string, r Reach) (bool, error) {
	n, err := t.NodeByID(id)
	if err != nil {
		return false, err
	}
	changed := n.PublicIP != r.PublicIP || n.UDPPort != r.UDPPort || jsonString(n.Locals) != jsonString(r.Locals) ||
		jsonString(n.Reflexive) != jsonString(r.Reflexive) || n.NAT != r.NAT || n.PortMap != r.PortMap ||
		string(n.DiscoKey) != string(r.DiscoKey) || n.Relay != r.Relay || jsonString(n.Routes) != jsonString(r.Routes) ||
		n.Exit != r.Exit || n.ExitDNS != r.ExitDNS
	_, err = t.tx.Exec(`UPDATE nodes SET public_ip = ?, udp_port = ?, locals = ?, client_version = ?, last_seen = ?,
		nat_type = ?, reflexive = ?, portmap = ?, disco_key = ?, relay = ?, routes = ?, exit_offer = ?, exit_dns = ? WHERE id = ?`,
		addrString(r.PublicIP), r.UDPPort, jsonString(r.Locals), r.Version, now(),
		r.NAT, jsonString(r.Reflexive), addrPortString(r.PortMap), r.DiscoKey, r.Relay, jsonString(r.Routes), r.Exit, r.ExitDNS, id)
	return changed, err
}

const nodeCols = `id, ed_key, box_key, name, public_ip, udp_port, locals, client_version, last_seen, created_at, nat_type, reflexive, portmap, disco_key, relay, routes, exit_offer, exit_dns`

func scanNode(row interface{ Scan(...any) error }) (*Node, error) {
	var n Node
	var pub, locals, reflexive, portmap, routes string
	var seen, created int64
	if err := row.Scan(&n.ID, &n.EdKey, &n.BoxKey, &n.Name, &pub, &n.UDPPort, &locals, &n.Version, &seen, &created,
		&n.NAT, &reflexive, &portmap, &n.DiscoKey, &n.Relay, &routes, &n.Exit, &n.ExitDNS); err != nil {
		return nil, notFound(err)
	}
	n.PublicIP, _ = netip.ParseAddr(pub)
	json.Unmarshal([]byte(locals), &n.Locals)
	json.Unmarshal([]byte(reflexive), &n.Reflexive)
	json.Unmarshal([]byte(routes), &n.Routes)
	n.PortMap, _ = netip.ParseAddrPort(portmap)
	n.LastSeen, n.CreatedAt = time.Unix(seen, 0), time.Unix(created, 0)
	return &n, nil
}

func (t *Tx) NodeByID(id string) (*Node, error) {
	return scanNode(t.tx.QueryRow(`SELECT `+nodeCols+` FROM nodes WHERE id = ?`, id))
}

// NodeByDiscoKey returns the node owning a disco key if it is an active
// member of at least one room.
func (t *Tx) NodeByDiscoKey(key []byte) (string, error) {
	var id string
	err := t.tx.QueryRow(`SELECT n.id FROM nodes n WHERE n.disco_key = ? AND EXISTS
		(SELECT 1 FROM members m WHERE m.node_id = n.id AND m.status = 'active')`, key).Scan(&id)
	return id, notFound(err)
}

// ShareActiveRoom reports whether both nodes are active members of one room.
func (t *Tx) ShareActiveRoom(a, b string) (bool, error) {
	var ok bool
	err := t.tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM members x JOIN members y ON x.room_id = y.room_id
		WHERE x.node_id = ? AND y.node_id = ? AND x.status = 'active' AND y.status = 'active')`, a, b).Scan(&ok)
	return ok, err
}

// ---- settings ----

func (t *Tx) Setting(key string) ([]byte, error) {
	var v []byte
	err := t.tx.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, notFound(err)
}

func (t *Tx) SetSetting(key string, value []byte) error {
	_, err := t.tx.Exec(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ---- rooms ----

type Room struct {
	ID         string
	Name       string
	Subnet     netip.Prefix
	Secret     []byte
	SignKey    []byte // Ed25519 private key
	OwnerID    int64
	JoinPolicy string // "manual" or "auto"
	Broadcast  string // "on", "off" or "mdns"
	DNS        []netip.Addr
	Version    int64
	CreatedAt  time.Time
}

func (t *Tx) CreateRoom(r *Room) error {
	_, err := t.tx.Exec(`INSERT INTO rooms(id, name, subnet, secret, sign_key, owner_id, join_policy, version, created_at) VALUES(?,?,?,?,?,?,?,1,?)`,
		r.ID, r.Name, r.Subnet.String(), r.Secret, r.SignKey, r.OwnerID, r.JoinPolicy, now())
	return err
}

const roomCols = `id, name, subnet, secret, sign_key, owner_id, join_policy, version, created_at, broadcast, dns`

func scanRoom(row interface{ Scan(...any) error }) (*Room, error) {
	var r Room
	var subnet, dns string
	var created int64
	if err := row.Scan(&r.ID, &r.Name, &subnet, &r.Secret, &r.SignKey, &r.OwnerID, &r.JoinPolicy, &r.Version, &created, &r.Broadcast, &dns); err != nil {
		return nil, notFound(err)
	}
	json.Unmarshal([]byte(dns), &r.DNS)
	r.Subnet, _ = netip.ParsePrefix(subnet)
	r.CreatedAt = time.Unix(created, 0)
	return &r, nil
}

func (t *Tx) RoomByID(id string) (*Room, error) {
	return scanRoom(t.tx.QueryRow(`SELECT `+roomCols+` FROM rooms WHERE id = ?`, id))
}

// ListRooms returns rooms owned by ownerID, or all rooms if ownerID is 0.
func (t *Tx) ListRooms(ownerID int64) ([]Room, error) {
	rows, err := t.tx.Query(`SELECT `+roomCols+` FROM rooms WHERE ? = 0 OR owner_id = ? ORDER BY name`, ownerID, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Room
	for rows.Next() {
		r, err := scanRoom(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

func (t *Tx) AllSubnets() ([]netip.Prefix, error) {
	rows, err := t.tx.Query(`SELECT subnet FROM rooms`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

func (t *Tx) UpdateRoom(id, name, joinPolicy, broadcast string) error {
	_, err := t.tx.Exec(`UPDATE rooms SET name = ?, join_policy = ?, broadcast = ? WHERE id = ?`, name, joinPolicy, broadcast, id)
	return err
}

// SetRoomDNS sets the room's own DNS servers (nil: none).
func (t *Tx) SetRoomDNS(id string, dns []netip.Addr) error {
	_, err := t.tx.Exec(`UPDATE rooms SET dns = ? WHERE id = ?`, jsonString(dns), id)
	return err
}

// BumpRoom increments the room config version.
func (t *Tx) BumpRoom(id string) error {
	_, err := t.tx.Exec(`UPDATE rooms SET version = version + 1 WHERE id = ?`, id)
	return err
}

func (t *Tx) DeleteRoom(id string) error {
	_, err := t.tx.Exec(`DELETE FROM rooms WHERE id = ?`, id)
	return err
}

// ---- members ----

const (
	StatusPending = "pending"
	StatusActive  = "active"
	StatusBanned  = "banned"
)

type Member struct {
	RoomID    string
	NodeID    string
	Name      string
	WGKey     []byte
	IP        netip.Addr
	Tags      []string
	Status    string
	CreatedAt time.Time
	// From the nodes table:
	LastSeen  time.Time
	PublicIP  netip.Addr
	Version   string
	NAT       string
	Reflexive []netip.AddrPort
	PortMap   netip.AddrPort
	// Routes approved by a room admin; Offered are the node's current offer.
	Routes  []netip.Prefix
	Offered []netip.Prefix
	// Exit is approved by a room admin; ExitOffered is the node's offer.
	Exit        bool
	ExitOffered bool
	ExitDNS     bool // the node answers DNS as an exit
	// UseExit is the node ID of the exit a room admin picked for this
	// member ("" = none; the member may pick one itself).
	UseExit string
}

func (t *Tx) AddMember(m *Member) error {
	_, err := t.tx.Exec(`INSERT INTO members(room_id, node_id, name, wg_key, ip, tags, status, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		m.RoomID, m.NodeID, m.Name, m.WGKey, addrString(m.IP), jsonString(m.Tags), m.Status, now())
	return err
}

const memberCols = `m.room_id, m.node_id, m.name, m.wg_key, m.ip, m.tags, m.status, m.created_at, n.last_seen, n.public_ip, n.client_version,
	n.nat_type, n.reflexive, n.portmap, m.routes, n.routes, m.exit, n.exit_offer, m.use_exit, n.exit_dns`

func scanMember(row interface{ Scan(...any) error }) (*Member, error) {
	var m Member
	var ip, tags, pub, reflexive, portmap, routes, offered string
	var created, seen int64
	if err := row.Scan(&m.RoomID, &m.NodeID, &m.Name, &m.WGKey, &ip, &tags, &m.Status, &created, &seen, &pub, &m.Version,
		&m.NAT, &reflexive, &portmap, &routes, &offered, &m.Exit, &m.ExitOffered, &m.UseExit, &m.ExitDNS); err != nil {
		return nil, notFound(err)
	}
	m.IP, _ = netip.ParseAddr(ip)
	m.PublicIP, _ = netip.ParseAddr(pub)
	json.Unmarshal([]byte(reflexive), &m.Reflexive)
	json.Unmarshal([]byte(routes), &m.Routes)
	json.Unmarshal([]byte(offered), &m.Offered)
	m.PortMap, _ = netip.ParseAddrPort(portmap)
	json.Unmarshal([]byte(tags), &m.Tags)
	m.CreatedAt, m.LastSeen = time.Unix(created, 0), time.Unix(seen, 0)
	return &m, nil
}

func (t *Tx) Member(roomID, nodeID string) (*Member, error) {
	return scanMember(t.tx.QueryRow(`SELECT `+memberCols+` FROM members m JOIN nodes n ON n.id = m.node_id WHERE m.room_id = ? AND m.node_id = ?`, roomID, nodeID))
}

func (t *Tx) queryMembers(where string, args ...any) ([]Member, error) {
	rows, err := t.tx.Query(`SELECT `+memberCols+` FROM members m JOIN nodes n ON n.id = m.node_id WHERE `+where+` ORDER BY m.ip`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// ListMembers returns all members of a room, any status.
func (t *Tx) ListMembers(roomID string) ([]Member, error) {
	return t.queryMembers(`m.room_id = ?`, roomID)
}

// Memberships returns every room membership of a node.
func (t *Tx) Memberships(nodeID string) ([]Member, error) {
	return t.queryMembers(`m.node_id = ?`, nodeID)
}

func (t *Tx) UpdateMember(m *Member) error {
	_, err := t.tx.Exec(`UPDATE members SET name = ?, ip = ?, tags = ?, status = ?, routes = ?, exit = ?, use_exit = ?
		WHERE room_id = ? AND node_id = ?`,
		m.Name, addrString(m.IP), jsonString(m.Tags), m.Status, jsonString(m.Routes), m.Exit, m.UseExit, m.RoomID, m.NodeID)
	return err
}

func (t *Tx) DeleteMember(roomID, nodeID string) error {
	_, err := t.tx.Exec(`DELETE FROM members WHERE room_id = ? AND node_id = ?`, roomID, nodeID)
	return err
}

// ---- invites ----

type Invite struct {
	ID          int64
	RoomID      string
	TokenHash   []byte
	UsesLeft    int // -1 = unlimited
	Expires     time.Time
	AutoApprove bool
	Note        string
	CreatedBy   int64
	CreatedAt   time.Time
}

func (t *Tx) CreateInvite(inv *Invite) (int64, error) {
	res, err := t.tx.Exec(`INSERT INTO invites(room_id, token_hash, uses_left, expires_at, auto_approve, note, created_by, created_at) VALUES(?,?,?,?,?,?,?,?)`,
		inv.RoomID, inv.TokenHash, inv.UsesLeft, inv.Expires.Unix(), inv.AutoApprove, inv.Note, inv.CreatedBy, now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const inviteCols = `id, room_id, token_hash, uses_left, expires_at, auto_approve, note, created_by, created_at`

func scanInvite(row interface{ Scan(...any) error }) (*Invite, error) {
	var inv Invite
	var exp, created int64
	if err := row.Scan(&inv.ID, &inv.RoomID, &inv.TokenHash, &inv.UsesLeft, &exp, &inv.AutoApprove, &inv.Note, &inv.CreatedBy, &created); err != nil {
		return nil, notFound(err)
	}
	inv.Expires, inv.CreatedAt = time.Unix(exp, 0), time.Unix(created, 0)
	return &inv, nil
}

// UseInvite consumes one use of a valid invite for the room.
func (t *Tx) UseInvite(roomID string, tokenHash []byte) (*Invite, error) {
	inv, err := scanInvite(t.tx.QueryRow(`SELECT `+inviteCols+` FROM invites
		WHERE room_id = ? AND token_hash = ? AND expires_at > ? AND uses_left != 0`, roomID, tokenHash, now()))
	if err != nil {
		return nil, err
	}
	if inv.UsesLeft > 0 {
		if _, err := t.tx.Exec(`UPDATE invites SET uses_left = uses_left - 1 WHERE id = ?`, inv.ID); err != nil {
			return nil, err
		}
	}
	return inv, nil
}

func (t *Tx) ListInvites(roomID string) ([]Invite, error) {
	rows, err := t.tx.Query(`SELECT `+inviteCols+` FROM invites WHERE room_id = ? AND expires_at > ? AND uses_left != 0 ORDER BY created_at DESC`, roomID, now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *inv)
	}
	return out, rows.Err()
}

func (t *Tx) RevokeInvite(roomID string, id int64) error {
	_, err := t.tx.Exec(`UPDATE invites SET uses_left = 0 WHERE room_id = ? AND id = ?`, roomID, id)
	return err
}

// ---- audit ----

type AuditEntry struct {
	Time    time.Time
	Actor   string
	Action  string
	Target  string
	Details string
}

func (t *Tx) Audit(actor, action, target, details string) error {
	_, err := t.tx.Exec(`INSERT INTO audit(ts, actor, action, target, details) VALUES(?,?,?,?,?)`, now(), actor, action, target, details)
	return err
}

func (t *Tx) ListAudit(limit int) ([]AuditEntry, error) {
	rows, err := t.tx.Query(`SELECT ts, actor, action, target, details FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		if err := rows.Scan(&ts, &e.Actor, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func addrPortString(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
