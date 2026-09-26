// SPDX-License-Identifier: MPL-2.0

// Package client talks to a controller on behalf of a node.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Chistovik92/zeropentime/internal/api"
	"github.com/Chistovik92/zeropentime/internal/identity"
	"github.com/Chistovik92/zeropentime/internal/netmark"
	"github.com/Chistovik92/zeropentime/internal/pki"
)

// transport keeps the controller connection out of an exit node's tunnel.
var transport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = netmark.Dialer().DialContext
	return t
}()

// Error is a non-2xx answer from the controller.
type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("controller: %s (HTTP %d)", e.Message, e.Status) }

// IsForbidden reports whether err is a 403 from the controller.
func IsForbidden(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusForbidden
}

// Client is a signed, encrypted connection to one controller.
type Client struct {
	Base    string
	ID      *identity.Identity
	Version string
	HTTP    *http.Client
}

// New creates a client for the controller at base URL.
func New(base string, id *identity.Identity, version string) *Client {
	return &Client{
		Base:    strings.TrimRight(base, "/"),
		ID:      id,
		Version: version,
		HTTP:    &http.Client{Timeout: (api.PollTimeout + 20) * time.Second, Transport: transport},
	}
}

// BoxKey is the public key the controller encrypts responses to.
func (c *Client) BoxKey() identity.Key {
	_, pub := c.ID.BoxKey()
	return pub
}

func (c *Client) call(ctx context.Context, path string, req, resp any, sealed bool) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("User-Agent", "zpt/"+c.Version)
	for k, v := range pki.RequestHeaders(c.ID, http.MethodPost, path, body, time.Now()) {
		hr.Header.Set(k, v)
	}
	res, err := c.HTTP.Do(hr)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusOK {
		var e api.Error
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(res.StatusCode)
		}
		return &Error{Status: res.StatusCode, Message: e.Error}
	}
	if sealed {
		priv, pub := c.ID.BoxKey()
		if data, err = pki.Open(data, priv, pub); err != nil {
			return err
		}
	}
	if resp == nil {
		return nil
	}
	return json.Unmarshal(data, resp)
}

// Join asks to join a room with an invite.
func (c *Client) Join(ctx context.Context, inv api.Invite, name string, ep api.Endpoints) (*api.JoinResponse, error) {
	wg, err := c.ID.RoomKey(inv.RoomID)
	if err != nil {
		return nil, err
	}
	var resp api.JoinResponse
	err = c.call(ctx, api.PathJoin, &api.JoinRequest{
		RoomID: inv.RoomID, Token: inv.Token, Name: name, WGKey: wg.Public(), BoxKey: c.BoxKey(),
		Endpoints: ep, ClientVersion: c.Version,
	}, &resp, true)
	return &resp, err
}

// Poll waits for a netmap newer than since.
func (c *Client) Poll(ctx context.Context, since int64, ep api.Endpoints) (*api.NetMap, error) {
	var nm api.NetMap
	err := c.call(ctx, api.PathPoll, &api.PollRequest{Since: since, BoxKey: c.BoxKey(), Endpoints: ep, ClientVersion: c.Version}, &nm, true)
	return &nm, err
}

// Leave leaves a room.
func (c *Client) Leave(ctx context.Context, roomID string) error {
	return c.call(ctx, api.PathLeave, &api.LeaveRequest{RoomID: roomID}, nil, false)
}
