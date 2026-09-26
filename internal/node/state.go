// SPDX-License-Identifier: MPL-2.0

package node

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Chistovik92/zeropentime/internal/fsutil"
)

// State is what "zpt join" records for the daemon: which controllers to
// follow and the pinned signing key of every room joined through them.
type State struct {
	Controllers []ControllerState `json:"controllers"`
	// Exit is the exit node chosen on this machine ("zpt exit"); nil
	// follows the choice of the room admins.
	Exit *ExitChoice `json:"exit,omitempty"`
}

// ExitChoice is an exit node picked with "zpt exit".
type ExitChoice struct {
	// Off: no exit, whatever room admins pick.
	Off    bool   `json:"off,omitempty"`
	Room   string `json:"room,omitempty"`   // room ID or name
	Member string `json:"member,omitempty"` // member name in the room
	// KillSwitch blocks the internet while the exit is not usable;
	// AllowLAN keeps the local network reachable meanwhile.
	KillSwitch bool `json:"kill_switch,omitempty"`
	AllowLAN   bool `json:"allow_lan,omitempty"`
}

// ControllerState is one controller the node follows.
type ControllerState struct {
	URL string `json:"url"`
	// Rooms maps room ID to the room signing key from the invite.
	Rooms map[string]string `json:"rooms"`
}

// StatePath is the state file next to the node key.
func StatePath(keyPath string) string {
	return filepath.Join(filepath.Dir(keyPath), "state.json")
}

// LoadState reads the state file; a missing file is an empty state.
func LoadState(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{}, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Save writes the state atomically, readable only by its owner, the
// administrators and the system.
func (s *State) Save(path string) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFile(path, b)
}

func normURL(u string) string { return strings.TrimRight(u, "/") }

// Pin records a room key for a controller.
func (s *State) Pin(controller, roomID, roomKey string) {
	controller = normURL(controller)
	for i := range s.Controllers {
		if s.Controllers[i].URL == controller {
			if s.Controllers[i].Rooms == nil {
				s.Controllers[i].Rooms = map[string]string{}
			}
			s.Controllers[i].Rooms[roomID] = roomKey
			return
		}
	}
	s.Controllers = append(s.Controllers, ControllerState{URL: controller, Rooms: map[string]string{roomID: roomKey}})
}

// Unpin forgets a room; a controller without rooms is dropped.
func (s *State) Unpin(roomID string) (controller string, ok bool) {
	for i := range s.Controllers {
		if _, found := s.Controllers[i].Rooms[roomID]; found {
			controller = s.Controllers[i].URL
			delete(s.Controllers[i].Rooms, roomID)
			if len(s.Controllers[i].Rooms) == 0 {
				s.Controllers = append(s.Controllers[:i], s.Controllers[i+1:]...)
			}
			return controller, true
		}
	}
	return "", false
}

// RoomKey returns the pinned key of a room at a controller.
func (s *State) RoomKey(controller, roomID string) (string, bool) {
	for _, c := range s.Controllers {
		if c.URL == normURL(controller) {
			k, ok := c.Rooms[roomID]
			return k, ok
		}
	}
	return "", false
}
