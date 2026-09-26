// SPDX-License-Identifier: MPL-2.0

package dnsfwd

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// TLD is the top-level domain of room names: name.room.zpt.
const TLD = "zpt"

// ZoneTTL is the TTL of the answers: short, members come and go.
const ZoneTTL = 30

// Zone is a room's names: Name is "room.zpt", Records map member labels
// ("laptop") to their addresses in the room.
type Zone struct {
	Name    string
	Records map[string]netip.Addr
}

// answerZone answers a query for a name in the zone (ok=false: not ours).
// Unknown names get NXDOMAIN, other record types an empty answer.
func answerZone(q []byte, z *Zone) (resp []byte, ok bool) {
	if z == nil || z.Name == "" {
		return nil, false
	}
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil || h.Response {
		return nil, false
	}
	question, err := p.Question()
	if err != nil {
		return nil, false
	}
	name := strings.TrimSuffix(strings.ToLower(question.Name.String()), ".")
	zone := strings.ToLower(z.Name)
	if name != zone && !strings.HasSuffix(name, "."+zone) {
		return nil, false
	}
	label := strings.TrimSuffix(strings.TrimSuffix(name, zone), ".")
	rh := dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	addr, found := z.Records[label]
	if !found && label != "" {
		rh.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, rh)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(question)
	b.StartAnswers()
	if found && question.Class == dnsmessage.ClassINET && (question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeALL) && addr.Is4() {
		b.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: ZoneTTL},
			dnsmessage.AResource{A: addr.As4()})
	}
	out, err := b.Finish()
	if err != nil {
		return nil, false
	}
	return out, true
}

// refused answers a query this server does not resolve for its sender.
func refused(q []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(q)
	if err != nil {
		return nil
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RCode: dnsmessage.RCodeRefused, RecursionDesired: h.RecursionDesired})
	b.StartQuestions()
	if question, err := p.Question(); err == nil {
		b.Question(question)
	}
	out, _ := b.Finish()
	return out
}

// Label turns a member or room name into a DNS label: lower case Latin
// letters, digits and hyphens (Cyrillic is transliterated), at most 63.
func Label(name string) string {
	var sb strings.Builder
	dash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			sb.WriteRune(r)
			dash = false
		case translit[r] != "":
			sb.WriteString(translit[r])
			dash = false
		default:
			if sb.Len() > 0 && !dash {
				sb.WriteByte('-')
				dash = true
			}
		}
	}
	s := sb.String()
	if len(s) > 63 {
		s = s[:63]
	}
	return strings.Trim(s, "-")
}

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "e", 'ж': "zh", 'з': "z", 'и': "i", 'й': "y",
	'к': "k", 'л': "l", 'м': "m", 'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u", 'ф': "f",
	'х': "h", 'ц': "c", 'ч': "ch", 'ш': "sh", 'щ': "sch", 'ы': "y", 'э': "e", 'ю': "yu", 'я': "ya",
}
