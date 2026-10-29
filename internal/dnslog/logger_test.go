package dnslog

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func sample(payload []byte, direction uint32) []byte {
	event := make([]byte, eventHeaderSize+len(payload))
	binary.LittleEndian.PutUint64(event, 42)
	copy(event[8:12], []byte{8, 8, 8, 8})
	binary.BigEndian.PutUint16(event[12:14], 53)
	binary.LittleEndian.PutUint32(event[16:20], direction)
	binary.LittleEndian.PutUint32(event[20:24], uint32(len(payload)))
	copy(event[eventHeaderSize:], payload)
	return event
}

func TestFormatDNS(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	alias := dnsmessage.MustNewName("www.example.com.")
	header := dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 123}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	for _, tc := range []struct {
		name      string
		message   dnsmessage.Message
		direction uint32
		want      []string
	}{
		{"query", query, 0, []string{"dns send", "socket=42", "original=8.8.8.8:53", "resolver=127.0.0.1:1053", "kind=query", "id=123", "example.com. TypeA"}},
		{"response", dnsmessage.Message{Header: dnsmessage.Header{ID: 123, Response: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{
			{Header: header, Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}}},
			{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120}, Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}},
			{Header: dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.CNAMEResource{CNAME: name}},
		}}, 1, []string{"dns receive", "kind=response", "rcode=RCodeSuccess", "ttl=60 93.184.216.34", "2001:db8::1", "www.example.com. TypeCNAME ttl=30 example.com."}},
		{"nxdomain", dnsmessage.Message{Header: dnsmessage.Header{ID: 123, Response: true, RCode: dnsmessage.RCodeNameError}, Questions: query.Questions}, 1, []string{"rcode=RCodeNameError", "answers=\"\""}},
		{"truncated", dnsmessage.Message{Header: dnsmessage.Header{Response: true, Truncated: true}, Questions: query.Questions}, 1, []string{"truncated=true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := tc.message.Pack()
			if err != nil {
				t.Fatal(err)
			}
			got, err := Format(sample(wire, tc.direction), "127.0.0.1:1053")
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q in %s", want, got)
				}
			}
		})
	}
}

func TestCompressedAndUntrustedDNS(t *testing.T) {
	name := dnsmessage.MustNewName("example.com.")
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, Response: true})
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	if err := builder.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := builder.TXTResource(dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, dnsmessage.TXTResource{TXT: []string{"hello\nforged log\r\x00"}}); err != nil {
		t.Fatal(err)
	}
	wire, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Format(sample(wire, 1), "127.0.0.1:1053")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(got, "\n\r\x00") || !strings.Contains(got, "hello\\nforged log\\r\\x00") {
		t.Fatalf("unsafe or missing TXT value: %q", got)
	}
}

func TestMalformedAndOversizeEvents(t *testing.T) {
	if _, err := Format([]byte{1}, "resolver"); err == nil {
		t.Fatal("short event accepted")
	}
	malformed := make([]byte, 12)
	binary.BigEndian.PutUint16(malformed[4:6], 1)
	got, err := Format(sample(malformed, 0), "resolver")
	if err != nil || !strings.Contains(got, "malformed=") {
		t.Fatalf("got %s, %v", got, err)
	}
	event := sample(make([]byte, 4096), 1)
	binary.LittleEndian.PutUint32(event[20:24], 5000)
	got, err = Format(event, "resolver")
	if err != nil || !strings.Contains(got, "capture_truncated=true captured=4096 size=5000") {
		t.Fatalf("got %s, %v", got, err)
	}
	for _, event := range [][]byte{sample(make([]byte, 12), 2), sample(make([]byte, 11), 0), sample(make([]byte, 4097), 0)} {
		if _, err := Format(event, "resolver"); err == nil {
			t.Fatal("invalid event accepted")
		}
	}
}

func FuzzFormat(f *testing.F) {
	f.Add(sample(make([]byte, 12), 0))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = Format(data, "127.0.0.1:1053") })
}
