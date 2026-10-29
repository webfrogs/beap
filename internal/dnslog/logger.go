// Package dnslog decodes best-effort DNS packet events emitted by cgroup hooks.
package dnslog

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/net/dns/dnsmessage"
)

const eventHeaderSize = 24

// Logger owns the reader and waits for both workers before returning from Close.
type Logger struct {
	reader  *ringbuf.Reader
	done    chan struct{}
	once    sync.Once
	workers sync.WaitGroup
}

func Start(events, drops *ebpf.Map, resolver string) (*Logger, error) {
	if events == nil || drops == nil {
		return nil, errors.New("missing DNS log maps")
	}
	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return nil, err
	}
	l := &Logger{reader: reader, done: make(chan struct{})}
	l.workers.Add(2)
	go func() {
		defer l.workers.Done()
		for {
			event, err := reader.Read()
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			if err != nil {
				log.Printf("dns log reader: %v", err)
				return
			}
			line, err := Format(event.RawSample, resolver)
			if err != nil {
				log.Printf("dns log decode: %v", err)
				continue
			}
			log.Print(line)
		}
	}()
	go func() {
		defer l.workers.Done()
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		var previous uint64
		report := func() {
			var values []uint64
			if err := drops.Lookup(uint32(0), &values); err != nil {
				log.Printf("dns log drop counter: %v", err)
				return
			}
			var total uint64
			for _, value := range values {
				total += value
			}
			if total > previous {
				log.Printf("dns log dropped=%d total_dropped=%d", total-previous, total)
			}
			previous = total
		}
		for {
			select {
			case <-l.done:
				report()
				return
			case <-ticker.C:
				report()
			}
		}
	}()
	return l, nil
}

func (l *Logger) Close() error {
	var err error
	l.once.Do(func() { close(l.done); err = l.reader.Close(); l.workers.Wait() })
	return err
}

// Format parses the explicitly little-endian BPF event ABI (built with bpfel).
// DNS names are quoted in the final log line to keep untrusted text on one line.
func Format(sample []byte, resolver string) (string, error) {
	if len(sample) < eventHeaderSize {
		return "", errors.New("short DNS event")
	}
	cookie := binary.LittleEndian.Uint64(sample[:8])
	original := netip.AddrFrom4([4]byte(sample[8:12]))
	port := binary.BigEndian.Uint16(sample[12:14])
	direction := binary.LittleEndian.Uint32(sample[16:20])
	wireLength := binary.LittleEndian.Uint32(sample[20:24])
	payload := sample[eventHeaderSize:]
	if direction > 1 || wireLength < 12 || len(payload) > 4096 || uint32(len(payload)) > wireLength {
		return "", errors.New("invalid DNS event header")
	}
	flow := "send"
	if direction == 1 {
		flow = "receive"
	}
	prefix := fmt.Sprintf("dns %s socket=%d original=%s resolver=%s", flow, cookie, netip.AddrPortFrom(original, port), resolver)
	if uint32(len(payload)) < wireLength {
		return fmt.Sprintf("%s capture_truncated=true captured=%d size=%d", prefix, len(payload), wireLength), nil
	}
	var message dnsmessage.Message
	if err := message.Unpack(payload); err != nil {
		return fmt.Sprintf("%s malformed=%q", prefix, err.Error()), nil
	}
	kind := "query"
	if message.Response {
		kind = "response"
	}
	questions := make([]string, 0, len(message.Questions))
	for _, q := range message.Questions {
		questions = append(questions, fmt.Sprintf("%s %s", q.Name.String(), q.Type))
	}
	answers := make([]string, 0, len(message.Answers))
	for _, a := range message.Answers {
		answers = append(answers, fmt.Sprintf("%s %s ttl=%d %s", a.Header.Name.String(), a.Header.Type, a.Header.TTL, answerValue(a.Body)))
	}
	return fmt.Sprintf("%s kind=%s id=%d rcode=%s truncated=%t questions=%q answers=%q", prefix, kind, message.ID, message.RCode, message.Truncated, strings.Join(questions, "; "), strings.Join(answers, "; ")), nil
}

func answerValue(body dnsmessage.ResourceBody) string {
	switch value := body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(value.A).String()
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(value.AAAA).String()
	case *dnsmessage.CNAMEResource:
		return value.CNAME.String()
	case *dnsmessage.NSResource:
		return value.NS.String()
	case *dnsmessage.PTRResource:
		return value.PTR.String()
	case *dnsmessage.MXResource:
		return fmt.Sprintf("%d %s", value.Pref, value.MX.String())
	case *dnsmessage.TXTResource:
		return strings.Join(value.TXT, " ")
	case *dnsmessage.SRVResource:
		return fmt.Sprintf("%d %d %d %s", value.Priority, value.Weight, value.Port, value.Target.String())
	case *dnsmessage.SOAResource:
		return fmt.Sprintf("%s %s serial=%d", value.NS.String(), value.MBox.String(), value.Serial)
	default:
		return fmt.Sprintf("%v", body)
	}
}
