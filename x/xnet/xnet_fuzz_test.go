package xnet

import (
	"net/netip"
	"testing"

	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/tcp"
)

func FuzzStackAsyncHTTP(f *testing.F) {
	const MTU = 1500
	const seed = 1
	var buf [MTU + ethernet.MaxOverheadSize]byte
	s1, s2, c1, c2 := newTCPStacks(f, seed, MTU)
	var hdr httpraw.Header
	err := s1.ListenTCP(c1, 80)
	if err != nil {
		f.Fatal(err)
	}
	err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(s1.Addr(), c1.LocalPort()))
	if err != nil {
		f.Fatal(err)
	}
	hdr.SetMethod("GET")
	hdr.SetProtocol("HTTP/1.1")
	hdr.SetRequestURI("/")
	data := hdr.AppendHeaders(nil)

	pktnum := 0
	written := false
	closed := false
	for {
		n1, err := s1.Encapsulate(buf[:], -1, 0)
		if err != nil {
			f.Fatal(err)
		}
		if n1 > 0 {
			err = s2.Demux(buf[:n1], 0)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n1])
			pktnum++
			if !written && c2.State() >= tcp.StateEstablished {
				_, err = c2.Write(data)
				if err != nil {
					f.Fatal(err)
				}
				written = true
			}
		}
		n2, err := s2.Encapsulate(buf[:], -1, 0)
		if n2 > 0 {
			pktnum++
			err = s1.Demux(buf[:n2], 0)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(pktnum, buf[:n2])
		}
		if n1 == 0 && n2 == 0 {
			if !closed {
				c2.Close()
				closed = true
				continue
			}
			break // No more data to send
		}
	}

	f.Fuzz(func(t *testing.T, pktnum int, a []byte) {
		var buf [MTU + ethernet.MaxOverheadSize]byte
		s1, s2, c1, c2 := newTCPStacks(t, seed, MTU)
		err := s1.ListenTCP(c1, 80)
		if err != nil {
			t.Fatal(err)
		}
		err = s2.DialTCP(c2, 1337, netip.AddrPortFrom(s1.Addr(), c1.LocalPort()))
		if err != nil {
			t.Fatal(err)
		}
		pkt := 0
		written := false
		closed := false
		const maxpkts = 100
		for {
			n1, err := s1.Encapsulate(buf[:], -1, 0)
			if err != nil {
				t.Fatal(err)
			}
			if n1 > 0 {
				if pkt == pktnum {
					n1 = copy(buf[:], a)
				}
				s2.Demux(buf[:n1], 0)
				pkt++
				if !written && c2.State() >= tcp.StateEstablished {
					c2.Write(data)
					written = true
				}
			}
			n2, err := s2.Encapsulate(buf[:], -1, 0)
			if n2 > 0 {
				if pkt == pktnum {
					n2 = copy(buf[:], a)
				}
				pkt++
				s1.Demux(buf[:n2], 0)
			}
			if n1 == 0 && n2 == 0 {
				if !closed {
					if c1.BufferedInput() > 0 {
						var hdr httpraw.Header
						n, _ := c1.Read(buf[:])
						hdr.ReadFromBytes(buf[:n])
						hdr.TryParse(false)
					}
					c2.Close()
					closed = true
					continue
				}
				break // No more data to send
			}
			if pkt > maxpkts {
				panic("infinite retransmission loop")
			}
		}
	})
}
