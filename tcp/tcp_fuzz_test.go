package tcp

import (
	"testing"

	"github.com/soypat/lneto/internal"
)

func FuzzTCPControlBlock(f *testing.F) {
	const (
		mutopFlags = 1 << iota
		mutopSeq
		mutopAck
		mutopMaxBit
	)
	const mutopBits = mutopMaxBit - 1
	const (
		mutPacketBits = 4

		mutFlags = 1 << iota
	)
	const wnd = 1500
	var seed uint64
	editPkt := func(rngSeed, ops uint64, seg *Segment) {
		ops &= mutopBits
		if ops&mutopFlags != 0 {
			seg.Flags ^= Flags(seed & uint64(FlagACK|FlagFIN|FlagRST|FlagSYN))
		}
		if ops&mutopSeq != 0 {
			seg.SEQ = Value(int32(seg.SEQ) + int32(int8(uint8(rngSeed>>32))))
		}
		if ops&mutopAck != 0 {
			seg.ACK = Value(int32(seg.ACK) + int32(int8(uint8(rngSeed>>48))))
		}
	}
	f.Add(seed, uint64(mutopFlags))
	f.Fuzz(func(t *testing.T, seed, op uint64) {
		var tcb0, tcb1 ControlBlock
		iss0 := Value(seed)
		iss1 := Value(seed >> 32)
		err := tcb0.Open(iss0, wnd)
		if err != nil {
			t.Fatal(err)
		}
		synseg := ClientSynSegment(iss1, wnd)
		err = tcb1.Send(synseg)
		if err != nil {
			t.Fatal(err)
		}
		err = tcb0.Recv(synseg)
		if err != nil {
			t.Fatal(err)
		}
		sent := 0
		const maxpkts = 30
		pktEdits := internal.Prand64(seed)
		nextOp := internal.Prand64(op)
		for range maxpkts {
			nextOp = internal.Prand64(nextOp)
			seg0, ok := tcb0.PendingSegment(10)
			if ok {
				edit := pktEdits&1 != 0
				pktEdits >>= 1
				if edit {
					editPkt(seed, nextOp, &seg0)
				}
				err = tcb0.Send(seg0)
				if err == nil {
					sent++
					err = tcb1.Recv(seg0)
					if err != nil {
						t.Fatal("packet sent from TCB0 to TCB1 failed:\n", StringExchange(seg0, tcb0.State(), tcb1.State(), false))
					}
				}
			}
			nextOp = internal.Prand64(nextOp)
			seg1, ok := tcb1.PendingSegment(10)
			if ok {
				edit := pktEdits&1 != 0
				pktEdits >>= 1
				if edit {
					editPkt(seed, nextOp, &seg1)
				}
				err = tcb1.Send(seg1)
				if err == nil {
					sent++
					err = tcb0.Recv(seg1)
					if err != nil {
						t.Fatal("packet sent from TCB1 to TCB0 failed:\n", StringExchange(seg1, tcb0.State(), tcb1.State(), true))
					}
				}
			}
		}
		if sent == 0 {
			t.Fatal("no packets sent")
		}
	})
}
