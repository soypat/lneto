package congestion

import "github.com/soypat/lneto/tcp"

// isDupACK reports whether seg is a duplicate ACK (RFC 5681 §2) with the
// peer's window not grown: una and room are SND.UNA and the room for data in
// flight before seg, unaNow, nxt and roomNow after it.
func isDupACK(seg tcp.Segment, una, unaNow, nxt tcp.Value, room, roomNow tcp.Size) bool {
	return seg.ACK == una && unaNow == una && una.LessThan(nxt) && seg.DATALEN == 0 &&
		!seg.Flags.HasAny(tcp.FlagSYN|tcp.FlagFIN) && roomNow <= room
}

// dupACKs counts the duplicate ACKs that can mean a loss. The ControlBlock
// resends SND.UNA on every duplicate ACK from the third, and each copy the
// peer already holds draws a duplicate ACK at a later SND.UNA. So as many
// duplicate ACKs as copies were sent do not count, and the resends they cause
// are copies again, until SND.UNA passes the data sent before the last copy.
type dupACKs struct {
	n         uint8     // Not answering copies, up to 3.
	copyOwed  bool      // Resends the ControlBlock owes for this SND.UNA are no loss.
	copies    uint8     // Copies of SND.UNA sent.
	answers   uint8     // Duplicate ACKs expected for copies of earlier SND.UNAs.
	copiesNxt tcp.Value // SND.NXT at the latest copy. Once SND.UNA passes it, all were answered.
}

// acked restarts the count for an ACK advancing SND.UNA to una.
func (d *dupACKs) acked(una tcp.Value) {
	d.n, d.copyOwed = 0, false
	d.answers, d.copies = d.answers+min(d.copies, 255-d.answers), 0
	if d.copiesNxt.LessThan(una) {
		d.answers = 0
	}
}

// dup takes a duplicate ACK, which counts if count and it answers no copy.
func (d *dupACKs) dup(count bool) {
	if d.answers > 0 {
		d.answers--
	} else if count {
		d.n = min(d.n+1, 3)
	}
}

// owed takes a fast retransmit the ControlBlock owes and reports whether it
// is a loss, after three duplicate ACKs if mayLose. Otherwise its resends are
// copies.
func (d *dupACKs) owed(mayLose bool) (loss bool) {
	if d.n == 3 && mayLose {
		return true
	}
	d.copyOwed = true
	return false
}

// resent takes a resend from seq, with SND.UNA una and SND.NXT nxt before it,
// and reports whether it is a copy.
func (d *dupACKs) resent(seq, una, nxt tcp.Value) (isCopy bool) {
	if seq != una || !d.copyOwed {
		return false
	}
	d.copies, d.copiesNxt = min(d.copies, 254)+1, nxt
	return true
}
