package tlsraw

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/crypto/internal/rfc8448"
)

// TestInstallKeys checks InstallKeys installs the key and IV that Keys derives
// and SetAEAD installs, and that the traffic key is left nowhere in the schedule
// afterwards, paranoid mode off included: the key is the AEAD's to keep, not ours.
func TestInstallKeys(t *testing.T) {
	keyLen := len(rfc8448.ServerHSKey)
	for _, paranoid := range []bool{false, true} {
		var ks KeySchedule
		var sHS [32]byte
		newSchedule := func() {
			err := ks.Configure(rfc8448.NewSHA256(), rfc8448.NewSHA256(), paranoid)
			if err != nil {
				t.Fatal(err)
			}
			ks.AddMessage(rfc8448.ClientHello)
			ks.AddMessage(rfc8448.ServerHello)
			var cHS [32]byte
			ks.Handshake(cHS[:], sHS[:], rfc8448.WantShared)
		}
		newSchedule()

		var rec recorderAEAD
		var hc HalfConn
		if err := ks.InstallKeys(&hc, &rec, keyLen, sHS[:]); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rec.key[:rec.keyLen], rfc8448.ServerHSKey) {
			t.Errorf("paranoid=%v: rekeyed with %x, want %x", paranoid, rec.key[:rec.keyLen], rfc8448.ServerHSKey)
		}
		if !bytes.Equal(hc.iv[:], rfc8448.ServerHSIV) {
			t.Errorf("paranoid=%v: iv=%x, want %x", paranoid, hc.iv, rfc8448.ServerHSIV)
		}
		if !hc.HasKeys() || hc.seq != 0 {
			t.Errorf("paranoid=%v: HasKeys=%v seq=%d, want true 0", paranoid, hc.HasKeys(), hc.seq)
		}
		if bytes.Contains(scheduleBytes(&ks), rfc8448.ServerHSKey) {
			t.Errorf("paranoid=%v: traffic key left in the key schedule", paranoid)
		}

		// A record sealed with the installed keys is the RFC's, so key, IV and
		// sequence reached the AEAD as a Keys+SetAEAD pair would have left them.
		newSchedule()
		var hcGCM HalfConn
		if err := ks.InstallKeys(&hcGCM, rfc8448.NewAES128GCM(), keyLen, sHS[:]); err != nil {
			t.Fatal(err)
		}
		flight := make([]byte, SizeHeaderRecord, MaxRecord)
		for _, msg := range [][]byte{rfc8448.EncryptedExtensions, rfc8448.Certificate, rfc8448.CertificateVerify, rfc8448.ServerFinished} {
			flight = append(flight, msg...)
		}
		got, err := hcGCM.Seal(flight, ContentTypeHandshake)
		if err != nil {
			t.Fatal(err)
		} else if !bytes.Equal(got, rfc8448.ServerRecord) {
			t.Errorf("paranoid=%v: server record=%x, want %x", paranoid, got, rfc8448.ServerRecord)
		}

		// A rejected key length must leave the half connection as it was: a
		// partially keyed HalfConn would seal with a stale key under a fresh IV.
		var unkeyed HalfConn
		// ks.Size()+1 is rejected rather than reaching expandLabel, which panics on
		// a destination longer than the digest.
		for _, bad := range []int{0, -1, ks.Size() + 1, len(ks.scratch) + 1} {
			if err := ks.InstallKeys(&unkeyed, &rec, bad, sHS[:]); err != lneto.ErrInvalidConfig {
				t.Errorf("paranoid=%v: InstallKeys keyLen=%d err=%v, want %v", paranoid, bad, err, lneto.ErrInvalidConfig)
			}
		}
		if unkeyed.HasKeys() {
			t.Errorf("paranoid=%v: rejected InstallKeys installed keys", paranoid)
		}
		// An AEAD that refuses the key leaves hc unkeyed too: the IV is installed
		// before the key is derived, so hc would otherwise seal under a stale key.
		badRekey := recorderAEAD{rekeyErr: lneto.ErrBadState}
		if err := ks.InstallKeys(&unkeyed, &badRekey, keyLen, sHS[:]); err != lneto.ErrBadState {
			t.Errorf("paranoid=%v: InstallKeys over failing Rekey err=%v, want %v", paranoid, err, lneto.ErrBadState)
		} else if unkeyed.HasKeys() {
			t.Errorf("paranoid=%v: InstallKeys left keys installed after Rekey failed", paranoid)
		}

		allocs := testing.AllocsPerRun(10, func() {
			ks.InstallKeys(&hc, &rec, keyLen, sHS[:])
		})
		if allocs != 0 {
			t.Errorf("paranoid=%v: InstallKeys allocs=%v, want 0", paranoid, allocs)
		}
	}
}

// scheduleBytes views ks as raw memory so a test can search it for a secret.
func scheduleBytes(ks *KeySchedule) []byte {
	b := make([]byte, 0, len(ks.secret)+len(ks.sum)+len(ks.scratch)+len(ks.pad)+len(ks.info))
	b = append(b, ks.secret[:]...)
	b = append(b, ks.sum[:]...)
	b = append(b, ks.scratch[:]...)
	b = append(b, ks.pad[:]...)
	return append(b, ks.info[:]...)
}

// recorderAEAD keeps the key it was rekeyed with so a test can check what the
// key schedule handed it. Seal and Open are unused.
type recorderAEAD struct {
	key      [32]byte
	keyLen   int
	rekeyErr error // Returned by Rekey, to exercise a cipher that refuses the key.
}

func (*recorderAEAD) NonceSize() int { return 12 }
func (*recorderAEAD) Overhead() int  { return SizeAEADTag }
func (r *recorderAEAD) Rekey(key []byte) error {
	if r.rekeyErr != nil {
		return r.rekeyErr
	}
	r.keyLen = copy(r.key[:], key)
	return nil
}
func (r *recorderAEAD) Zeroize() { r.key, r.keyLen = [32]byte{}, 0 }
func (*recorderAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	panic("unused")
}
func (*recorderAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	panic("unused")
}
