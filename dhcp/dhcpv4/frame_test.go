package dhcpv4

import "testing"

// EncodeOption must fill a buffer of exactly the option's size.
// Previously it checked one byte past the option and panicked. Found by lfuzzo.
func TestEncodeOptionExactBuffer(t *testing.T) {
	dst := make([]byte, 3)
	n, err := EncodeOption(dst, OptMessageType, byte(MsgDiscover))
	if err != nil || n != 3 || dst[0] != byte(OptMessageType) || dst[1] != 1 || dst[2] != byte(MsgDiscover) {
		t.Fatalf("EncodeOption = %d, %v, % x; want 3, nil, %x 01 %x", n, err, dst, OptMessageType, MsgDiscover)
	}
}

// TestForEachOptionBoundsCheck verifies that ForEachOption properly validates
// buffer bounds and doesn't panic on malformed options with lengths that extend
// past the buffer end.
func TestForEachOptionBoundsCheck(t *testing.T) {
	// Create a minimal valid frame buffer
	buf := make([]byte, OptionsOffset+10)
	frm, err := NewFrame(buf)
	if err != nil {
		t.Fatal(err)
	}
	frm.SetMagicCookie(MagicCookie)

	testCases := []struct {
		name    string
		options []byte
		wantErr bool
	}{
		{
			name:    "valid option",
			options: []byte{byte(OptHostName), 4, 't', 'e', 's', 't', byte(OptEnd)},
			wantErr: false,
		},
		{
			name:    "option length exceeds buffer",
			options: []byte{byte(OptHostName), 100, 't', 'e', 's', 't'}, // claims 100 bytes but only 4 available
			wantErr: true,
		},
		{
			name:    "option length exactly at buffer end",
			options: []byte{byte(OptHostName), 255}, // claims 255 bytes, way past end
			wantErr: true,
		},
		{
			name:    "option length causes ptr+2+optlen overflow",
			options: []byte{byte(OptHostName), 8, 'a', 'b', 'c'}, // claims 8 bytes but only 3 available
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create fresh buffer for each test
			testBuf := make([]byte, OptionsOffset+len(tc.options))
			testFrm, _ := NewFrame(testBuf)
			testFrm.SetMagicCookie(MagicCookie)
			copy(testBuf[OptionsOffset:], tc.options)

			// Use recover to catch panics
			var panicked bool
			var gotErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						panicked = true
					}
				}()
				gotErr = testFrm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
					// Access the data to trigger potential panic
					_ = len(data)
					if len(data) > 0 {
						_ = data[0]
					}
					return nil
				})
			}()

			if panicked {
				t.Errorf("ForEachOption panicked on malformed input %q", tc.name)
			}
			if tc.wantErr && gotErr == nil {
				t.Errorf("ForEachOption should return error for %q, got nil", tc.name)
			}
			if !tc.wantErr && gotErr != nil {
				t.Errorf("ForEachOption should not return error for %q, got %v", tc.name, gotErr)
			}
		})
	}
}

// TestForEachOptionEdgeCases tests additional edge cases for bounds checking.
func TestForEachOptionEdgeCases(t *testing.T) {
	t.Run("empty options section", func(t *testing.T) {
		buf := make([]byte, OptionsOffset)
		frm, _ := NewFrame(buf)
		frm.SetMagicCookie(MagicCookie)

		err := frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
			return nil
		})
		// Should return errNoOptions for empty options
		if err == nil {
			t.Error("expected error for empty options section")
		}
	})

	t.Run("only end option", func(t *testing.T) {
		buf := make([]byte, OptionsOffset+1)
		frm, _ := NewFrame(buf)
		frm.SetMagicCookie(MagicCookie)
		buf[OptionsOffset] = byte(OptEnd)

		var called bool
		err := frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
			called = true
			return nil
		})
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if called {
			t.Error("callback should not be called for OptEnd")
		}
	})

	t.Run("truncated option header", func(t *testing.T) {
		// Buffer has option type but no length byte
		buf := make([]byte, OptionsOffset+1)
		frm, _ := NewFrame(buf)
		frm.SetMagicCookie(MagicCookie)
		buf[OptionsOffset] = byte(OptHostName) // Not OptEnd, so it needs a length

		var panicked bool
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
				}
			}()
			frm.ForEachOption(func(_ int, opt OptNum, data []byte) error {
				return nil
			})
		}()

		if panicked {
			t.Error("ForEachOption panicked on truncated option header")
		}
	})
}
