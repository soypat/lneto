package lneto

// ReaderBuffered gives access to unread transport data without copying it.
type ReaderBuffered interface {
	// BufferedData returns unread bytes without consuming them. data1 follows data0 when the data wraps.
	// The slices are valid until the next LinearizeInput or DiscardInput.
	BufferedData() (data0, data1 []byte)
	// LinearizeInput moves unread bytes so BufferedData returns them all in data0.
	LinearizeInput()
	// DiscardInput consumes n unread bytes.
	DiscardInput(n int) error
	// WaitInput blocks until n bytes are unread. It returns ErrBufferFull if n is more than the buffer holds.
	WaitInput(n int) error
}
