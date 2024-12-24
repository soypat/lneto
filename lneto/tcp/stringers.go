// Code generated by "stringer -type=State -linecomment -output stringers.go ."; DO NOT EDIT.

package tcp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[StateClosed-0]
	_ = x[StateListen-1]
	_ = x[StateSynRcvd-2]
	_ = x[StateSynSent-3]
	_ = x[StateEstablished-4]
	_ = x[StateFinWait1-5]
	_ = x[StateFinWait2-6]
	_ = x[StateClosing-7]
	_ = x[StateTimeWait-8]
	_ = x[StateCloseWait-9]
	_ = x[StateLastAck-10]
}

const _State_name = "CLOSEDLISTENSYN-RECEIVEDSYN-SENTESTABLISHEDFIN-WAIT-1FIN-WAIT-2CLOSINGTIME-WAITCLOSE-WAITLAST-ACK"

var _State_index = [...]uint8{0, 6, 12, 24, 32, 43, 53, 63, 70, 79, 89, 97}

func (i State) String() string {
	if i >= State(len(_State_index)-1) {
		return "State(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _State_name[_State_index[i]:_State_index[i+1]]
}