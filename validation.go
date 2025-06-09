package lneto

import (
	"errors"
	"fmt"
)

type ValidateFlags uint64

const (
	validateReserved ValidateFlags = 1 << iota
	ValidateEvilBit
	validateAllowMultiErrors
)

func (vf ValidateFlags) has(v ValidateFlags) bool {
	return vf&v == v
}

type Validator struct {
	accum       []error
	accumBitpos []BitPosErr
	flags       ValidateFlags
}

func (v *Validator) Flags() ValidateFlags {
	return v.flags
}

func (v *Validator) ResetErr() {
	v.accum = v.accum[:0]
	v.accumBitpos = v.accumBitpos[:0]
}

func (v *Validator) HasError() bool {
	if v.flags.has(validateReserved) {
		panic("reserved bit set")
	}
	return len(v.accum) != 0
}

// ErrPop returns the error(s) accumulated in the validator and clears them.
func (v *Validator) ErrPop() (err error) {
	if len(v.accum) == 1 {
		err = v.accum[0]
		v.ResetErr()
	} else if len(v.accum) > 0 {
		err = errors.Join(v.accum...)
		v.ResetErr()
	}
	return err
}

func (v *Validator) gotErr(err error) {
	v.accum = append(v.accum, err)
}

func (v *Validator) AddError(err error) {
	if err == nil {
		panic("error argument to AddError cannot be nil")
	} else if len(v.accum) != 0 && !v.flags.has(validateAllowMultiErrors) {
		return
	}
	v.accum = append(v.accum, err)
}

func (v *Validator) AddBitPosErr(bitStart, bitLen int, err error) {
	if err == nil {
		panic("err argument to bitPosErr cannot be nil")
	} else if bitLen <= 0 {
		panic("zero bitlen")
	}
	v.accumBitpos = append(v.accumBitpos, BitPosErr{BitStart: bitStart, BitLen: bitLen, Err: err})
	v.accum = append(v.accum, &v.accumBitpos[len(v.accumBitpos)-1])
}

type BitPosErr struct {
	BitStart int
	BitLen   int
	Err      error
}

func (bpe *BitPosErr) Error() string {
	return fmt.Sprintf("%s at bits %d..%d", bpe.Err.Error(), bpe.BitStart, bpe.BitStart+bpe.BitLen)
}
