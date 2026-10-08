package lneto

import (
	"errors"
	"strconv"
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
	// err is the first error. It is kept apart from accum, the errors after it,
	// so recording an error does not allocate.
	err         error
	accum       []error
	accumBitpos []BitPosErr
	flags       ValidateFlags
}

func (v *Validator) Flags() ValidateFlags {
	return v.flags
}

func (v *Validator) ResetErr() {
	v.err = nil
	v.accum = v.accum[:0]
	v.accumBitpos = v.accumBitpos[:0]
}

func (v *Validator) HasError() bool {
	if v.flags.has(validateReserved) {
		panic("reserved bit set")
	}
	return v.err != nil
}

// ErrPop returns the error(s) accumulated in the validator and clears them.
func (v *Validator) ErrPop() (err error) {
	if len(v.accum) == 0 {
		err = v.err
	} else {
		err = errors.Join(append([]error{v.err}, v.accum...)...)
	}
	v.ResetErr()
	return err
}

func (v *Validator) gotErr(err error) {
	if v.err == nil {
		v.err = err
	} else {
		v.accum = append(v.accum, err)
	}
}

func (v *Validator) AddError(err error) {
	if err == nil {
		panic("error argument to AddError cannot be nil")
	} else if v.err != nil && !v.flags.has(validateAllowMultiErrors) {
		return
	}
	v.gotErr(err)
}

func (v *Validator) AddBitPosErr(bitStart, bitLen int, err error) {
	if err == nil {
		panic("err argument to bitPosErr cannot be nil")
	} else if bitLen <= 0 {
		panic("zero bitlen")
	}
	v.accumBitpos = append(v.accumBitpos, BitPosErr{BitStart: bitStart, BitLen: bitLen, Err: err})
	v.gotErr(&v.accumBitpos[len(v.accumBitpos)-1])
}

type BitPosErr struct {
	BitStart int
	BitLen   int
	Err      error
}

func (bpe *BitPosErr) Error() string {
	return bpe.Err.Error()
}

func (bpe *BitPosErr) AppendError(dst []byte) []byte {
	dst = append(dst, bpe.Err.Error()...)
	dst = append(dst, ": bits "...)
	dst = strconv.AppendUint(dst, uint64(bpe.BitStart), 10)
	dst = append(dst, '.', '.')
	dst = strconv.AppendUint(dst, uint64(bpe.BitStart+bpe.BitLen), 10)
	return dst
}
