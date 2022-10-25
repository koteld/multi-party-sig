package ecdsa

import (
	"github.com/koteld/multi-party-sig/pkg/math/curve"
)

const (
	compactSigSize = 65
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()

	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	r := sig.R.XScalar()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}

// ToCompactEth serializes signature to the compact format [R || S || V] format where V is 0 or 1.
func (sig Signature) ToCompactEth() []byte {
	b := make([]byte, compactSigSize)

	bytesR := sig.R.XBytes()
	bytesS := sig.S.Bytes()

	copy(b[0:32], bytesR[:])
	copy(b[32:64], bytesS[:])

	recoveryID := byte(sig.R.IsOddYBit())

	if sig.S.IsOverHalfOrder() {
		recoveryID ^= 0x01
	}

	b[64] = recoveryID

	return b
}
