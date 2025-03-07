package ot

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"

	"github.com/cronokirby/safenum"
	"github.com/koteld/multi-party-sig/internal/params"
	"github.com/koteld/multi-party-sig/pkg/hash"
	"github.com/koteld/multi-party-sig/pkg/math/curve"
	"github.com/koteld/multi-party-sig/pkg/math/sample"
	zksch "github.com/koteld/multi-party-sig/pkg/zk/sch"
	"github.com/zeebo/blake3"
)

// RandomOTSetupSendMessage is the message generated by the sender of the OT.
type RandomOTSetupSendMessage struct {
	// A public key used for subsequent random OTs.
	B curve.Point
	// A proof of the discrete log of this public key.
	BProof *zksch.Proof
}

func EmptyRandomOTSetupSendMessage(group curve.Curve) *RandomOTSetupSendMessage {
	return &RandomOTSetupSendMessage{B: group.NewPoint(), BProof: zksch.EmptyProof(group)}
}

// RandomOTSendSetup is the result that should be saved for the sender.
//
// This result can be used for multiple random OTs later.
type RandomOTSendSetup struct {
	// A secret key used for subsequent random OTs.
	b curve.Scalar
	// The matching public key.
	_B curve.Point
	// b * _B
	_bB curve.Point
}

// RandomOTSetupSend runs the Sender's part of the setup protocol for Random OT.
//
// The hash should be used to tie the execution of the protocol to the ambient context,
// if that's desired.
//
// This setup can be done once and then used for multiple executions.
func RandomOTSetupSend(hash *hash.Hash, group curve.Curve) (*RandomOTSetupSendMessage, *RandomOTSendSetup) {
	b := sample.Scalar(rand.Reader, group)
	B := b.ActOnBase()
	BProof := zksch.NewProof(hash, B, b, nil)
	return &RandomOTSetupSendMessage{B: B, BProof: BProof}, &RandomOTSendSetup{_B: B, b: b, _bB: b.Act(B)}
}

// RandomOTReceiveSetup is the result that should be saved for the receiver.
type RandomOTReceiveSetup struct {
	// The public key for the sender, used for subsequent random OTs.
	_B curve.Point
}

// RandomOTSetupReceive runs the Receiver's part of the setup protocol for Random OT.
//
// The hash should be used to tie the execution of the protocol to the ambient context,
// if that's desired.
//
// This setup can be done once and then used for multiple executions.
func RandomOTSetupReceive(hash *hash.Hash, msg *RandomOTSetupSendMessage) (*RandomOTReceiveSetup, error) {
	if !msg.BProof.Verify(hash, msg.B, nil) {
		return nil, fmt.Errorf("RandomOTSetupReceive: Schnorr proof failed to verify")
	}

	return &RandomOTReceiveSetup{_B: msg.B}, nil
}

// RandomOTReceiver contains the state needed for a single execution of a Random OT.
//
// This should be created from a saved setup, for each execution.
type RandomOTReceiever struct {
	// After setup
	hash  *blake3.Hasher
	group curve.Curve
	// Which random message we want to receive.
	choice safenum.Choice
	// The public key of the sender.
	_B curve.Point
	// After Round1

	// The random message we've received.
	randChoice [params.OTBytes]byte
	// After Round2

	// The challenge sent to use by the sender.
	receivedChallenge [params.OTBytes]byte
	// H(H(randChoice)), used to avoid redundant calculations.
	hh_randChoice [params.OTBytes]byte
}

// NewRandomOTReceiver sets up the receiver's state for a single Random OT.
//
// The nonce should be 32 bytes, and must be different if a single setup is used for multiple OTs.
//
// choice indicates which of the two random messages should be received.
func NewRandomOTReceiver(nonce []byte, result *RandomOTReceiveSetup, choice safenum.Choice) (out RandomOTReceiever) {
	// This will only error if the nonce has the wrong length, which is a programmer error
	var err error
	out.hash, err = blake3.NewKeyed(nonce)
	if err != nil {
		panic(err)
	}
	out.group = result._B.Curve()
	out.choice = choice
	out._B = result._B

	return
}

// RandomOTReceiveRound1Message is the first message sent by the receiver in a Random OT.
type RandomOTReceiveRound1Message struct {
	ABytes []byte
}

// Round1 executes the receiver's side of round 1 of a Random OT.
//
// This is the starting point for a Random OT.
func (r *RandomOTReceiever) Round1() (outMsg RandomOTReceiveRound1Message, err error) {
	// We sample a <- Z_q, and then compute
	//   A = a * G + w * B
	//   randChoice = H(a * B)
	a := sample.Scalar(rand.Reader, r.group)
	A := a.ActOnBase()
	outMsg.ABytes, err = A.MarshalBinary()
	if err != nil {
		return
	}
	A = A.Add(r._B)
	_APlusBBytes, err := A.MarshalBinary()
	if err != nil {
		return outMsg, err
	}
	mask := -byte(r.choice)
	for i := 0; i < len(outMsg.ABytes) && i < len(_APlusBBytes); i++ {
		outMsg.ABytes[i] ^= (mask & (outMsg.ABytes[i] ^ _APlusBBytes[i]))
	}

	abBytes, err := a.Act(r._B).MarshalBinary()
	if err != nil {
		return outMsg, err
	}
	_, _ = r.hash.Write(abBytes)
	_, _ = r.hash.Digest().Read(r.randChoice[:])

	return
}

// RandomOTReceiveRound2Message is the second message sent by the receiver in a Random OT.
type RandomOTReceiveRound2Message struct {
	// A Response to the challenge submitted by the sender.
	Response [params.OTBytes]byte
}

// Round2 executes the receiver's side of round 2 of a Random OT.
func (r *RandomOTReceiever) Round2(msg *RandomOTSendRound1Message) (outMsg RandomOTReceiveRound2Message) {
	// response = H(H(randW)) ^ (w * challenge).
	r.receivedChallenge = msg.Challenge

	r.hash.Reset()
	_, _ = r.hash.Write(r.randChoice[:])
	_, _ = r.hash.Digest().Read(outMsg.Response[:])
	r.hash.Reset()
	_, _ = r.hash.Write(outMsg.Response[:])
	_, _ = r.hash.Digest().Read(outMsg.Response[:])

	copy(r.hh_randChoice[:], outMsg.Response[:])

	mask := -byte(r.choice)
	for i := 0; i < len(msg.Challenge); i++ {
		outMsg.Response[i] ^= mask & msg.Challenge[i]
	}

	return
}

// Round3 finalizes the result for the receiver, performing verification.
//
// The random choice is returned as the first argument, upon success.
func (r *RandomOTReceiever) Round3(msg *RandomOTSendRound2Message) ([params.OTBytes]byte, error) {
	var actualChallenge, h_decommit0, h_decommit1 [params.OTBytes]byte
	r.hash.Reset()
	_, _ = r.hash.Write(msg.Decommit0[:])
	_, _ = r.hash.Digest().Read(h_decommit0[:])

	r.hash.Reset()
	_, _ = r.hash.Write(msg.Decommit1[:])
	_, _ = r.hash.Digest().Read(h_decommit1[:])

	for i := 0; i < params.OTBytes; i++ {
		actualChallenge[i] = h_decommit0[i] ^ h_decommit1[i]
	}

	if subtle.ConstantTimeCompare(r.receivedChallenge[:], actualChallenge[:]) != 1 {
		return r.randChoice, fmt.Errorf("RandomOTReceive Round 3: incorrect decommitment")
	}

	// Assign the decommitment hash to the one matching our own choice
	h_decommitChoice := h_decommit0
	mask := -byte(r.choice)
	for i := 0; i < params.OTBytes; i++ {
		h_decommitChoice[i] ^= mask & (h_decommitChoice[i] ^ h_decommit1[i])
	}
	if subtle.ConstantTimeCompare(h_decommitChoice[:], r.hh_randChoice[:]) != 1 {
		return r.randChoice, fmt.Errorf("RandomOTReceive Round 3: incorrect decommitment")
	}

	return r.randChoice, nil
}

// RandomOTSender holds the state needed for a single execution of a Random OT.
//
// This should be created from a saved setup, for each execution.
type RandomOTSender struct {
	// After setup
	hash  *blake3.Hasher
	group curve.Curve
	b     curve.Scalar
	_B    curve.Point
	_bB   curve.Point
	// After round 1
	rand0 [params.OTBytes]byte
	rand1 [params.OTBytes]byte

	decommit0 [params.OTBytes]byte
	decommit1 [params.OTBytes]byte

	h_decommit0 [params.OTBytes]byte
}

// NewRandomOTSender sets up the receiver's state for a single Random OT.
//
// The nonce should be 32 bytes, and must be different if a single setup is used for multiple OTs.
func NewRandomOTSender(nonce []byte, result *RandomOTSendSetup) (out RandomOTSender) {
	// This will only error if the nonce has the wrong length, which is a programmer error
	var err error
	out.hash, err = blake3.NewKeyed(nonce)
	if err != nil {
		panic(err)
	}
	out.group = result.b.Curve()
	out.b = result.b
	out._B = result._B
	out._bB = result._bB

	return
}

// RandomOTSendRound1Message is the message sent by the sender in round 1.
type RandomOTSendRound1Message struct {
	Challenge [params.OTBytes]byte
}

// Round1 executes the sender's side of round 1 for a Random OT.
func (r *RandomOTSender) Round1(msg *RandomOTReceiveRound1Message) (outMsg RandomOTSendRound1Message, err error) {
	// We can compute the two random pads:
	//    rand0 = H(b * A)
	//    rand1 = H(b * (A - B))
	_A := r.group.NewPoint()
	if err = _A.UnmarshalBinary(msg.ABytes); err != nil {
		return
	}
	bA := r.b.Act(_A)

	r.hash.Reset()
	bABytes, err := bA.MarshalBinary()
	if err != nil {
		return outMsg, err
	}
	_, _ = r.hash.Write(bABytes)
	_, _ = r.hash.Digest().Read(r.rand0[:])

	r.hash.Reset()
	bAMinusBBytes, err := bA.Sub(r._bB).MarshalBinary()
	if err != nil {
		return outMsg, err
	}
	_, _ = r.hash.Write(bAMinusBBytes)
	_, _ = r.hash.Digest().Read(r.rand1[:])

	// Compute the challenge:
	//   H(H(rand0)) ^ H(H(rand1))
	r.hash.Reset()
	_, _ = r.hash.Write(r.rand0[:])
	_, _ = r.hash.Digest().Read(r.decommit0[:])

	r.hash.Reset()
	_, _ = r.hash.Write(r.rand1[:])
	_, _ = r.hash.Digest().Read(r.decommit1[:])

	r.hash.Reset()
	_, _ = r.hash.Write(r.decommit0[:])
	_, _ = r.hash.Digest().Read(r.h_decommit0[:])

	r.hash.Reset()
	_, _ = r.hash.Write(r.decommit1[:])
	_, _ = r.hash.Digest().Read(outMsg.Challenge[:])

	for i := 0; i < params.OTBytes; i++ {
		outMsg.Challenge[i] ^= r.h_decommit0[i]
	}

	return
}

// RandomOTSendRound2Message is the message sent by the sender in round 2 of a Random OT.
type RandomOTSendRound2Message struct {
	Decommit0 [params.OTBytes]byte
	Decommit1 [params.OTBytes]byte
}

// RandomOTSendResult is the result for a sender in a Random OT.
//
// We have two random results with a symmetric security parameter's worth of bits each.
type RandomOTSendResult struct {
	// Rand0 is the first random message.
	Rand0 [params.OTBytes]byte
	// Rand1 is the second random message.
	Rand1 [params.OTBytes]byte
}

// Round2 executes the sender's side of round 2 in a Random OT.
func (r *RandomOTSender) Round2(msg *RandomOTReceiveRound2Message) (outMsg RandomOTSendRound2Message, res RandomOTSendResult, err error) {
	if subtle.ConstantTimeCompare(msg.Response[:], r.h_decommit0[:]) != 1 {
		return outMsg, res, fmt.Errorf("RandomOTSender Round2: invalid response")
	}

	outMsg.Decommit0 = r.decommit0
	outMsg.Decommit1 = r.decommit1
	res.Rand0 = r.rand0
	res.Rand1 = r.rand1

	return
}
