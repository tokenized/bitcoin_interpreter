package check_signature_preimage

import (
	"encoding/binary"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
)

// CheckPreimageOutputsHashScript creates a script section that verifies that the preimage in the
// top stack item contains the specified outputs hash. It leaves the preimage on the stack.
func CheckPreimageOutputsHashScript(outputsHash bitcoin.Hash32, verify bool) bitcoin.Script {
	opEqual := bitcoin.OP_EQUAL
	if verify {
		opEqual = bitcoin.OP_EQUALVERIFY
	}

	return bitcoin.ConcatScript(
		Script_Get_OutputsHash,
		bitcoin.PushData(outputsHash[:]),
		opEqual,
	)
}

// CheckPreimageInputSequenceScript creates a script section that verifies that the preimage in the
// top stack item contains the specified sequence in the input being checked. It leaves the preimage
// on the stack.
func CheckPreimageInputSequenceScript(inputSequence uint32, verify bool) bitcoin.Script {
	var inputSequenceBytes [4]byte
	binary.LittleEndian.PutUint32(inputSequenceBytes[:], inputSequence)

	opEqual := bitcoin.OP_EQUAL
	if verify {
		opEqual = bitcoin.OP_EQUALVERIFY
	}

	return bitcoin.ConcatScript(
		Script_Get_InputsSequence,
		bitcoin.PushData(inputSequenceBytes[:]),
		opEqual,
	)
}

// CheckPreimageLockTimeScript creates a script section that verifies that the preimage in the top
// stack item contains the specified lock time and the input being checked has a sequnce less than
// the max sequence. It leaves the preimage on the stack.
// Note: for the lock time to be applied one of the inputs must have a sequence less than the max
// sequence value.
func CheckPreimageLockTimeScript(lockTime uint32, verify bool) bitcoin.Script {
	var lockTimeBytes [4]byte
	binary.LittleEndian.PutUint32(lockTimeBytes[:], lockTime)

	var maxInputSequenceBytes [4]byte
	binary.LittleEndian.PutUint32(maxInputSequenceBytes[:], wire.MaxTxInSequenceNum)

	result := bitcoin.ConcatScript(
		Script_Get_LockTime,
		bitcoin.PushData(lockTimeBytes[:]),
		bitcoin.OP_EQUALVERIFY, // This uses verify because it isn't at the end of the script.
		Script_Get_InputsSequence,
		bitcoin.PushData(maxInputSequenceBytes[:]),
		bitcoin.OP_EQUAL, bitcoin.OP_NOT, // Not equal to max sequence
	)

	if verify {
		return bitcoin.ConcatScript(result, bitcoin.OP_VERIFY)
	}

	return result
}
