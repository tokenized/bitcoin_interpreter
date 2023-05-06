package check_signature_preimage

import (
	"encoding/binary"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
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

// MatchPreimageOutputsHashScript checks if the beginning of items matches a
// CheckPreimageOutputsHashScript then returns the remaining script items and the outputs hash.
// If it doesn't match it returns ScriptNotMatching.
func MatchPreimageOutputsHashScript(items bitcoin.ScriptItems,
	verify bool) (bitcoin.ScriptItems, *bitcoin.Hash32, error) {

	var err error
	items, err = bitcoin_interpreter.MatchScript(items, Script_Get_OutputsHash)
	if err != nil {
		return nil, nil, errors.Wrap(err, "get outputs hash")
	}

	var hash32Bytes []byte
	items, hash32Bytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, bitcoin.Hash32Size)
	if err != nil {
		return nil, nil, errors.Wrap(err, "hash32")
	}

	hash, err := bitcoin.NewHash32(hash32Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "hash32")
	}

	if verify {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUALVERIFY)
		if err != nil {
			return nil, nil, err
		}
	} else {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUAL)
		if err != nil {
			return nil, nil, err
		}
	}

	return items, hash, nil
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
		Script_Get_InputSequence,
		bitcoin.PushData(inputSequenceBytes[:]),
		opEqual,
	)
}

// MatchPreimageInputSequenceScript checks if the beginning of items matches a
// CheckPreimageInputSequenceScript then returns the remaining script items and the input sequence.
// If it doesn't match it returns ScriptNotMatching.
func MatchPreimageInputSequenceScript(items bitcoin.ScriptItems,
	verify bool) (bitcoin.ScriptItems, uint32, error) {

	var err error
	items, err = bitcoin_interpreter.MatchScript(items, Script_Get_InputSequence)
	if err != nil {
		return nil, 0, errors.Wrap(err, "get input sequence")
	}

	var inputSequenceBytes []byte
	items, inputSequenceBytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, 4)
	if err != nil {
		return nil, 0, errors.Wrap(err, "hash32")
	}

	inputSequence := binary.LittleEndian.Uint32(inputSequenceBytes)

	if verify {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUALVERIFY)
		if err != nil {
			return nil, 0, err
		}
	} else {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUAL)
		if err != nil {
			return nil, 0, err
		}
	}

	return items, inputSequence, nil
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
		Script_Get_InputSequence,
		bitcoin.PushData(maxInputSequenceBytes[:]),
		bitcoin.OP_EQUAL, bitcoin.OP_NOT, // Not equal to max sequence
	)

	if verify {
		return bitcoin.ConcatScript(result, bitcoin.OP_VERIFY)
	}

	return result
}

// MatchPreimageLockTimeScript checks if the beginning of items matches a
// CheckPreimageLockTimeScript then returns the remaining script items and the lock time.
// If it doesn't match it returns ScriptNotMatching.
func MatchPreimageLockTimeScript(items bitcoin.ScriptItems,
	verify bool) (bitcoin.ScriptItems, uint32, error) {

	// Script_Get_LockTime
	var err error
	items, err = bitcoin_interpreter.MatchScript(items, Script_Get_LockTime)
	if err != nil {
		return nil, 0, errors.Wrap(err, "get lock time")
	}

	var lockTimeBytes []byte
	items, lockTimeBytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, 4)
	if err != nil {
		return nil, 0, errors.Wrap(err, "lock time")
	}

	lockTime := binary.LittleEndian.Uint32(lockTimeBytes)

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUALVERIFY)
	if err != nil {
		return nil, 0, err
	}

	// Look ahead
	var lookAhead string
	for i := 0; i < 5; i++ {
		if len(items) <= i {
			break
		}

		lookAhead += " " + items[i].String()
	}

	// Script_Get_InputsSequence
	items, err = bitcoin_interpreter.MatchScript(items, Script_Get_InputSequence)
	if err != nil {
		return nil, 0, errors.Wrap(err, "get input sequence")
	}

	var inputSequenceBytes []byte
	items, inputSequenceBytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, 4)
	if err != nil {
		return nil, 0, errors.Wrap(err, "hash32")
	}

	inputSequence := binary.LittleEndian.Uint32(inputSequenceBytes)

	if inputSequence != wire.MaxTxInSequenceNum {
		return nil, 0, errors.Wrapf(bitcoin_interpreter.ScriptNotMatching,
			"input sequence should be max value: %d", inputSequence)
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUAL)
	if err != nil {
		return nil, 0, err
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_NOT)
	if err != nil {
		return nil, 0, err
	}

	if verify {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_VERIFY)
		if err != nil {
			return nil, 0, err
		}
	}

	return items, lockTime, nil
}
