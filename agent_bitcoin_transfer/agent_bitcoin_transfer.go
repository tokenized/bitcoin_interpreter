package agent_bitcoin_transfer

import (
	"bytes"
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/bitcoin_interpreter/check_signature_preimage"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

type Info struct {
	AgentLockingScript bitcoin.Script

	// Only the hash of the approve and refund outputs is contained in the script. Not the locking
	// scripts or the required value. They must be supplied somewhere else.
	ApproveOutputHash bitcoin.Hash32
	RefundOutputHash  bitcoin.Hash32

	RecoverLockingScript bitcoin.Script
	RecoverLockTime      uint32
}

// CreateScript creates a locking script that can be unlocked 3 ways.
// 1. Authorized by the agent and spending to approve output.
// 2. Authorized by the agent and spending to refund output.
// 3. Authorized by the recoverer after the recover lock time.
func CreateScript(agentLockingScript, approveLockingScript, refundLockingScript bitcoin.Script,
	value uint64, recoverLockingScript bitcoin.Script,
	recoverLockTime uint32) (bitcoin.Script, error) {

	if err := agentLockingScript.AddHardVerify(); err != nil {
		return nil, errors.Wrap(err, "recover add verify")
	}

	approveOutput := wire.NewTxOut(value, approveLockingScript)
	var approveOutputBuf bytes.Buffer
	approveOutput.Serialize(&approveOutputBuf, 0, 0)
	approveOutputsHash, _ := bitcoin.NewHash32(bitcoin.DoubleSha256(approveOutputBuf.Bytes()))

	refundOutput := wire.NewTxOut(value, refundLockingScript)
	var refundOutputBuf bytes.Buffer
	refundOutput.Serialize(&refundOutputBuf, 0, 0)
	refundOutputsHash, _ := bitcoin.NewHash32(bitcoin.DoubleSha256(refundOutputBuf.Bytes()))

	agentFunction := bitcoin.ConcatScript(
		agentLockingScript, // Verify this is the agent.

		bitcoin.OP_NOTIF, // OP_0 is approve
		check_signature_preimage.CheckPreimageOutputsHashScript(*approveOutputsHash, true),
		bitcoin.OP_ELSE, // Assume refund
		check_signature_preimage.CheckPreimageOutputsHashScript(*refundOutputsHash, true),
		bitcoin.OP_ENDIF,
	)

	if err := recoverLockingScript.AddHardVerify(); err != nil {
		return nil, errors.Wrap(err, "recover add verify")
	}

	recoverFunction := bitcoin.ConcatScript(
		recoverLockingScript, // Verify they are authorized to recover.
		check_signature_preimage.CheckPreimageLockTimeScript(recoverLockTime, true),
	)

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle

	// Provide option to either approve, refund, or recover
	return bitcoin.ConcatScript(
		// OP_0 means to execute the agent branch.
		bitcoin.OP_NOTIF,
		agentFunction,

		// Assume the recover branch.
		bitcoin.OP_ELSE, recoverFunction,

		bitcoin.OP_ENDIF,

		check_signature_preimage.CheckSignaturePreimageScript(sigHashType),
	), nil
}

func UnlockApprove(ctx context.Context, tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	agentUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimageUnlockingScript, err := check_signature_preimage.UnlockSignaturePreimageScript(ctx, tx,
		inputIndex, inputLockingScript, 1, inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		preimageUnlockingScript, // verify preimage

		bitcoin.OP_0, // 0 for approve function
		agentUnlockingScript,
		bitcoin.OP_0, // 0 for agent branch
	), nil
}

func UnlockRefund(ctx context.Context, tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	agentUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimageUnlockingScript, err := check_signature_preimage.UnlockSignaturePreimageScript(ctx, tx,
		inputIndex, inputLockingScript, 1, inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		preimageUnlockingScript, // verify preimage

		bitcoin.OP_1, // 1 for refund function
		agentUnlockingScript,
		bitcoin.OP_0, // 0 for agent branch
	), nil
}

func UnlockRecover(ctx context.Context, tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	recoverUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimageUnlockingScript, err := check_signature_preimage.UnlockSignaturePreimageScript(ctx, tx,
		inputIndex, inputLockingScript, 1, inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		preimageUnlockingScript, // verify preimage

		recoverUnlockingScript,
		bitcoin.OP_1, // 1 for recover branch
	), nil
}

// MatchSignaturePreimageScript parses the information from an agent bitcoin transfer locking script.
// Right now this doesn't support when sub-scripts like agent or recover locking scripts contain
// OP_NOTIF.
func MatchScript(lockingScript bitcoin.Script) (*Info, error) {
	result := &Info{}

	items, err := bitcoin.ParseScriptItems(bytes.NewReader(lockingScript), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse script")
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_NOTIF)
	if err != nil {
		return nil, errors.Wrap(err, "first")
	}

	if len(items) == 0 {
		return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching, "ends after first OP_NOTIF")
	}

	// Parse agent locking script section.
	var agentLockingScriptItems bitcoin.ScriptItems
	for items[0].Type != bitcoin.ScriptItemTypeOpCode || items[0].OpCode != bitcoin.OP_NOTIF {
		agentLockingScriptItems = append(agentLockingScriptItems, items[0])

		if len(items) == 0 {
			return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching,
				"second OP_NOTIF not found")
		}
		items = items[1:]
	}

	if len(agentLockingScriptItems) == 0 {
		return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching, "empty agent locking script")
	}

	if agentLockingScript, err := agentLockingScriptItems.Script(); err != nil {
		return nil, errors.Wrap(err, "agent locking script")
	} else {
		result.AgentLockingScript = agentLockingScript
	}

	if len(items) == 0 {
		return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching,
			"ends after second OP_NOTIF")
	}
	items = items[1:]

	// Parse check approve output hash script.
	var approveOutputHash *bitcoin.Hash32
	items, approveOutputHash, err = check_signature_preimage.MatchPreimageOutputsHashScript(items,
		true)
	if err != nil {
		return nil, errors.Wrap(err, "approve outputs hash")
	}
	result.ApproveOutputHash = *approveOutputHash

	// Parse OP_ELSE for first OP_NOTIF.
	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_ELSE)
	if err != nil {
		return nil, errors.Wrap(err, "for first OP_NOTIF")
	}

	// Parse check refund output hash script.
	var refundOutputHash *bitcoin.Hash32
	items, refundOutputHash, err = check_signature_preimage.MatchPreimageOutputsHashScript(items,
		true)
	if err != nil {
		return nil, errors.Wrap(err, "refund outputs hash")
	}
	result.RefundOutputHash = *refundOutputHash

	// Parse OP_ENDIF for first OP_NOTIF.
	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_ENDIF)
	if err != nil {
		return nil, errors.Wrap(err, "for first OP_NOTIF")
	}

	// Parse OP_ELSE for second OP_NOTIF.
	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_ELSE)
	if err != nil {
		return nil, errors.Wrap(err, "for second OP_NOTIF")
	}

	// Parse recover locking script. Check lock time script is right after it, so that is how we
	// know it ends.
	var lockTime uint32
	var recoverLockingScriptItems bitcoin.ScriptItems
	var afterLockTimeItems bitcoin.ScriptItems
	for {
		// Attempt match with check preimage lock time script.
		afterLockTimeItems, lockTime, err = check_signature_preimage.MatchPreimageLockTimeScript(items,
			true)
		if err == nil {
			items = afterLockTimeItems
			result.RecoverLockTime = lockTime
			break
		}

		// Still in recover locking script
		if len(items) == 0 {
			return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching,
				"ends after recover locking script")
		}

		recoverLockingScriptItems = append(recoverLockingScriptItems, items[0])
		items = items[1:]
	}

	if len(recoverLockingScriptItems) == 0 {
		return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching,
			"empty recover locking script")
	}

	if recoverLockingScript, err := recoverLockingScriptItems.Script(); err != nil {
		return nil, errors.Wrap(err, "recover locking script")
	} else {
		result.RecoverLockingScript = recoverLockingScript
	}

	if items[0].Type != bitcoin.ScriptItemTypeOpCode || items[0].OpCode != bitcoin.OP_ENDIF {
		return nil, errors.Wrapf(bitcoin_interpreter.ScriptNotMatching, "second OP_ENDIF: %s",
			items[0])
	}
	items = items[1:]

	// Parse check signature preimage script.
	var sigHashType bitcoin_interpreter.SigHashType
	items, sigHashType, err = check_signature_preimage.MatchSignaturePreimageScript(items)
	if err != nil {
		return nil, errors.Wrap(err, "signature preimage")
	}

	if len(items) != 0 {
		return nil, errors.Wrap(bitcoin_interpreter.ScriptNotMatching, "script after preimage check")
	}

	if sigHashType != bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashSingle {
		return nil, errors.Wrapf(bitcoin_interpreter.ScriptNotMatching,
			"wrong sig hash type : 0x%02x should be 0x%02x", sigHashType,
			bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashSingle)
	}

	return result, nil
}
