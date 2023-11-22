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

const (
	OpCodeSeparatorIndex = 1
)

var (
	// AgentLockingScriptOffset is the offset within the script where the agent locking script
	// starts.
	AgentLockingScriptOffset = 1 // OP_NOTIF

	// RecoverLockingScriptOffset is the offset within the script, not counting the size of the
	// agent locking script, where the recover locking script starts.
	RecoverLockingScriptOffset int
)

func init() {
	RecoverLockingScriptOffset = 1 + // OP_NOTIF
		// Agent locking script
		1 + // OP_NOTIF
		check_signature_preimage.CheckPreimageOutputsHashScript_Size +
		1 + // OP_ELSE
		check_signature_preimage.CheckPreimageOutputsHashScript_Size +
		1 + // OP_ENDIF
		1 // OP_ELSE
}

type Info struct {
	AgentLockingScript bitcoin.Script

	// Only the hash of the approve and refund outputs is contained in the script. Not the locking
	// scripts or the required value. They must be supplied somewhere else.
	ApproveOutputHash bitcoin.Hash32
	RefundOutputHash  bitcoin.Hash32

	RecoverLockingScript bitcoin.Script
	RecoverLockTime      uint32
}

// ApproveMatches returns true if the ApproveOutputHash matches the locking script and value.
func (i Info) ApproveMatches(lockingScript bitcoin.Script, value uint64) bool {
	outputHash := wire.NewTxOut(value, lockingScript).OutputHash()
	return outputHash.Equal(&i.ApproveOutputHash)
}

// RefundMatches returns true if the RefundOutputHash matches the locking script and value.
func (i Info) RefundMatches(lockingScript bitcoin.Script, value uint64) bool {
	outputHash := wire.NewTxOut(value, lockingScript).OutputHash()
	return outputHash.Equal(&i.RefundOutputHash)
}

// CreateScript creates a locking script that can be unlocked 3 ways.
// 1. Authorized by the agent and spending to approve output.
// 2. Authorized by the agent and spending to refund output.
// 3. Authorized by the recoverer after the recover lock time.
func CreateScript(agentLockingScript, approveLockingScript, refundLockingScript bitcoin.Script,
	value uint64, recoverLockingScript bitcoin.Script,
	recoverLockTime uint32) (bitcoin.Script, error) {

	approveOutputHash := wire.NewTxOut(value, approveLockingScript).OutputHash()
	refundOutputHash := wire.NewTxOut(value, refundLockingScript).OutputHash()

	return CreateScriptFromOutputHashes(agentLockingScript, approveOutputHash, refundOutputHash,
		recoverLockingScript, recoverLockTime)
}

func CreateScriptFromOutputHashes(agentLockingScript bitcoin.Script,
	approveOutputHash, refundOutputHash bitcoin.Hash32, recoverLockingScript bitcoin.Script,
	recoverLockTime uint32) (bitcoin.Script, error) {

	agentLockingScript = agentLockingScript.Copy()
	if err := agentLockingScript.AddHardVerify(); err != nil {
		return nil, errors.Wrap(err, "recover add verify")
	}

	agentFunction := bitcoin.ConcatScript(
		agentLockingScript, // Verify this is the agent.

		bitcoin.OP_NOTIF, // OP_0 is approve
		check_signature_preimage.CheckPreimageOutputsHashScript(approveOutputHash, true),
		bitcoin.OP_ELSE, // Assume refund
		check_signature_preimage.CheckPreimageOutputsHashScript(refundOutputHash, true),
		bitcoin.OP_ENDIF,
	)

	recoverLockingScript = recoverLockingScript.Copy()
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
		bitcoin.OP_ELSE,
		recoverFunction,

		bitcoin.OP_ENDIF,

		check_signature_preimage.CreateScript(sigHashType),
	), nil
}

// Check returns the TxNeedsMalleation error if the current tx will need malleation to unlock the
// provided locking script.
func Check(ctx context.Context, tx *wire.MsgTx, inputIndex int, inputLockingScript bitcoin.Script,
	value uint64, hashCache *bitcoin_interpreter.SigHashCache) error {

	// This will return that the script isn't unlocked because we are just checking the
	// "check preimage" function, so we need to ignore other errors.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	if _, err := check_signature_preimage.Unlock(ctx, tx, inputIndex, inputLockingScript,
		OpCodeSeparatorIndex, value, sigHashType, hashCache); err != nil {
		if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
			return err
		}
	}

	return nil
}

func UnlockApprove(ctx context.Context, tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	agentUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimageUnlockingScript, err := check_signature_preimage.Unlock(ctx, tx, inputIndex,
		inputLockingScript, OpCodeSeparatorIndex, inputValue, sigHashType, hashCache)
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

	preimageUnlockingScript, err := check_signature_preimage.Unlock(ctx, tx, inputIndex,
		inputLockingScript, OpCodeSeparatorIndex, inputValue, sigHashType, hashCache)
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

	preimageUnlockingScript, err := check_signature_preimage.Unlock(ctx, tx, inputIndex,
		inputLockingScript, OpCodeSeparatorIndex, inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		preimageUnlockingScript, // verify preimage

		recoverUnlockingScript,
		bitcoin.OP_1, // 1 for recover branch
	), nil
}

// MatchScript parses the information from an agent bitcoin transfer locking script.
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
	items, sigHashType, err = check_signature_preimage.MatchScript(items)
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

func ApproveUnlockingSize(agentUnlockingSize int) int {
	// +2 for the two branch selection bytes for agent unlocks
	return check_signature_preimage.UnlockingSize + agentUnlockingSize + 2
}

func RefundUnlockingSize(agentUnlockingSize int) int {
	// +2 for the two branch selection bytes for agent unlocks
	return check_signature_preimage.UnlockingSize + agentUnlockingSize + 2
}

func RecoverUnlockingSize(recoverUnlockingSize int) int {
	// +1 for the recover branch selection byte for recover unlock
	return check_signature_preimage.UnlockingSize + recoverUnlockingSize + 1
}
