package agent_bitcoin_tranfer

import (
	"bytes"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/bitcoin_interpreter/check_signature_preimage"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

// AgentBitcoinTransferScript creates a locking script that can be unlocked 3 ways.
// 1. Authorized by the agent and spending to approve output.
// 2. Authorized by the agent and spending to refund output.
// 3. Authorized by the recoverer after the recover lock time.
func AgentBitcoinTransferScript(agentLockingScript, approveLockingScript,
	refundLockingScript bitcoin.Script, value uint64, recoverLockingScript bitcoin.Script,
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

func UnlockAgentBitcoinTransferApprove(tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	agentUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, inputLockingScript, 1,
		inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(preimage), // Preimage

		bitcoin.OP_0, // 0 for approve function
		agentUnlockingScript,
		bitcoin.OP_0, // 0 for agent branch
	), nil
}

func UnlockAgentBitcoinTransferRefund(tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	agentUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, inputLockingScript, 1,
		inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(preimage), // Preimage

		bitcoin.OP_1, // 1 for refund function
		agentUnlockingScript,
		bitcoin.OP_0, // 0 for agent branch
	), nil
}

func UnlockAgentBitcoinTransferRecover(tx *wire.MsgTx, inputIndex int, inputValue uint64,
	inputLockingScript bitcoin.Script,
	recoverUnlockingScript bitcoin.Script) (bitcoin.Script, error) {

	// Use single sig hash type so that only the corresponding output's hash is checked against the
	// approve or refund output hashes.
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	hashCache := &bitcoin_interpreter.SigHashCache{}

	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, inputLockingScript, 1,
		inputValue, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(preimage), // Preimage

		recoverUnlockingScript,
		bitcoin.OP_1, // 1 for recover branch
	), nil
}
