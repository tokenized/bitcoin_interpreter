package agent_bitcoin_transfer

import (
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/bitcoin_interpreter/check_signature_preimage"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

type AgentApproveUnlocker struct {
	AgentUnlocker bitcoin_interpreter.Unlocker // unlocks agent locking script
}

func NewAgentApproveUnlocker(agentUnlocker bitcoin_interpreter.Unlocker) *AgentApproveUnlocker {
	return &AgentApproveUnlocker{
		AgentUnlocker: agentUnlocker,
	}
}

func (u *AgentApproveUnlocker) Unlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int) (bitcoin.Script, error) {

	return u.SubUnlock(ctx, tx, inputIndex, 0)
}

func (u *AgentApproveUnlocker) SubUnlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int,
	lockingScriptOffset int) (bitcoin.Script, error) {

	msgTx := tx.GetMsgTx()
	txout, err := tx.InputOutput(inputIndex)
	if err != nil {
		return nil, errors.Wrap(err, "input output")
	}

	agentUnlockingScript, err := u.AgentUnlocker.SubUnlock(ctx, tx, inputIndex,
		lockingScriptOffset+1)
	if err != nil {
		return nil, errors.Wrap(err, "agent")
	}

	unlockingScript, err := UnlockApprove(ctx, msgTx, inputIndex, txout.Value, txout.LockingScript,
		agentUnlockingScript)
	if err != nil {
		return nil, errors.Wrap(err, "approve")
	}

	return unlockingScript, nil
}

func (u *AgentApproveUnlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "match")
	}

	agentUnlockingSize, err := u.AgentUnlocker.UnlockingSize(info.AgentLockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "agent")
	}

	// +2 for the two branch selection bytes for agent unlocks
	return check_signature_preimage.UnlockingSize + agentUnlockingSize + 2, nil
}

// CanUnlock returns true if the locking script matches the agent. It does not check if the output
// is correct for the approve.
func (u *AgentApproveUnlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return false
	}

	return u.AgentUnlocker.CanUnlock(info.AgentLockingScript)
}

func (u *AgentApproveUnlocker) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *AgentApproveUnlocker) Copy() bitcoin_interpreter.Unlocker {
	return &AgentApproveUnlocker{
		AgentUnlocker: u.AgentUnlocker.Copy(),
	}
}

type AgentRefundUnlocker struct {
	AgentUnlocker bitcoin_interpreter.Unlocker // unlocks agent locking script
}

func NewAgentRefundUnlocker(agentUnlocker bitcoin_interpreter.Unlocker) *AgentRefundUnlocker {
	return &AgentRefundUnlocker{
		AgentUnlocker: agentUnlocker,
	}
}

func (u *AgentRefundUnlocker) Unlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int) (bitcoin.Script, error) {

	return u.SubUnlock(ctx, tx, inputIndex, 0)
}

func (u *AgentRefundUnlocker) SubUnlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int,
	lockingScriptOffset int) (bitcoin.Script, error) {

	msgTx := tx.GetMsgTx()
	txout, err := tx.InputOutput(inputIndex)
	if err != nil {
		return nil, errors.Wrap(err, "input output")
	}

	agentUnlockingScript, err := u.AgentUnlocker.SubUnlock(ctx, tx, inputIndex,
		lockingScriptOffset+1)
	if err != nil {
		return nil, errors.Wrap(err, "agent")
	}

	unlockingScript, err := UnlockRefund(ctx, msgTx, inputIndex, txout.Value, txout.LockingScript,
		agentUnlockingScript)
	if err != nil {
		return nil, errors.Wrap(err, "refund")
	}

	return unlockingScript, nil
}

func (u *AgentRefundUnlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "match")
	}

	agentUnlockingSize, err := u.AgentUnlocker.UnlockingSize(info.AgentLockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "agent")
	}

	// +2 for the two branch selection bytes for agent unlocks
	return check_signature_preimage.UnlockingSize + agentUnlockingSize + 2, nil
}

// CanUnlock returns true if the locking script matches the agent. It does not check if the output
// is correct for the refund.
func (u *AgentRefundUnlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return false
	}

	return u.AgentUnlocker.CanUnlock(info.AgentLockingScript)
}

func (u *AgentRefundUnlocker) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *AgentRefundUnlocker) Copy() bitcoin_interpreter.Unlocker {
	return &AgentRefundUnlocker{
		AgentUnlocker: u.AgentUnlocker.Copy(),
	}
}

type RecoverUnlocker struct {
	SubUnlocker bitcoin_interpreter.Unlocker // unlocks embedded recover locking script
}

func NewRecoverUnlocker(subUnlocker bitcoin_interpreter.Unlocker) *RecoverUnlocker {
	return &RecoverUnlocker{
		SubUnlocker: subUnlocker,
	}
}

func (u *RecoverUnlocker) Unlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int) (bitcoin.Script, error) {

	return u.SubUnlock(ctx, tx, inputIndex, 0)
}

func (u *RecoverUnlocker) SubUnlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int,
	lockingScriptOffset int) (bitcoin.Script, error) {

	msgTx := tx.GetMsgTx()
	txout, err := tx.InputOutput(inputIndex)
	if err != nil {
		return nil, errors.Wrap(err, "input output")
	}

	info, err := MatchScript(txout.LockingScript)
	if err != nil {
		return nil, errors.Wrap(err, "match")
	}

	subUnlockingScript, err := u.SubUnlocker.SubUnlock(ctx, tx, inputIndex, lockingScriptOffset+
		len(info.AgentLockingScript)+RecoverLockingScriptOffset)
	if err != nil {
		return nil, errors.Wrap(err, "sub")
	}

	unlockingScript, err := UnlockRecover(ctx, msgTx, inputIndex, txout.Value, txout.LockingScript,
		subUnlockingScript)
	if err != nil {
		return nil, errors.Wrap(err, "recover")
	}

	return unlockingScript, nil
}

func (u *RecoverUnlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "match")
	}

	recoverUnlockingSize, err := u.SubUnlocker.UnlockingSize(info.RecoverLockingScript)
	if err != nil {
		return 0, errors.Wrap(err, "recover")
	}

	// +1 for the branch selection byte for recover unlock
	return check_signature_preimage.UnlockingSize + recoverUnlockingSize + 1, nil
}

// CanUnlock returns true if the locking script matches the recover. It does not check if the
// input sequence and lock time are valid for the unlock.
func (u *RecoverUnlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return false
	}

	return u.SubUnlocker.CanUnlock(info.RecoverLockingScript)
}

func (u *RecoverUnlocker) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *RecoverUnlocker) Copy() bitcoin_interpreter.Unlocker {
	return &RecoverUnlocker{
		SubUnlocker: u.SubUnlocker.Copy(),
	}
}
