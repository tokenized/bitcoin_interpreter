package agent_bitcoin_transfer

import (
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
)

// ApproveUnlockEstimator can't actually unlock anything, but it can estimate the size of P2PKH unlocking
// scripts.
type ApproveUnlockEstimator struct {
	SubEstimators bitcoin_interpreter.Unlocker
}

func NewApproveUnlockEstimator(subEstimators bitcoin_interpreter.Unlocker) *ApproveUnlockEstimator {
	return &ApproveUnlockEstimator{
		SubEstimators: subEstimators,
	}
}

func (u *ApproveUnlockEstimator) Unlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs,
	inputIndex int) (bitcoin.Script, error) {
	return u.SubUnlock(ctx, tx, inputIndex, 0)
}

func (u *ApproveUnlockEstimator) SubUnlock(ctx context.Context,
	tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int,
	lockingScriptOffset int) (bitcoin.Script, error) {
	return nil, bitcoin_interpreter.CantSign
}

func (u *ApproveUnlockEstimator) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	info, err := MatchScript(lockingScript)
	if err != nil {
		return 0, bitcoin_interpreter.ScriptNotMatching
	}

	if subUnlockingSize, err := u.SubEstimators.UnlockingSize(info.AgentLockingScript); err == nil {
		return ApproveUnlockingSize(subUnlockingSize), nil
	}

	return 0, bitcoin_interpreter.ScriptNotMatching
}

func (u *ApproveUnlockEstimator) CanUnlock(lockingScript bitcoin.Script) bool {
	return false
}

func (u *ApproveUnlockEstimator) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *ApproveUnlockEstimator) Copy() bitcoin_interpreter.Unlocker {
	return &ApproveUnlockEstimator{}
}
