package p2pkh

import (
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
)

// UnlockEstimator can't actually unlock anything, but it can estimate the size of P2PKH unlocking
// scripts.
type UnlockEstimator struct{}

func NewUnlockEstimator() *UnlockEstimator {
	return &UnlockEstimator{}
}

func (u *UnlockEstimator) Unlock(ctx context.Context, tx bitcoin_interpreter.TransactionWithOutputs,
	inputIndex int) (bitcoin.Script, error) {
	return u.SubUnlock(ctx, tx, inputIndex, 0)
}

func (u *UnlockEstimator) SubUnlock(ctx context.Context, tx bitcoin_interpreter.TransactionWithOutputs,
	inputIndex int, lockingScriptOffset int) (bitcoin.Script, error) {
	return nil, bitcoin_interpreter.CantSign
}

func (u *UnlockEstimator) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	if _, err := MatchScript(lockingScript, true); err == nil {
		return UnlockingSize, nil
	}
	if _, err := MatchScript(lockingScript, false); err == nil {
		return UnlockingSize, nil
	}

	return 0, bitcoin_interpreter.ScriptNotMatching
}

func (u *UnlockEstimator) CanUnlock(lockingScript bitcoin.Script) bool {
	return false
}

func (u *UnlockEstimator) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *UnlockEstimator) Copy() bitcoin_interpreter.Unlocker {
	return &UnlockEstimator{}
}
