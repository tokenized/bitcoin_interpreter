package p2pkh

import (
	"bytes"
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
)

type Unlocker struct {
	Key                  bitcoin.Key
	Verify               bool
	SigHashType          bitcoin_interpreter.SigHashType
	OpCodeSeparatorIndex int
}

func NewUnlocker(key bitcoin.Key, verify bool, sigHashType bitcoin_interpreter.SigHashType,
	opCodeSeparatorIndex int) *Unlocker {
	return &Unlocker{
		Key:                  key,
		Verify:               verify,
		SigHashType:          sigHashType,
		OpCodeSeparatorIndex: opCodeSeparatorIndex,
	}
}

func (u *Unlocker) Unlock(ctx context.Context, tx bitcoin_interpreter.TransactionWithOutputs,
	inputIndex int, lockingScriptOffset int) (bitcoin.Script, error) {
	return Unlock(tx, inputIndex, lockingScriptOffset, u.Key, u.SigHashType, u.OpCodeSeparatorIndex,
		u.Verify)
}

func (u *Unlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	return UnlockingSize, nil
}

func (u *Unlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	scriptHash, err := MatchScript(lockingScript, u.Verify)
	if err != nil {
		return false
	}

	keyHash := bitcoin.Hash160(u.Key.PublicKey().Bytes())
	return bytes.Equal(scriptHash[:], keyHash)
}

func (u *Unlocker) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	return u.CanUnlock(lockingScript)
}

func (u *Unlocker) Copy() bitcoin_interpreter.Unlocker {
	return &Unlocker{
		Key:                  u.Key.Copy(),
		Verify:               u.Verify,
		SigHashType:          u.SigHashType,
		OpCodeSeparatorIndex: u.OpCodeSeparatorIndex,
	}
}
