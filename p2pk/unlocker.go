package p2pk

import (
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
)

type Unlocker struct {
	Key                  bitcoin.Key
	Verify               bool // Verify is only used with embedded scripts
	SigHashType          bitcoin_interpreter.SigHashType
	OpCodeSeparatorIndex int
}

func NewUnlocker(key bitcoin.Key) *Unlocker {
	return &Unlocker{
		Key:                  key,
		Verify:               false,
		SigHashType:          bitcoin_interpreter.SigHashDefault,
		OpCodeSeparatorIndex: -1,
	}
}

func NewUnlockerFull(key bitcoin.Key, verify bool, sigHashType bitcoin_interpreter.SigHashType,
	opCodeSeparatorIndex int) *Unlocker {
	return &Unlocker{
		Key:                  key,
		Verify:               verify,
		SigHashType:          sigHashType,
		OpCodeSeparatorIndex: opCodeSeparatorIndex,
	}
}

func (u *Unlocker) Unlock(ctx context.Context,
	writeSigPreimage bitcoin_interpreter.WriteSignaturePreimage,
	lockingScript bitcoin.Script) (bitcoin.Script, error) {
	return u.SubUnlock(ctx, writeSigPreimage, lockingScript, 0)
}

func (u *Unlocker) SubUnlock(ctx context.Context,
	writeSigPreimage bitcoin_interpreter.WriteSignaturePreimage, lockingScript bitcoin.Script,
	lockingScriptOffset int) (bitcoin.Script, error) {
	return Unlock(u.Key, writeSigPreimage, lockingScript, lockingScriptOffset, u.SigHashType,
		u.OpCodeSeparatorIndex, u.Verify)
}

func (u *Unlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	publicKey, err := MatchScript(lockingScript, u.Verify)
	if err != nil {
		return 0, bitcoin_interpreter.ScriptNotMatching
	}

	if !publicKey.Equal(u.Key.PublicKey()) {
		return 0, bitcoin_interpreter.ScriptNotMatching
	}

	return UnlockingSize, nil
}

func (u *Unlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	publicKey, err := MatchScript(lockingScript, u.Verify)
	if err != nil {
		return false
	}

	return publicKey.Equal(u.Key.PublicKey())
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
