package bitcoin_interpreter

import (
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

var (
	// CantUnlock is returned when the unlocker can't unlock the locking script.
	CantUnlock = errors.New("Can't Unlock")

	// CantSign is returned when the unlocker can't sign the locking script. This is for unlockers
	// that are only used for fee estimation but don't actually have the private keys.
	CantSign = errors.New("Can't Sign")

	// NotFullyUnlocked will be returned from the unlock function when the unlocker provided partial
	// unlocking but it is not complete.
	NotFullyUnlocked = errors.New("Not Fully Unlocked")
)

type Unlocker interface {
	// Unlock returns the correct unlocking script.
	Unlock(writeSigPreimage WriteSignaturePreimage,
		lockingScript bitcoin.Script) (bitcoin.Script, error)

	// SubUnlock returns the correct unlocking script. It supports sub-script where the script is
	// embedded in another script.
	SubUnlock(writeSigPreimage WriteSignaturePreimage,
		lockingScript bitcoin.Script, lockingScriptOffset int) (bitcoin.Script, error)

	// UnlockingSize estimates the size of the unlocking script for the locking script.
	UnlockingSize(lockingScript bitcoin.Script) (int, error)

	// CanUnlock returns true if this unlocker can generate the correct unlocking script for the
	// locking script.
	CanUnlock(lockingScript bitcoin.Script) bool

	// CanUnlock returns true if this unlocker can generate part of the correct unlocking script for
	// the locking script. It is also able to update an existing unlocking script.
	// For example with a multi-P2PKH locking script this will return true if this unlocker can
	// create the initial unlocking script with one signature and can update an unlocking script
	// with another signature.
	CanPartiallyUnlock(lockingScript bitcoin.Script) bool

	// Copy returns a copy of the unlocker that is safe to use in a different thread.
	Copy() Unlocker
}

// TransactionWithOutputs is a transaction with spent outputs provided.
type TransactionWithOutputs interface {
	GetMsgTx() *wire.MsgTx
	InputOutput(index int) (*wire.TxOut, error) // The output being spent by the input
}

type MultiUnlocker []Unlocker

func (u MultiUnlocker) Unlock(writeSigPreimage WriteSignaturePreimage,
	lockingScript bitcoin.Script) (bitcoin.Script, error) {

	for _, unlocker := range u {
		if unlockingScript, err := unlocker.Unlock(writeSigPreimage,
			lockingScript); err == nil {
			return unlockingScript, nil
		} else if errors.Cause(err) != CantUnlock && errors.Cause(err) != ScriptNotMatching {
			return nil, err
		}
	}

	return nil, CantUnlock
}

func (u MultiUnlocker) SubUnlock(writeSigPreimage WriteSignaturePreimage,
	lockingScript bitcoin.Script, lockingScriptOffset int) (bitcoin.Script, error) {

	for _, unlocker := range u {
		if unlockingScript, err := unlocker.SubUnlock(writeSigPreimage, lockingScript,
			lockingScriptOffset); err == nil {
			return unlockingScript, nil
		} else if errors.Cause(err) != CantUnlock {
			return nil, err
		}
	}

	return nil, CantUnlock
}

func (u MultiUnlocker) UnlockingSize(lockingScript bitcoin.Script) (int, error) {
	notMatching := ScriptNotMatching
	for _, unlocker := range u {
		if unlockingSize, err := unlocker.UnlockingSize(lockingScript); err == nil {
			return unlockingSize, nil
		} else if errors.Cause(err) != ScriptNotMatching {
			return 0, err
		} else {
			notMatching = err
		}
	}

	return 0, notMatching
}

func (u MultiUnlocker) CanUnlock(lockingScript bitcoin.Script) bool {
	for _, unlocker := range u {
		if unlocker.CanUnlock(lockingScript) {
			return true
		}
	}

	return false
}

func (u MultiUnlocker) CanPartiallyUnlock(lockingScript bitcoin.Script) bool {
	for _, unlocker := range u {
		if unlocker.CanPartiallyUnlock(lockingScript) {
			return true
		}
	}

	return false
}

func (u MultiUnlocker) Copy() Unlocker {
	copy := make(MultiUnlocker, len(u))
	for i, unlocker := range u {
		copy[i] = unlocker.Copy()
	}

	return copy
}
