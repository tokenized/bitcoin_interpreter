package multi_p2pkh

import (
	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

type Info struct {
	RequiredSigners       int
	SignerPublicKeyHashes []bitcoin.Hash20
}

func Unlock(key bitcoin.Key, writeSigPreimage bitcoin_interpreter.WriteSignaturePreimage,
	lockingScript bitcoin.Script, lockingScriptOffset int,
	sigHashType bitcoin_interpreter.SigHashType, opCodeSeparatorIndex int,
	verify bool) (bitcoin.Script, error) {

	return nil, errors.New("Not Implemented")
}

func MatchScript(lockingScript bitcoin.Script, verify bool) (*Info, error) {
	return nil, errors.New("Not Implemented")
}
