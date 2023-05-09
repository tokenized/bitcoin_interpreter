package multi_p2pkh

import (
	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

const (
	LockingSize = 4 * bitcoin.Hash20Size

	SubUnlockingSize = bitcoin_interpreter.MaxSignaturesPushDataSize +
		bitcoin_interpreter.PublicKeyPushDataSize + 1
)

var (
	Script_P2PKH_Pre = bitcoin.ConcatScript(
		bitcoin.OP_DUP,
		bitcoin.OP_HASH160,
	)
)

type Info struct {
	RequiredSigners       int
	SignerPublicKeyHashes []bitcoin.Hash20
}

// func CreateScript(publicKey bitcoin.PublicKey, verify bool) bitcoin.Script {
// }

func Unlock(tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int, lockingScriptOffset int,
	key bitcoin.Key, sigHashType bitcoin_interpreter.SigHashType, opCodeSeparatorIndex int,
	verify bool) (bitcoin.Script, error) {

	return nil, errors.New("Not Implemented")
}

func MatchScript(lockingScript bitcoin.Script, verify bool) (*Info, error) {
	return nil, errors.New("Not Implemented")
}
