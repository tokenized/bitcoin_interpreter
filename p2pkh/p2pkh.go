package p2pkh

import (
	"bytes"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

const (
	LockingSize = 4 * bitcoin.Hash20Size

	UnlockingSize = bitcoin_interpreter.MaxSignaturesPushDataSize +
		bitcoin_interpreter.PublicKeyPushDataSize
)

var (
	Script_P2PKH_Pre = bitcoin.ConcatScript(
		bitcoin.OP_DUP,
		bitcoin.OP_HASH160,
	)
)

func CreateScript(publicKey bitcoin.PublicKey, verify bool) bitcoin.Script {
	opCheckSig := bitcoin.OP_CHECKSIG
	if verify {
		opCheckSig = bitcoin.OP_CHECKSIGVERIFY
	}

	return bitcoin.ConcatScript(
		Script_P2PKH_Pre,
		bitcoin.PushData(bitcoin.Hash160(publicKey.Bytes())),
		bitcoin.OP_EQUALVERIFY,
		opCheckSig,
	)
}

func Unlock(tx bitcoin_interpreter.TransactionWithOutputs, inputIndex int, lockingScriptOffset int,
	key bitcoin.Key, sigHashType bitcoin_interpreter.SigHashType, opCodeSeparatorIndex int,
	verify bool) (bitcoin.Script, error) {

	txout, err := tx.InputOutput(inputIndex)
	if err != nil {
		return nil, errors.Wrap(err, "input output")
	}

	scriptHash, err := MatchScript(txout.LockingScript[lockingScriptOffset:], verify)
	if err != nil && errors.Cause(err) != bitcoin_interpreter.RemainingScript {
		return nil, errors.Wrap(bitcoin_interpreter.CantUnlock, err.Error())
	}

	publicKeyBytes := key.PublicKey().Bytes()
	publicKeyHash := bitcoin.Hash160(publicKeyBytes)

	if !bytes.Equal(scriptHash[:], publicKeyHash) {
		return nil, errors.Wrap(bitcoin_interpreter.CantUnlock, "wrong public key hash")
	}

	sigHash, err := bitcoin_interpreter.SignatureHash(tx.GetMsgTx(), inputIndex,
		txout.LockingScript, opCodeSeparatorIndex, txout.Value, sigHashType,
		&bitcoin_interpreter.SigHashCache{})
	if err != nil {
		return nil, errors.Wrap(err, "sig hash")
	}

	signature, err := key.Sign(*sigHash)
	if err != nil {
		return nil, errors.Wrap(err, "signature")
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(append(signature.Bytes(), byte(sigHashType))),
		bitcoin.PushData(publicKeyBytes),
	), nil
}

func MatchScript(lockingScript bitcoin.Script, verify bool) (*bitcoin.Hash20, error) {
	items, err := bitcoin.ParseScriptItems(bytes.NewReader(lockingScript), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse script")
	}

	items, err = bitcoin_interpreter.MatchScript(items, Script_P2PKH_Pre)
	if err != nil {
		return nil, errors.Wrap(err, "match pre")
	}

	var hash20Bytes []byte
	items, hash20Bytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, bitcoin.Hash20Size)
	if err != nil {
		return nil, errors.Wrap(err, "match hash")
	}

	scriptHash, err := bitcoin.NewHash20(hash20Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "hash20")
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_EQUALVERIFY)
	if err != nil {
		return nil, err
	}

	if verify {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_CHECKSIGVERIFY)
		if err != nil {
			return nil, err
		}
	} else {
		items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_CHECKSIG)
		if err != nil {
			return nil, err
		}
	}

	if len(items) != 0 {
		return scriptHash, bitcoin_interpreter.RemainingScript
	}

	return scriptHash, nil
}
