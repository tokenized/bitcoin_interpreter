package p2pk

import (
	"bytes"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

const (
	LockingSize = bitcoin_interpreter.PublicKeyPushDataSize + 1

	UnlockingSize = bitcoin_interpreter.MaxSignaturesPushDataSize
)

func CreateScript(publicKey bitcoin.PublicKey, verify bool) bitcoin.Script {
	opCheckSig := bitcoin.OP_CHECKSIG
	if verify {
		opCheckSig = bitcoin.OP_CHECKSIGVERIFY
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(publicKey.Bytes()),
		opCheckSig,
	)
}

func Unlock(key bitcoin.Key, writeSigPreimage bitcoin_interpreter.WriteSignaturePreimage,
	lockingScript bitcoin.Script, lockingScriptOffset int,
	sigHashType bitcoin_interpreter.SigHashType, opCodeSeparatorIndex int,
	verify bool) (bitcoin.Script, error) {

	publicKey, err := MatchScript(lockingScript[lockingScriptOffset:], verify)
	if err != nil && errors.Cause(err) != bitcoin_interpreter.RemainingScript {
		return nil, err
	}

	if !publicKey.Equal(key.PublicKey()) {
		return nil, errors.Wrap(bitcoin_interpreter.CantUnlock, "wrong public key")
	}

	sigHash, err := bitcoin_interpreter.CalculateSignatureHash(writeSigPreimage, sigHashType,
		lockingScript, opCodeSeparatorIndex)
	if err != nil {
		return nil, errors.Wrap(err, "sig hash")
	}

	signature, err := key.Sign(sigHash)
	if err != nil {
		return nil, errors.Wrap(err, "signature")
	}

	return bitcoin.ConcatScript(
		bitcoin.PushData(append(signature.Bytes(), byte(sigHashType))),
	), nil
}

func MatchScript(lockingScript bitcoin.Script, verify bool) (*bitcoin.PublicKey, error) {
	items, err := bitcoin.ParseScriptItems(bytes.NewReader(lockingScript), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse script")
	}

	var publicKeyBytes []byte
	items, publicKeyBytes, err = bitcoin_interpreter.MatchNextPushDataSize(items,
		bitcoin_interpreter.PublicKeyPushDataSize)
	if err != nil {
		return nil, errors.Wrap(err, "match public key")
	}

	publicKey, err := bitcoin.PublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "public key")
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
		return &publicKey, bitcoin_interpreter.RemainingScript
	}

	return &publicKey, nil
}
