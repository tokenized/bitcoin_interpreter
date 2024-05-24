package check_signature_preimage

import (
	"bytes"
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

var (
	// TxNeedsMalleation is an error that needs the current transaction's signature hash produces an
	// invalid signature with the current check preimage locking script.
	TxNeedsMalleation = errors.New("Tx Needs Malleation")
)

// CreateScript returns a section of bitcoin script that verifies that the top item on the stack is
// the signature preimage of the spending transaction.
func CreateScript(sigHashType bitcoin_interpreter.SigHashType) bitcoin.Script {
	return bitcoin.ConcatScript(
		Script_CheckSignaturePreimage_Pre,
		bitcoin.BytePushData(byte(sigHashType)), bitcoin.OP_CAT, // append sig hash type
		bitcoin.PushData(Value_PublicKey),
		bitcoin.OP_CODESEPARATOR,
		bitcoin.OP_CHECKSIG,
	)
}

func Unlock(ctx context.Context, writeSigPreimage bitcoin_interpreter.WriteSignaturePreimage,
	lockingScript bitcoin.Script, sigHashType bitcoin_interpreter.SigHashType,
	opCodeSeparatorIndex int) (bitcoin.Script, error) {

	buf := &bytes.Buffer{}
	if err := writeSigPreimage(buf, sigHashType, lockingScript, opCodeSeparatorIndex); err != nil {
		return nil, errors.Wrap(err, "preimage")
	}
	preimage := buf.Bytes()

	sigHash := bitcoin.DoubleSha256(preimage)
	logger.InfoWithFields(ctx, []logger.Field{
		logger.Formatter("sig_hash", "%x", sigHash),
	}, "Preimage hash")

	unlockingScript := bitcoin.PushData(preimage)

	// Verify that it creates a valid signature and the tx doesn't need malleation. This depends on
	// the fact that all variable parts of the locking script are before the OP_CODE_SEPARATOR so
	// this preimage will be the same. If not then this will not unlock the script and return an
	// error.
	checkLockingScript := CreateScript(sigHashType)

	interpreter := bitcoin_interpreter.NewInterpreter()

	if err := interpreter.Execute(ctx, unlockingScript, writeSigPreimage); err != nil {
		return nil, errors.Wrap(err, "execute unlocking")
	}

	if err := interpreter.Execute(ctx, checkLockingScript, writeSigPreimage); err != nil {
		cause := errors.Cause(err)
		if cause == bitcoin_interpreter.ErrMalformedSignature ||
			cause == bitcoin_interpreter.ErrNonMinimallyEncodedNumber {
			// The signature generated in the script has leading zeros so it doesn't encode
			// correctly. The tx needs to be changed so the signature will generate differently.
			return nil, errors.Wrap(TxNeedsMalleation, err.Error())
		}

		return nil, errors.Wrap(err, "execute locking")
	}

	if !interpreter.IsUnlocked() {
		return nil, interpreter.Error()
	}

	return unlockingScript, nil
}

// MatchScript checks if the beginning of items matches a check preimage script then returns the
// remaining script items and the lock time.
// If it doesn't match it returns ScriptNotMatching.
func MatchScript(items bitcoin.ScriptItems) (bitcoin.ScriptItems, bitcoin_interpreter.SigHashType, error) {
	// Script_CheckSignaturePreimage_Pre
	var err error
	items, err = bitcoin_interpreter.MatchScript(items, Script_CheckSignaturePreimage_Pre)
	if err != nil {
		return nil, 0, errors.Wrap(err, "get pre-script")
	}

	var sigHashTypeBytes []byte
	items, sigHashTypeBytes, err = bitcoin_interpreter.MatchNextPushDataSize(items, 1)
	if err != nil {
		return nil, 0, errors.Wrap(err, "sig hash type")
	}

	sigHashType := bitcoin_interpreter.SigHashType(sigHashTypeBytes[0])

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_CAT)
	if err != nil {
		return nil, 0, errors.Wrap(err, "sig hash type")
	}

	items, _, err = bitcoin_interpreter.MatchNextPushDataSize(items,
		bitcoin.PublicKeyCompressedLength)
	if err != nil {
		return nil, 0, errors.Wrap(err, "public key")
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_CODESEPARATOR)
	if err != nil {
		return nil, 0, err
	}

	items, err = bitcoin_interpreter.MatchNextOpCode(items, bitcoin.OP_CHECKSIG)
	if err != nil {
		return nil, 0, err
	}

	return items, sigHashType, nil
}
