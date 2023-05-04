package check_signature_preimage

import (
	"context"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

var (
	// TxNeedsMalleation is an error that needs the current transaction's signature hash produces an
	// invalid signature with the current check preimage locking script.
	TxNeedsMalleation = errors.New("Tx Needs Malleation")
)

// CheckSignaturePreimageScript returns a section of bitcoin script that verifies that the top item
// on the stack is the signature preimage of the spending transaction.
func CheckSignaturePreimageScript(sigHashType bitcoin_interpreter.SigHashType) bitcoin.Script {
	return bitcoin.ConcatScript(
		Script_CheckSignaturePreimage_Pre,
		bitcoin.BytePushData(byte(sigHashType)),
		bitcoin.OP_CAT,
		bitcoin.PushData(Value_PublicKey),
		bitcoin.OP_CODESEPARATOR,
		bitcoin.OP_CHECKSIG,
	)
}

func UnlockSignaturePreimageScript(ctx context.Context, tx *wire.MsgTx, inputIndex int,
	lockingScript bitcoin.Script, opCodeSeparatorIndex int, value uint64,
	sigHashType bitcoin_interpreter.SigHashType,
	hashCache *bitcoin_interpreter.SigHashCache) (bitcoin.Script, error) {

	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript,
		opCodeSeparatorIndex, value, sigHashType, hashCache)
	if err != nil {
		return nil, errors.Wrap(err, "preimage")
	}

	sigHash := bitcoin.DoubleSha256(preimage)
	logger.InfoWithFields(ctx, []logger.Field{
		logger.Formatter("sig_hash", "%x", sigHash),
	}, "Preimage hash")

	unlockingScript := bitcoin.PushData(preimage)

	// Verify that it creates a valid signature and the tx doesn't need malleation. This depends on
	// the fact that all variable parts of the locking script are before the OP_CODE_SEPARATOR so
	// this preimage will be the same. If not then this will not unlock the script and return an
	// error.
	checkLockingScript := CheckSignaturePreimageScript(sigHashType)

	interpreter := bitcoin_interpreter.NewInterpreter()
	checkHashCache := &bitcoin_interpreter.SigHashCache{}

	if err := interpreter.ExecuteVerbose(ctx, unlockingScript, tx, inputIndex, value,
		checkHashCache); err != nil {
		return nil, errors.Wrap(err, "execute unlocking")
	}

	if err := interpreter.ExecuteVerbose(ctx, checkLockingScript, tx, inputIndex, value,
		checkHashCache); err != nil {
		if errors.Cause(err) == bitcoin_interpreter.ErrMalformedSignature {
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
