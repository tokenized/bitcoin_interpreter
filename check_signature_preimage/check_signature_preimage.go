package check_signature_preimage

import (
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/txbuilder"
)

// CheckSignaturePreimageScript returns a section of bitcoin script that verifies that the top item
// on the stack is the signature preimage of the spending transaction.
func CheckSignaturePreimageScript(sigHashType txbuilder.SigHashType) bitcoin.Script {
	return bitcoin.ConcatScript(
		Script_CheckSignaturePreimage_Pre,
		bitcoin.BytePushData(byte(sigHashType)),
		bitcoin.OP_CAT,
		bitcoin.PushData(Value_PublicKey),
		bitcoin.OP_CODESEPARATOR,
		bitcoin.OP_CHECKSIG,
	)
}