package bitcoin_interpreter

import (
	"bytes"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/txbuilder"

	"github.com/pkg/errors"
)

// Note:
// Due to Low-S constraint, the most significant byte (MSB) of the signature hash, the hash of the
// preimage, must be less than a threshold of 0x7E. This can be easily solved by malleating the
// transaction if it does not meet this constraint. Each malleation has a success chance of ~50%. It
// will only take a few malleations to find a valid transaction.
// If there is no lock time requirement then just leave all input sequences at max and increment the
// lock time.
// If there is a specific lock time requirement then add OP_RETURN or OP_DROP data to a script.
// Maybe just extra random data at the end of a Tokenized action script.

var (
	Script_CheckSignaturePreimage_Pre = "OP_HASH256" + // Hash preimage
		Script_ReverseEndian32 + " " + Script_FixNegative + " " + // Change to little endian positive
		Script_ComputeS + " " + Script_EncodeSignature // Compute S and encode in signature

	// Secp256k1 (little endian):
	// Gx  : 0x9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79
	// Gy  : 0xb8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48
	// N   : 0x414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00
	// N/2 : 0xa0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f00
	Script_CurveN     = "0x414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00"
	Script_CurveNHalf = "0xa0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f00"

	// Use pre-calculated R from a pre-generated k:
	// R = (k * G) mod N
	// k is the ephemoral signing key.
	Script_R           = "0x7abd2c4243d334251912749e254a8c5aa9be8cc3fb702bc1a0e03b993fbb5f33"
	Script_R_BigEndian = "0x335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a"
	Script_Encoded_R   = "0x0220335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a"
	Script_K           = "0x721d78d06d37bc9c25eab4b241fd1343a68e91255d71993fcc170bc5b68393e1"
	Script_InverseK    = "0xe4985843644c24f6d3dca51da13ca4303f4de290393918fa3ddfa348f94aeb79"

	// Script_Key is the little endian pre-generated private key to use for in script signature
	// generation.
	Script_Key = "0x97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026"

	// Script_PublicKey is the public key derived from Script_Key to use for passing into
	// OP_CHECKSIG to verify a signature generated in a script.
	Script_PublicKey = "0x02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382"

	// Script_ComputeS is a section of bitcoin script that computes the corresponding S value for a
	// signature.
	//
	// Input: The top item on the stack previous to this script execution must be the signature hash
	// as a little endian number value so the output of a OP_HASH256 must have endian reversed and
	// be converted to a number.
	// Output: S is on top of the stack.
	//
	// S = privateKey * R
	// S = S + hash
	// S = S * invK
	// S = S mod N
	Script_ComputeS = Script_FixNegative +
		Script_R + " " +
		Script_Key + " OP_MUL " + // S = private key * R (duplicate to leave R on stack)
		"OP_ADD " + // S = S + hash (OP_2 OP_ROLL to get sig hash from before R)
		Script_InverseK + " OP_MUL " + // S = S * invK
		Script_CurveN +
		" OP_DUP OP_ROT OP_SWAP OP_MOD " + // S = S mod N (OP_SWAP so N is the denominator)
		`
		OP_DUP
		OP_2 OP_3 OP_PICK OP_DIV
		OP_LESSTHAN
		OP_IF
			OP_SWAP
			OP_SUB
		OP_ELSE
			OP_NIP
		OP_ENDIF
	` // if S is less than half curve N then add curve N

	// Script_FixNegative changes the top item on the stack, if it's high bit is set, to a postive
	// by adding the zero byte.
	Script_FixNegative = `
		OP_DUP
		OP_0 OP_GREATERTHAN
		OP_IF
			OP_0 OP_CAT
		OP_ENDIF
	`

	// Script_EncodeSignature encodes a little endian S value as a signature by combining the
	// pre-computed R value.
	//
	// Inputs: The top stack item must be a little endian S value
	// Outputs: The top stack item will be a DER encoded signature that works with OP_CHECKSIG.
	Script_EncodeSignature = Script_EncodeSignatureValue + // Encode S
		Script_Encoded_R + " OP_SWAP OP_CAT " + // concatenate pre-encoded R in front of S
		" OP_SIZE OP_SWAP OP_CAT " + // prepend size
		" 0x30 OP_SWAP OP_CAT" // prepend header byte 0x30

	// Script_EncodeSignatureValue prepends the top stack item with 0x02 and a byte for its length.
	// TODO We might need to have special handling for shorter values. --ce
	Script_EncodeSignatureValue = Script_FixNegative_Reverse + Script_ReverseEndian32Or33 + `
		OP_SIZE
		OP_SWAP
		OP_CAT
		OP_2
		OP_SWAP
		OP_CAT
	`

	Script_FixNegative_Reverse = `
		OP_DUP
		OP_0 OP_GREATERTHAN
		OP_IF
			OP_0 OP_SWAP OP_CAT
		OP_ENDIF
	`
)

// Script_CheckSignaturePreimage verifies that the top item on the stack is the signature preimage
// of the spending transaction.
func Script_CheckSignaturePreimage(sigHashType txbuilder.SigHashType) (bitcoin.Script, error) {
	b, err := bitcoin.StringToScript(Script_CheckSignaturePreimage_Pre)
	if err != nil {
		return nil, errors.Wrap(err, "string pre")
	}

	items, err := bitcoin.ParseScriptItems(bytes.NewReader(b), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse pre")
	}

	sigHashTypeItem := bitcoin.PushNumberScriptItemUnsigned(uint64(sigHashType))
	items = append(items, sigHashTypeItem)
	items = append(items, bitcoin.NewOpCodeScriptItem(bitcoin.OP_CAT))

	b, err = bitcoin.StringToScript(Script_PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "string pub key")
	}

	newItems, err := bitcoin.ParseScriptItems(bytes.NewReader(b), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse pub key")
	}

	items = append(items, newItems...)

	items = append(items, bitcoin.NewOpCodeScriptItem(bitcoin.OP_CODESEPARATOR))
	items = append(items, bitcoin.NewOpCodeScriptItem(bitcoin.OP_CHECKSIG))

	result, err := items.Script()
	if err != nil {
		return nil, errors.Wrap(err, "script")
	}

	return result, nil
}
