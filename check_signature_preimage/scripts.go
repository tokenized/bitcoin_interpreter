package check_signature_preimage

import (
	"encoding/hex"

	"github.com/tokenized/pkg/bitcoin"
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
	Value_CurveN     []byte // secp256k1 curve N
	Value_CurveNHalf []byte // secp256k1 curve N/2

	Value_K           []byte // Hard coded k value
	Value_InverseK    []byte // Pre-computed inverse of Value_K
	Value_R           []byte // Pre-computed little endian R from Value_K
	Value_R_BigEndian []byte // Pre-computed big endian Value_R
	Value_Encoded_R   []byte // Pre-computed big endian Value_R with 0x02 and length byte

	Value_Key       []byte // Hard coded private key
	Value_PublicKey []byte // Pre-computed public key from Value_Key
	Value_Key_R_Mul []byte // Pre-computed Value_Key * Value_R

	Script_ReverseEndian32 bitcoin.Script
	Script_FixNegative     bitcoin.Script

	Script_EncodeSignatureValue bitcoin.Script
	Script_EncodeSignature      bitcoin.Script

	Script_ComputeS bitcoin.Script

	Script_CheckSignaturePreimage_Pre bitcoin.Script
)

func init() {
	// Secp256k1 (little endian):
	// Gx  : 0x9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79
	// Gy  : 0xb8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48
	// N   : 0x414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00
	// N/2 : 0xa0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f00
	Value_CurveN, _ = hex.DecodeString("414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00")
	Value_CurveNHalf, _ = hex.DecodeString("a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f00")

	// Use pre-calculated R from a pre-generated k:
	// R = (k * G) mod N
	// k is the ephemoral signing key.
	Value_R, _ = hex.DecodeString("7abd2c4243d334251912749e254a8c5aa9be8cc3fb702bc1a0e03b993fbb5f33")
	Value_R_BigEndian, _ = hex.DecodeString("335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a")
	Value_Encoded_R, _ = hex.DecodeString("0220335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a")
	Value_K, _ = hex.DecodeString("721d78d06d37bc9c25eab4b241fd1343a68e91255d71993fcc170bc5b68393e1")
	Value_InverseK, _ = hex.DecodeString("e4985843644c24f6d3dca51da13ca4303f4de290393918fa3ddfa348f94aeb79")

	// Value_Key is the little endian pre-generated private key to use for in script signature
	// generation.
	Value_Key, _ = hex.DecodeString("97dfd76851bf465e8f715593b217714858bbe9570ff3bd5e33840a34e20ff026")

	Value_Key_R_Mul, _ = hex.DecodeString("f608e7b277ed70a30a879f500cdc24ef395fab9966d07615541c27da0222143d1044147c0f5849d63e288e823215a090789e81be96c8a523e8214cfdba62d007")

	// Value_PublicKey is the public key derived from Value_Key to use for passing into
	// OP_CHECKSIG to verify a signature generated in a script.
	Value_PublicKey, _ = hex.DecodeString("02ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382")

	// Script_ReverseEndian32 takes a 32 byte top stack item and reverses the bytes.
	for i := 0; i < 31; i++ {
		Script_ReverseEndian32 = append(Script_ReverseEndian32, bitcoin.OP_1)
		Script_ReverseEndian32 = append(Script_ReverseEndian32, bitcoin.OP_SPLIT)
	}
	for i := 0; i < 31; i++ {
		Script_ReverseEndian32 = append(Script_ReverseEndian32, bitcoin.OP_SWAP)
		Script_ReverseEndian32 = append(Script_ReverseEndian32, bitcoin.OP_CAT)
	}

	// Script_FixNegative changes the top item on the stack, if it's high bit is set, to a postive
	// by adding the zero byte.
	Script_FixNegative = bitcoin.ConcatScript(
		bitcoin.OP_DUP,
		bitcoin.OP_0, bitcoin.OP_GREATERTHAN,
		bitcoin.OP_IF,
		bitcoin.OP_0, bitcoin.OP_CAT,
		bitcoin.OP_ENDIF,
	)

	// Script_EncodeSignatureValue converts the top stack item to big endian and prepends 0x02 and a
	// byte for its length.
	//
	// Input: The top stack item must be little endian value
	// Output: The top stack item will be a big endian number with 0x02 and a length byte prepended.
	Script_EncodeSignatureValue = bitcoin.ConcatScript(
		bitcoin.BytePushData(0x20), bitcoin.OP_NUM2BIN, Script_ReverseEndian32,

		// Trim trailing zero. There is still the potential to have more than one trailing zero, so
		// we still need to have a preimage malleation fix when unlocking.
		bitcoin.BytePushData(0x1f), bitcoin.OP_SPLIT,
		bitcoin.OP_DUP,
		bitcoin.OP_IF,
		bitcoin.OP_CAT,
		bitcoin.OP_ELSE,
		bitcoin.OP_DROP,
		bitcoin.OP_ENDIF,

		bitcoin.OP_SIZE,
		bitcoin.OP_SWAP,
		bitcoin.OP_CAT,
		bitcoin.OP_2,
		bitcoin.OP_SWAP,
		bitcoin.OP_CAT,
	)

	// Script_EncodeSignature encodes a little endian S value as a signature by combining the
	// pre-computed R value.
	//
	// Input: The top stack item must be a little endian S value
	// Output: The top stack item will be a DER encoded signature that works with OP_CHECKSIG.
	Script_EncodeSignature = bitcoin.ConcatScript(
		Script_EncodeSignatureValue,                                        // Encode S
		bitcoin.PushData(Value_Encoded_R), bitcoin.OP_SWAP, bitcoin.OP_CAT, // bitcoin.ConcatScriptenate pre-encoded R in front of S
		bitcoin.OP_SIZE, bitcoin.OP_SWAP, bitcoin.OP_CAT, // prepend size
		bitcoin.BytePushData(0x30), bitcoin.OP_SWAP, bitcoin.OP_CAT, // prepend header byte 0x30
	)

	// Script_ComputeS is a section of bitcoin script that computes the corresponding S value for a
	// signature.
	//
	// Input: The top item on the stack previous to this script execution must be the signature hash
	// as a little endian number value so the output of a OP_HASH256 must have endian reversed and
	// be converted to a number.
	// Output: The top stack item will be the little endian S value.
	//
	// S = privateKey * R
	// S = S + hash
	// S = S * invK
	// S = S mod N
	Script_ComputeS = bitcoin.ConcatScript(
		Script_FixNegative,
		// bitcoin.PushData(Value_R), bitcoin.PushData(Value_Key), bitcoin.OP_MUL, // S = private key * R
		bitcoin.PushData(Value_Key_R_Mul),                // S = private key * R
		bitcoin.OP_ADD,                                   // S = S + hash (OP_2 OP_ROLL to get sig hash from before R)
		bitcoin.PushData(Value_InverseK), bitcoin.OP_MUL, // S = S * invK
		bitcoin.PushData(Value_CurveN),
		bitcoin.OP_DUP, bitcoin.OP_ROT, bitcoin.OP_SWAP, bitcoin.OP_MOD, // S = S mod N (OP_SWAP so N is the denominator)
		bitcoin.OP_DUP,
		bitcoin.OP_2, bitcoin.OP_3, bitcoin.OP_PICK, bitcoin.OP_DIV, // Curve N / 2
		bitcoin.OP_LESSTHAN, // if S is less than half curve N then add curve N
		bitcoin.OP_IF,
		bitcoin.OP_SWAP,
		bitcoin.OP_SUB,
		bitcoin.OP_ELSE,
		bitcoin.OP_NIP,
		bitcoin.OP_ENDIF,
	)

	Script_CheckSignaturePreimage_Pre = bitcoin.ConcatScript(
		bitcoin.OP_HASH256,                      // Hash preimage
		Script_ReverseEndian32,                  // Change to little endian
		Script_ComputeS, Script_EncodeSignature, // Compute S and encode in signature
	)
}
