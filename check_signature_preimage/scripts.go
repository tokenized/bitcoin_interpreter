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

	Script_ReverseEndian32            bitcoin.Script
	Script_FixNegative                bitcoin.Script
	Script_TrimLeadingZeroNotNegative bitcoin.Script

	Script_EncodeSignatureValue bitcoin.Script
	Script_EncodeFullSignature  bitcoin.Script

	Script_ComputeS bitcoin.Script

	Script_CheckSignaturePreimage_Pre bitcoin.Script

	Script_Get_OutputsHash   bitcoin.Script
	Script_Get_InputSequence bitcoin.Script
	Script_Get_LockTime      bitcoin.Script
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

	// Script_FixNegative changes the top item on the stack, if it's high bit is set, to a positive
	// by adding the zero byte.
	Script_FixNegative = bitcoin.ConcatScript(
		bitcoin.OP_DUP,
		bitcoin.OP_0, bitcoin.OP_LESSTHAN,
		bitcoin.OP_IF,
		bitcoin.PushData([]byte{0x00}), bitcoin.OP_CAT,
		bitcoin.OP_ENDIF,
	)

	// Script_TrimLeadingZeroNotNegative removes a leading zero from the top stack item if the next
	// byte does not have its high bit set.
	//
	// Trimming the leading zero removes a failure with 1 in 256 odds when the first byte is zero.
	// Checking for a high bit in the next byte removes a failure with 1 in 512 odds.
	// There is still a 1 in 131,071 chance of failure when the first two bytes are zero and the
	// next byte's high bit is not set.
	// These can be fixed by the spender by malleating the signature preimage to change the
	// signature hash so the S value changes to not having leading zeros. If tx lock time is not
	// being used (all input sequences are max) then just increment the lock time as it doesn't
	// functionaly change anything. If the tx lock time is required to be something specific then
	// the input's sequence can be incremented so long as there aren't other signatures that depend
	// on it. Otherwise a locking script can be modified in a way that doesn't change the function.
	Script_TrimLeadingZeroNotNegative = bitcoin.ConcatScript(
		bitcoin.OP_1, bitcoin.OP_SPLIT,
		bitcoin.OP_SWAP,
		bitcoin.OP_DUP,
		bitcoin.OP_0, bitcoin.OP_EQUAL, // 0x80 will be "false" so check for exactly equal to zero

		// The first byte is zero
		bitcoin.OP_IF,
		bitcoin.OP_DROP, // drop the zero

		// Check for high bit set because then we want to leave the zero
		bitcoin.OP_1, bitcoin.OP_SPLIT,
		bitcoin.OP_SWAP,
		bitcoin.OP_DUP,
		bitcoin.BytePushData(0x80), bitcoin.OP_AND,
		bitcoin.OP_0, bitcoin.OP_EQUAL, // 0x80 will be "false" so check for exactly equal to zero

		bitcoin.OP_3, bitcoin.OP_ROLL,
		bitcoin.OP_CAT, // put the next byte back

		bitcoin.OP_SWAP,                                                 // Get && 0x80 back to the top
		bitcoin.OP_NOTIF,                                                // If high bit set (and result is not zero)
		bitcoin.PushData([]byte{0x00}), bitcoin.OP_SWAP, bitcoin.OP_CAT, // put the zero back at the beginning
		bitcoin.OP_ENDIF,

		bitcoin.OP_ELSE,

		bitcoin.OP_SWAP, bitcoin.OP_CAT,

		bitcoin.OP_ENDIF,
	)

	// Script_EncodeSignatureValue converts the top stack item to big endian and prepends 0x02 and a
	// byte for its length.
	//
	// Input: The top stack item must be little endian value
	// Output: The top stack item will be a big endian number with 0x02 and a length byte prepended.
	Script_EncodeSignatureValue = bitcoin.ConcatScript(
		bitcoin.BytePushData(0x20), bitcoin.OP_NUM2BIN,
		Script_ReverseEndian32,
		// Script_TrimLeadingZeroNotNegative, // 30 bytes smaller script but more chance of malleation
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
	Script_EncodeFullSignature = bitcoin.ConcatScript(
		Script_EncodeSignatureValue,                                        // Encode S
		bitcoin.PushData(Value_Encoded_R), bitcoin.OP_SWAP, bitcoin.OP_CAT, // concat pre-encoded R in front of S
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
		// Stack:
		//  Sig Hash

		Script_FixNegative,
		// Stack:
		//  Sig Hash (with leading zero if needed to retain positive sign)

		// S = private key * R
		//
		// We save a few bytes of script here by pre-calculating this rather than including the two
		// values and multiplying. R is used later, but must be big endian so is smaller to just
		// push in that format then to try to retain this value and reverse it.
		// bitcoin.PushData(Value_R), bitcoin.PushData(Value_Key), bitcoin.OP_MUL, // S = private key * R
		//
		// Stack:
		//  Sig Hash
		bitcoin.PushData(Value_Key_R_Mul),

		// Stack:
		//  Private key * R
		//  Sig Hash
		bitcoin.OP_ADD, // S = S + hash

		// Stack:
		//  S
		bitcoin.PushData(Value_InverseK), bitcoin.OP_MUL, // S = S * invK

		// S = S mod N
		// Stack:
		//  S
		bitcoin.PushData(Value_CurveN),

		// Stack:
		//  Curve N
		//  S
		bitcoin.OP_TUCK, // Copy Curve N to under S

		// Stack:
		//  Curve N
		//  S
		//  Curve N
		bitcoin.OP_MOD, // S mod N

		// If S is greater than half curve N (high S) then change to Curve N minus S
		// Stack:
		//  S
		//  Curve N
		bitcoin.OP_DUP, // Duplicate S

		// Stack:
		//  S
		//  S
		//  Curve N
		bitcoin.OP_2, bitcoin.OP_PICK, // Copy Curve N to the top of the stack

		// Stack:
		//  Curve N
		//  S
		//  S
		//  Curve N
		bitcoin.OP_2, bitcoin.OP_DIV, // Curve N / 2

		// Stack:
		//  Curve N / 2
		//  S
		//  S
		//  Curve N
		bitcoin.OP_GREATERTHAN, bitcoin.OP_IF, // S is greater than Curve N

		// Stack:
		//  S
		//  Curve N
		bitcoin.OP_SUB, // Curve N minus S
		bitcoin.OP_ELSE,
		bitcoin.OP_NIP, // Remove Curve N from stack (second item)
		bitcoin.OP_ENDIF,

		// Stack:
		//  S
	)

	Script_CheckSignaturePreimage_Pre = bitcoin.ConcatScript(
		bitcoin.OP_HASH256,         // Hash preimage
		Script_ReverseEndian32,     // Change to little endian
		Script_ComputeS,            // Compute S value of signature
		Script_EncodeFullSignature, // Combine pre-computed R value and encode full signature
	)

	Script_Get_OutputsHash = bitcoin.ConcatScript(
		bitcoin.OP_DUP, // Copy preimage

		// Calculate offset 8 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(8), bitcoin.OP_SUB,

		// Drop sig hash type and lock time that are after the outputs hash.
		bitcoin.OP_SPLIT, bitcoin.OP_DROP,

		// Calculate offset 32 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(32), bitcoin.OP_SUB,

		// Drop everything before the outputs hash.
		bitcoin.OP_SPLIT, bitcoin.OP_SWAP, bitcoin.OP_DROP,
	)

	Script_Get_InputSequence = bitcoin.ConcatScript(
		bitcoin.OP_DUP, // Copy preimage

		// Calculate offset 40 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(40), bitcoin.OP_SUB,

		// Drop sig hash type, lock time, and outputs hash that are after the input sequence.
		bitcoin.OP_SPLIT, bitcoin.OP_DROP,

		// Calculate offset 4 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(4), bitcoin.OP_SUB,

		// Drop everything before the input sequence.
		bitcoin.OP_SPLIT, bitcoin.OP_SWAP, bitcoin.OP_DROP,
	)

	Script_Get_LockTime = bitcoin.ConcatScript(
		bitcoin.OP_DUP, // Copy preimage

		// Calculate offset 4 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(4), bitcoin.OP_SUB,

		// Drop sig hash type.
		bitcoin.OP_SPLIT, bitcoin.OP_DROP,

		// Calculate offset 4 before the end.
		bitcoin.OP_SIZE, bitcoin.BytePushData(4), bitcoin.OP_SUB,

		// Drop everything before the lock time.
		bitcoin.OP_SPLIT, bitcoin.OP_SWAP, bitcoin.OP_DROP,
	)
}
