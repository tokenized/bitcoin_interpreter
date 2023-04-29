package bitcoin_interpreter

import (
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/txbuilder"
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
	Value_CurveN      []byte
	Value_CurveNHalf  []byte
	Value_R           []byte
	Value_R_BigEndian []byte
	Value_Encoded_R   []byte
	Value_K           []byte
	Value_InverseK    []byte

	Value_Key       []byte
	Value_PublicKey []byte

	Script_ReverseEndian32     bitcoin.Script
	Script_ReverseEndian32Or33 bitcoin.Script

	Script_FixNegative         bitcoin.Script
	Script_FixNegative_Reverse bitcoin.Script

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

	Script_ReverseEndian32Or33 = concat(
		bitcoin.OP_SIZE,
		bytePushData(0x21), bitcoin.OP_EQUAL,
		bitcoin.OP_DUP,
		bitcoin.OP_TOALTSTACK,
		bitcoin.OP_IF,
		bitcoin.OP_1, bitcoin.OP_SPLIT,
		bitcoin.OP_ENDIF,
		Script_ReverseEndian32,
		bitcoin.OP_FROMALTSTACK,
		bitcoin.OP_IF,
		bitcoin.OP_SWAP,
		bitcoin.OP_CAT,
		bitcoin.OP_ENDIF,
	)

	// Script_FixNegative changes the top item on the stack, if it's high bit is set, to a postive
	// by adding the zero byte.
	Script_FixNegative = concat(
		bitcoin.OP_DUP,
		bitcoin.OP_0, bitcoin.OP_GREATERTHAN,
		bitcoin.OP_IF,
		bitcoin.OP_0, bitcoin.OP_CAT,
		bitcoin.OP_ENDIF,
	)

	Script_FixNegative_Reverse = concat(
		bitcoin.OP_DUP,
		bitcoin.OP_0, bitcoin.OP_GREATERTHAN,
		bitcoin.OP_IF,
		bitcoin.OP_0, bitcoin.OP_SWAP, bitcoin.OP_CAT,
		bitcoin.OP_ENDIF,
	)

	// Script_EncodeSignatureValue prepends the top stack item with 0x02 and a byte for its length.
	// TODO We might need to have special handling for shorter values. --ce
	Script_EncodeSignatureValue = concat(
		Script_FixNegative_Reverse, Script_ReverseEndian32Or33,
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
	// Inputs: The top stack item must be a little endian S value
	// Outputs: The top stack item will be a DER encoded signature that works with OP_CHECKSIG.
	Script_EncodeSignature = concat(
		Script_EncodeSignatureValue,                                // Encode S
		pushData(Value_Encoded_R), bitcoin.OP_SWAP, bitcoin.OP_CAT, // concatenate pre-encoded R in front of S
		bitcoin.OP_SIZE, bitcoin.OP_SWAP, bitcoin.OP_CAT, // prepend size
		bytePushData(0x30), bitcoin.OP_SWAP, bitcoin.OP_CAT, // prepend header byte 0x30
	)

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
	Script_ComputeS = concat(
		Script_FixNegative,
		pushData(Value_R),
		pushData(Value_Key), bitcoin.OP_MUL, // S = private key * R (duplicate to leave R on stack)
		bitcoin.OP_ADD,                           // S = S + hash (OP_2 OP_ROLL to get sig hash from before R)
		pushData(Value_InverseK), bitcoin.OP_MUL, // S = S * invK
		pushData(Value_CurveN),
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

	Script_CheckSignaturePreimage_Pre = concat(
		bitcoin.OP_HASH256,                      // Hash preimage
		Script_ReverseEndian32,                  // Change to little endian
		Script_ComputeS, Script_EncodeSignature, // Compute S and encode in signature
	)
}

// bytePushData returns the push op to push a single byte value to the stack.
func bytePushData(b byte) []byte {
	if b == 0 {
		return []byte{bitcoin.OP_0}
	}

	if b <= 16 {
		return []byte{b - bitcoin.OP_1 + 1}
	}

	return []byte{0x01, b} // one byte push data
}

func pushData(b []byte) []byte {
	script, err := bitcoin.NewPushDataScriptItem(b).Script()
	if err != nil {
		panic(fmt.Sprintf("Failed to create push data script : %s", err))
	}

	return script
}

type byteOrSlice interface{}

func concat(bs ...byteOrSlice) []byte {
	l := 0
	for _, v := range bs {
		switch b := v.(type) {
		case []byte:
			l += len(b)
		case bitcoin.Script:
			l += len(b)
		case byte, int:
			l += 1
		default:
			panic(fmt.Sprintf("Unknown concat script value type : %s : %v", typeName(reflect.TypeOf(v)), v))
		}
	}

	result := make([]byte, l)
	offset := 0
	for _, v := range bs {
		switch b := v.(type) {
		case []byte:
			// println("add byte slice", "0x"+hex.EncodeToString(b))
			// println("offset", offset)
			copy(result[offset:], b)
			offset += len(b)
		case bitcoin.Script:
			// println("add byte slice", "0x"+hex.EncodeToString(b))
			// println("offset", offset)
			copy(result[offset:], b)
			offset += len(b)
		case byte:
			// println("add byte", "0x"+hex.EncodeToString([]byte{byte(b)}))
			// println("offset", offset)
			result[offset] = b
			offset += 1
		case int:
			if uint(b) > uint(0xff) {
				panic("unsupported script int value over 8 bits")
			}

			// println("add int", "0x"+hex.EncodeToString([]byte{byte(b)}))
			// println("offset", offset)
			result[offset] = byte(b)
			offset += 1

		default:
			panic(fmt.Sprintf("Unknown concat script value type : %s", typeName(reflect.TypeOf(v))))
		}
	}

	return result
}

func typeName(typ reflect.Type) string {
	kind := typ.Kind()
	switch kind {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return fmt.Sprintf("%s:%s", kind, typeName(typ.Elem()))
	case reflect.Struct:
		return typ.Name()
	default:
		return kind.String()
	}
}

// Script_CheckSignaturePreimage verifies that the top item on the stack is the signature preimage
// of the spending transaction.
func Script_CheckSignaturePreimage(sigHashType txbuilder.SigHashType) bitcoin.Script {
	script := Script_CheckSignaturePreimage_Pre
	script = append(script, bytePushData(byte(sigHashType))...)
	script = append(script, bitcoin.OP_CAT)
	script = append(script, pushData(Value_PublicKey)...)
	script = append(script, bitcoin.OP_CODESEPARATOR)
	script = append(script, bitcoin.OP_CHECKSIG)
	return script
}
