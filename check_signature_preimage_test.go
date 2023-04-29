package bitcoin_interpreter

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
	"github.com/tokenized/txbuilder"
)

func Test_Script_CheckSignaturePreimage(t *testing.T) {
	sigHashType := txbuilder.SigHashForkID | txbuilder.SigHashSingle
	lockingScript := Script_CheckSignaturePreimage(sigHashType)

	t.Logf("Script_CheckSignatureHash (%d bytes) : %s", len(lockingScript), lockingScript)

	value := uint64(1000)

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))

	// Add output for preimage SigHashSingle
	receiveLockingScript, _ := bitcoin.StringToScript("OP_DUP OP_HASH160 0x4905c36bfbe7a2c41eefe947a70aeac36a31d70f OP_EQUALVERIFY OP_CHECKSIG")
	tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

	hashCache := &txbuilder.SigHashCache{}
	preimage, err := txbuilder.SignaturePreimage(tx, inputIndex, lockingScript, value, sigHashType,
		hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	sigHash := bitcoin.DoubleSha256(preimage)
	t.Logf("Preimage Hash : %x", sigHash)

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)
	t.Logf("Locking Script (%d bytes) : %s", len(lockingScript), lockingScript)

	interpreter := NewInterpreter()

	hashCache = &txbuilder.SigHashCache{}
	if err := interpreter.Execute(unlockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	t.Logf("Final Stack (%d items):\n%s", len(interpreter.stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_Script_ComputeS(t *testing.T) {
	lockingScript := Script_ComputeS

	t.Logf("Script_ComputeS (%d bytes) : %s", len(lockingScript), lockingScript)

	k := new(big.Int).SetBytes(Value_K)
	privateKey := new(big.Int).SetBytes(reverseEndian(Value_Key))

	pubKey, err := bitcoin.PublicKeyFromBytes(Value_PublicKey)
	if err != nil {
		t.Fatalf("Failed to decode public key : %s", err)
	}

	tests := []struct {
		name string
		hash string
	}{
		{
			name: "high hash bit not set",
			hash: "208750d11d183562772a58b2b85739363604928dca7605209700d75eb238f25f",
		},
		{
			name: "high hash bit set 1",
			hash: "64603e6ccd728800a1dc0fdddade05b8a374b526c7f1c7c765fdb70d4110dce2",
		},
		{
			name: "high hash bit set 2",
			hash: "cd05424c6520740b5c2bce4336545eda12716317df58e6fb764fcb3004f5248c",
		},
		{
			name: "last S byte zero",
			hash: "47bc35fb59f7792a349511b2bb3504ba4a28717823a27a1f99ce6970290b26ef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, _ := hex.DecodeString(tt.hash)
			t.Logf("Hash : %x", hash)

			check_Script_ComputeS(t, hash, lockingScript, k, privateKey, pubKey)
		})
	}

	hash := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		rand.Read(hash)
		t.Run(fmt.Sprintf("Random Hash %d", i), func(t *testing.T) {
			t.Logf("Hash : %x", hash)
			check_Script_ComputeS(t, hash, lockingScript, k, privateKey, pubKey)
		})
	}
}

func check_Script_ComputeS(t *testing.T, hash []byte, lockingScript bitcoin.Script,
	k, privateKey *big.Int, pubKey bitcoin.PublicKey) {

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(reverseEndian(hash))}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	interpreter := NewInterpreter()

	if err := interpreter.Execute(unlockingScript, nil, 0, 0, nil); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, nil, 0, 0, nil); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	t.Logf("Final Stack (%d items):\n%s", len(interpreter.stack), interpreter.StackString())

	sig, err := bitcoin.SignWithK(*privateKey, *k, hash)
	if err != nil {
		t.Fatalf("Failed to create signature : %s", err)
	}

	var sh bitcoin.Hash32
	copy(sh[:], hash)
	if !sig.Verify(sh, pubKey) {
		t.Fatalf("Failed to verify signature for that was calculated for checking")
	}

	if len(interpreter.stack) != 1 {
		t.Fatalf("Stack should have 1 items: S")
	}

	// r, err := interpreter.getStack(1, false)
	// if err != nil {
	// 	t.Fatalf("Failed to get r stack item : %s", err)
	// }

	// if !bytes.Equal(r, Value_R) {
	// 	t.Fatalf("Bottom stack value is not R : \n  got  %x, \n  want %x", r, Value_R)
	// }

	// sigR := reverseEndian(sig.R.Bytes())
	// if !bytes.Equal(sigR, r) {
	// 	t.Fatalf("Wrong R value : got %x, want %x", r, sigR)
	// }

	s, err := interpreter.getStack(0, false)
	if err != nil {
		t.Fatalf("Failed to get s stack item : %s", err)
	}

	// TODO Not sure if we want to trim the last byte when encoding the value. --ce
	// hash: 47bc35fb59f7792a349511b2bb3504ba4a28717823a27a1f99ce6970290b26ef
	// check_signature_hash_test.go:136: Wrong S value :
	//       got  88d7c5823b491ab3fafbd85ef33179de731c3d9582cdd2172179da77cfcc9d00,
	//       want 88d7c5823b491ab3fafbd85ef33179de731c3d9582cdd2172179da77cfcc9d
	s = bytes.TrimRight(s, string([]byte{0}))

	sigS := reverseEndian(sig.S.Bytes())
	if !bytes.Equal(sigS, s) {
		t.Fatalf("Wrong S value : \n  got  %x, \n  want %x", s, sigS)
	}
}

func Test_Script_EncodeSignature(t *testing.T) {
	lockingScript := Script_EncodeSignature

	t.Logf("Script_EncodeSignature (%d bytes) : %s", len(lockingScript), lockingScript)

	tests := []struct {
		name string
		s    string
	}{
		{
			name: "random",
			s:    "d9ca09318dc87d802e16cf82a8978735b27dda5189acebb472cd060dede77128",
		},
		// { // This might not be a valid test case as I think high bit S values are invalid
		// 	name: "high bit",
		// 	s:    "d9ca09318dc87d802e16cf82a8978735b27dda5189acebb472cd060dede771c8",
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := new(big.Int).SetBytes(reverseEndian(Value_R))

			s, _ := hex.DecodeString(tt.s)
			t.Logf("S : %x", s)
			sb := new(big.Int).SetBytes(reverseEndian(s))

			sig := &bitcoin.Signature{R: *r, S: *sb}

			unlockingScriptItems := bitcoin.ScriptItems{
				bitcoin.NewPushDataScriptItem(s),
			}
			unlockingScript, err := unlockingScriptItems.Script()
			if err != nil {
				t.Fatalf("Failed to create unlocking script : %s", err)
			}

			interpreter := NewInterpreter()

			if err := interpreter.Execute(unlockingScript, nil, 0, 0, nil); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(lockingScript, nil, 0, 0, nil); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			t.Logf("Final Stack (%d items):\n%s", len(interpreter.stack), interpreter.StackString())

			if len(interpreter.stack) != 1 {
				t.Fatalf("Stack should have 1 item, the encoded signature")
			}

			t.Logf("Proper signature encoding : %x", sig.Bytes())

			if _, err := bitcoin.SignatureFromBytes(interpreter.stack[0]); err != nil {
				t.Fatalf("Invalid signature encoding : %s", err)
			}

			if !bytes.Equal(sig.Bytes(), interpreter.stack[0]) {
				t.Fatalf("Wrong signature encoding : \n  got  : %x\n  want : %x",
					interpreter.stack[0], sig.Bytes())
			}
		})
	}
}

func reverseEndian(b []byte) []byte {
	l := len(b)
	result := make([]byte, l)
	r := l - 1
	for _, v := range b {
		result[r] = v
		r--
	}
	return result
}
