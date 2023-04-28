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
	lockingScript, err := Script_CheckSignaturePreimage(sigHashType)
	if err != nil {
		t.Fatalf("Failed to get locking script : %s", err)
	}

	t.Logf("Script_CheckSignatureHash size : %d", len(lockingScript))

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
	lockingScript, err := bitcoin.StringToScript(Script_ComputeS)
	if err != nil {
		t.Fatalf("Failed to get locking script : %s", err)
	}

	t.Logf("Script_ComputeS size : %d", len(lockingScript))

	kb, err := hex.DecodeString(Script_K[2:])
	if err != nil {
		t.Fatalf("Failed to decode private key : %s", err)
	}
	k := new(big.Int).SetBytes(kb)

	pk, err := hex.DecodeString(Script_Key[2:])
	if err != nil {
		t.Fatalf("Failed to decode private key : %s", err)
	}
	privateKey := new(big.Int).SetBytes(reverseEndian(pk))

	preCalcR, err := hex.DecodeString(Script_R[2:])
	if err != nil {
		t.Fatalf("Failed to decode R : %s", err)
	}

	pubKey, err := bitcoin.PublicKeyFromStr(Script_PublicKey[2:])
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

			check_Script_ComputeS(t, hash, lockingScript, k, privateKey, preCalcR, pubKey)
		})
	}

	hash := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		rand.Read(hash)
		t.Run(fmt.Sprintf("Random Hash %d", i), func(t *testing.T) {
			t.Logf("Hash : %x", hash)
			check_Script_ComputeS(t, hash, lockingScript, k, privateKey, preCalcR, pubKey)
		})
	}
}

func check_Script_ComputeS(t *testing.T, hash []byte, lockingScript bitcoin.Script,
	k, privateKey *big.Int, preCalcR []byte, pubKey bitcoin.PublicKey) {

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

	// if !bytes.Equal(r, preCalcR) {
	// 	t.Fatalf("Bottom stack value is not R : \n  got  %x, \n  want %x", r, preCalcR)
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
	lockingScript, err := bitcoin.StringToScript(Script_EncodeSignature)
	if err != nil {
		t.Fatalf("Failed to get locking script : %s", err)
	}

	t.Logf("Script_EncodeSignature size : %d", len(lockingScript))

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
			preCalcR, err := hex.DecodeString(Script_R[2:])
			if err != nil {
				t.Fatalf("Failed to decode R : %s", err)
			}
			r := new(big.Int).SetBytes(reverseEndian(preCalcR))

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

// Signature preimage 769 bytes (locking script + 156 bytes)
//
// 01000000 // version
// 79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1 // prev outs hash
// 0000000000000000000000000000000000000000000000000000000000000000 // inputs sequence hash
// 52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649 // previous txid
// 00000000 // previous tx output index

// fd // previous locking script size type (2 bytes)
// 6202 // previous locking script size (610)

// previous locking script
// 5b795a795a79856151795a795a79210ac407f0e4bd44bfc207355a778b046225a7068fc59ee7eda4
// 3ad905aadbffc800206c266b30e6a1319c66dc401e5bd6b432ba49688eecd118297041da8074ce08
// 105c795679615679aa0079610079517f517f517f517f517f517f517f517f517f517f517f517f517f
// 517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e
// 7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e
// 7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e007e81517a7561577956795679567956796153795679
// 5479577995939521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff
// 00517951796151795179970079009f63007952799367007968517a75517a75517a7561527a75517a
// 517951795296a0630079527994527a75517a6853798277527982775379012080517f517f517f517f
// 517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f
// 517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e
// 7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01205279
// 947f7754537993527993013051797e527e54797e58797e527e53797e52797e57797e0079517a7551
// 7a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a75517a756100795779
// ac517a75517a75517a75517a75517a75517a75517a75517a75517a7561517a75517a756177777777
// 77777777777777777777

// e803000000000000 // input value
// ffffffff // input sequence
// 1d94f3090978a1f915ce1cc68bace2129f20f8140d4603845a1d6da67e914a97 // outputs hash
// 00000000 // lock time
// 43000000 // sig hash type
