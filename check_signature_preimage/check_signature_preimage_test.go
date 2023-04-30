package check_signature_preimage

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
	"github.com/tokenized/txbuilder"
)

func Test_CheckSignaturePreimageScript_Fixed(t *testing.T) {
	sigHashType := txbuilder.SigHashForkID | txbuilder.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

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

	t.Logf("Tx : %s", tx)

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	t.Logf("Tx Bytes: %x", txBuf.Bytes())

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

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &txbuilder.SigHashCache{}
	if err := interpreter.Execute(unlockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckSignaturePreimageScript_Bytes_Known_Success(t *testing.T) {
	sigHashType := txbuilder.SigHashForkID | txbuilder.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("Script_CheckSignatureHash (%d bytes) : %s", len(lockingScript), lockingScript)

	b, _ := hex.DecodeString("0100000001cf1e722618a457be68619b980754795f4ac95ebf4f1820b85ca8e3fbffa2430f0000000000ffffffff019c010000000000001976a9147489b37971c080ac98fe7eea0df5701191bdee2c88ac00000000")

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("Failed to deserialize tx : %s", err)
	}

	inputIndex := 0
	value := tx.TxOut[0].Value

	t.Logf("Tx : %s", tx)

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	t.Logf("Tx Bytes: %x", txBuf.Bytes())

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

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &txbuilder.SigHashCache{}
	if err := interpreter.Execute(unlockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckSignaturePreimageScript_Bytes_Known_Fail(t *testing.T) {
	sigHashType := txbuilder.SigHashForkID | txbuilder.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("Script_CheckSignatureHash (%d bytes) : %s", len(lockingScript), lockingScript)

	b, _ := hex.DecodeString("01000000013879d7c7c516859d4e9c05db0f74c045ecc30a51e515feea627da387ff7807190000000000ffffffff011d000000000000001976a9149fbd4cd9f2dc091f99884860491fcefd817d9bd888ac00000000")

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("Failed to deserialize tx : %s", err)
	}

	inputIndex := 0
	value := tx.TxOut[0].Value

	t.Logf("Tx : %s", tx)

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	t.Logf("Tx Bytes: %x", txBuf.Bytes())

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

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &txbuilder.SigHashCache{}
	if err := interpreter.Execute(unlockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckSignaturePreimageScript_Random(t *testing.T) {
	t.Skip() // Wait until Test_CheckSignaturePreimageScript_Bytes_Known_Fail is fixed

	sigHashType := txbuilder.SigHashForkID | txbuilder.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("Script_CheckSignatureHash (%d bytes) : %s", len(lockingScript), lockingScript)

	for i := 0; i < 1000; i++ {
		t.Run(fmt.Sprintf("random%d", i), func(t *testing.T) {
			checkSignaturePreimageScript_Random(t, lockingScript, sigHashType)
		})
	}
}

func checkSignaturePreimageScript_Random(t *testing.T, lockingScript bitcoin.Script,
	sigHashType txbuilder.SigHashType) {

	value := uint64(rand.Intn(1000) + 1)

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	var previousTxHash bitcoin.Hash32
	rand.Read(previousTxHash[:])
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&previousTxHash, 0), nil))

	// Add output for preimage SigHashSingle
	var receiverKey bitcoin.Key
	for i := 0; i < 10; i++ {
		key, err := bitcoin.GenerateKey(bitcoin.MainNet)
		if err != nil {
			continue
		}

		receiverKey = key
	}

	receiveLockingScript, _ := receiverKey.LockingScript()
	tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

	t.Logf("Tx : %s", tx)

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	t.Logf("Tx Bytes: %x", txBuf.Bytes())

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

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &txbuilder.SigHashCache{}
	if err := interpreter.Execute(unlockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, tx, inputIndex, value, hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_ComputeS(t *testing.T) {
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

	interpreter := bitcoin_interpreter.NewInterpreter()

	if err := interpreter.Execute(unlockingScript, nil, 0, 0, nil); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.Execute(lockingScript, nil, 0, 0, nil); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	sig, err := bitcoin.SignWithK(*privateKey, *k, hash)
	if err != nil {
		t.Fatalf("Failed to create signature : %s", err)
	}

	var sh bitcoin.Hash32
	copy(sh[:], hash)
	if !sig.Verify(sh, pubKey) {
		t.Fatalf("Failed to verify signature for that was calculated for checking")
	}

	if len(stack) != 1 {
		t.Fatalf("Stack should have 1 items: S")
	}

	stack[0] = bytes.TrimRight(stack[0], string([]byte{0})) // 0x20, bitcoin.OP_NUM2BIN
	sigS := reverseEndian(sig.S.Bytes())                    // Script_ReverseEndian32
	if !bytes.Equal(sigS, stack[0]) {
		t.Fatalf("Wrong S value : \n  got  %x, \n  want %x", stack[0], sigS)
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
		{
			name: "short high bit",
			s:    "88d7c5823b491ab3fafbd85ef33179de731c3d9582cdd2172179da77cfcc9d00",
		},
		{
			name: "short",
			s:    "88d7c5823b491ab3fafbd85ef33179de731c3d9582cdd2172179da77cfcc5d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rInt := new(big.Int).SetBytes(reverseEndian(Value_R))

			s, _ := hex.DecodeString(tt.s)
			t.Logf("S : %x", s)
			sb := bytes.TrimRight(s, string([]byte{0})) // 0x20, bitcoin.OP_NUM2BIN
			sb = reverseEndian(sb)                      // Script_ReverseEndian32
			sInt := new(big.Int).SetBytes(sb)

			sig := &bitcoin.Signature{R: *rInt, S: *sInt}

			unlockingScriptItems := bitcoin.ScriptItems{
				bitcoin.NewPushDataScriptItem(s),
			}
			unlockingScript, err := unlockingScriptItems.Script()
			if err != nil {
				t.Fatalf("Failed to create unlocking script : %s", err)
			}

			interpreter := bitcoin_interpreter.NewInterpreter()

			if err := interpreter.Execute(unlockingScript, nil, 0, 0, nil); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(lockingScript, nil, 0, 0, nil); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			stack := interpreter.StackItems()
			t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

			if len(stack) != 1 {
				t.Fatalf("Stack should have 1 item, the encoded signature")
			}

			t.Logf("Proper signature encoding : %x", sig.Bytes())

			if _, err := bitcoin.SignatureFromBytes(stack[0]); err != nil {
				t.Fatalf("Invalid signature encoding : %s", err)
			}

			if !bytes.Equal(sig.Bytes(), stack[0]) {
				t.Fatalf("Wrong signature encoding : \n  got  : %x\n  want : %x", stack[0],
					sig.Bytes())
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
