package check_signature_preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"testing"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

func Test_CheckSignaturePreimageScript_Fixed(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("CheckSignaturePreimageScript (%d bytes) : %s", len(lockingScript), lockingScript)

	value := uint64(1000)

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))

	// Add output for preimage SigHashSingle
	receiveLockingScript, _ := bitcoin.StringToScript("OP_DUP OP_HASH160 0x4905c36bfbe7a2c41eefe947a70aeac36a31d70f OP_EQUALVERIFY OP_CHECKSIG")
	tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

	receiveLockingScript, _ = bitcoin.StringToScript("OP_DUP OP_HASH160 0x5284dc915c8bda35155341b52a9341f3a31a4b04 OP_EQUALVERIFY OP_CHECKSIG")
	tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

	t.Logf("Tx : %s", tx)

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	t.Logf("Tx Bytes: %x", txBuf.Bytes())

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	sigHash := bitcoin.DoubleSha256(preimage)
	t.Logf("Preimage Hash : %x", sigHash)

	k := new(big.Int).SetBytes(Value_K)
	privateKey := new(big.Int).SetBytes(reverseEndian(Value_Key))
	sig, err := bitcoin.SignWithK(*privateKey, *k, sigHash)
	if err != nil {
		t.Fatalf("Failed to create check signature : %s", err)
	}

	t.Logf("Correct Signature : %s", sig)

	key := bitcoin.KeyFromValue(*privateKey, bitcoin.MainNet)
	publicKey := key.PublicKey()
	hash, _ := bitcoin.NewHash32(sigHash)
	if !sig.Verify(*hash, publicKey) {
		t.Fatalf("Invalid check signature")
	}

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)
	t.Logf("Locking Script (%d bytes) : %s", len(lockingScript), lockingScript)

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteVerbose(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteVerbose(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

// Test_CheckSignaturePreimageScript tests specific preimages that have known to fail in the past.
func Test_CheckSignaturePreimageScript_Specific(t *testing.T) {
	t.Skip()

	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("CheckSignaturePreimageScript (%d bytes) : %s", len(lockingScript), lockingScript)

	tests := []struct {
		name            string
		txHex           string
		needsMalleation bool
	}{
		{
			// This is just here as a control to ensure the test is working.
			name:            "always passed",
			txHex:           "0100000001cf1e722618a457be68619b980754795f4ac95ebf4f1820b85ca8e3fbffa2430f0000000000ffffffff019c010000000000001976a9147489b37971c080ac98fe7eea0df5701191bdee2c88ac00000000",
			needsMalleation: false,
		},
		{
			// This one failed because there were issues with trimming zero bytes from S.
			// It was trimming a trailing 0x80 because it is negative zero when it should only be
			// trimming actual zeros.
			name:            "trailing 0x80",
			txHex:           "01000000013879d7c7c516859d4e9c05db0f74c045ecc30a51e515feea627da387ff7807190000000000ffffffff011d000000000000001976a9149fbd4cd9f2dc091f99884860491fcefd817d9bd888ac00000000",
			needsMalleation: false,
		},
		{
			// This one failed because the trailing zero on the S value was trimmed and should not
			// have been.
			// Script S = 6a56416b76e93954f355db90fb585787af9ad828cc937ffa105611b1a1155900
			// Correct Encoded S = 6a56416b76e93954f355db90fb585787af9ad828cc937ffa105611b1a1155900
			//
			// Original S is not less than half N
			// a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f
			// 005915a1b1115610fa7f93cc28d89aaf875758fb90db55f35439e9766b41566a
			//
			// After numb2bin
			// 005915a1b1115610fa7f93cc28d89aaf875758fb90db55f35439e9766b41566a
			name:            "trailing 0x00",
			txHex:           "0100000001bf5f8792e3aceb0e868765b8611d7905089949e0c273e2410c72a146cd63981f0000000000ffffffff0186020000000000001976a91482b7b2cb4e6a6eef62e37711ec3a23b355cfd35388ac00000000",
			needsMalleation: false,
		},
		{ // 1 in 256 chance of failure, fixed by preimage malleation.
			// This one failed because the trailing zero should be trimmed.
			// S = 6da481adfafea67209fbe63fb699f0010bcb913eb0df4dbbd83cba77fbf0b500
			// Correct encoded S = 6da481adfafea67209fbe63fb699f0010bcb913eb0df4dbbd83cba77fbf0b5
			//
			// Original S is less than half N becuase negative
			// a0201b68462fe9df1d50a457736e575dffffffffffffffffffffffffffffff7f
			// 8c503a58d221fa03eec097705511a3b90e6649c01904f68d590105527e5b92ff00
			//
			// After subtracting N
			// 414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00
			// b5f0fb77ba3cd8bb4ddfb03e91cb0b01f099b63fe6fb0972a6fefaad81a46d
			//
			// After numb2bin
			// b5f0fb77ba3cd8bb4ddfb03e91cb0b01f099b63fe6fb0972a6fefaad81a46d00
			//
			// 006da481adfafea67209fbe63fb699f0010bcb913eb0df4dbbd83cba77fbf0b5
			// ^ this zero byte should be removed
			name:            "S leading 0x00 positive",
			txHex:           "0100000001b729c11328d3288604097600a0c151fa3d9e4268de75866558e9f47d8dd331990000000000ffffffff016a000000000000001976a9142a5574d1352f28a1bca033e47c28ca9fd3d8877b88ac00000000",
			needsMalleation: true,
		},
		{
			// This one failed because there is a leading zero on the big endian s value being
			// encoded, but the next bytes high bit is set so we need to leave the zero there.
			//
			// 00f69944c3b8aebee07c8b25038fab021a1d0d8c8020bc94531007ad57187f31
			// ^ this zero byte should not be removed
			name:            "S leading 0x00 negative",
			txHex:           "0100000001be2ad167dd574b32b3d0c22aa4d9b52761e8f56cf2100fe5a39fceae3d865f370000000000ffffffff0149000000000000001976a91408619263792d0027321f2c146bd2a640dd0c4b2888ac00000000",
			needsMalleation: false,
		},
		{
			// When the two leading bytes of S are zero and the next byte's highest bit is not set
			// we would need to trim two zeros. This is a 1 in 131,071 chance.
			// S : 00002daa32fac000f12935b78f6c3353e01d467ea762a8f5a6ea3d96be305e10
			name:            "S two leading 0x00",
			txHex:           "010000000157908187ed8ebe6a11444eede85099149ca82921bc28bdd6b9999594a41d97300000000000ffffffff0195020000000000001976a9144112450decb224ff08658bba28d40202467f6c7488ac00000000",
			needsMalleation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkSignaturePreimageScript(ctx, t, tt.txHex, sigHashType, lockingScript,
				tt.needsMalleation)
		})
	}
}

func checkSignaturePreimageScript(ctx context.Context, t *testing.T, txHex string,
	sigHashType bitcoin_interpreter.SigHashType, lockingScript bitcoin.Script,
	needsMalleation bool) {

	b, _ := hex.DecodeString(txHex)

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

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}

	sigHash := bitcoin.DoubleSha256(preimage)
	t.Logf("Preimage Hash : %x", sigHash)

	k := new(big.Int).SetBytes(Value_K)
	privateKey := new(big.Int).SetBytes(reverseEndian(Value_Key))
	sig, err := bitcoin.SignWithK(*privateKey, *k, sigHash)
	if err != nil {
		t.Fatalf("Failed to create check signature : %s", err)
	}

	t.Logf("Correct Signature : %s", sig)

	unlockingScript, err := UnlockSignaturePreimageScript(ctx, tx, inputIndex, lockingScript, 1,
		value, sigHashType, hashCache)
	if needsMalleation {
		if err == nil {
			t.Fatalf("Should have returned needs malleation error")
		}

		if errors.Cause(err) != TxNeedsMalleation {
			t.Fatalf("Wrong error type : got %s, want %s", err, TxNeedsMalleation)
		}
	} else if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

	if needsMalleation {
		for i := 0; i < 10; i++ {
			tx.LockTime++
			hashCache = &bitcoin_interpreter.SigHashCache{}
			unlockingScript, err = UnlockSignaturePreimageScript(ctx, tx, inputIndex, lockingScript,
				1, value, sigHashType, hashCache)
			if err == nil {
				break
			} else if errors.Cause(err) != TxNeedsMalleation {
				t.Fatalf("Failed to create unlocking script after tx malleation : %s", err)
			}
		}
	}

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteVerbose(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteVerbose(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckSignaturePreimageScript_Random(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	lockingScript := CheckSignaturePreimageScript(sigHashType)

	t.Logf("CheckSignaturePreimageScript (%d bytes) : %s", len(lockingScript), lockingScript)

	totalMalleations := 0
	total := 1000
	for i := 0; i < total; i++ {
		t.Run(fmt.Sprintf("random%d", i), func(t *testing.T) {
			if txBytes, malleations, err := checkSignaturePreimageScript_Random(ctx, t,
				lockingScript, sigHashType); err != nil {
				t.Errorf("Failed Tx Bytes (%s) : %x", err, txBytes)
			} else {
				totalMalleations += malleations
			}
		})
	}

	t.Logf("%d of %d transaction malleations needed", totalMalleations, total)
}

func checkSignaturePreimageScript_Random(ctx context.Context, t *testing.T,
	lockingScript bitcoin.Script,
	sigHashType bitcoin_interpreter.SigHashType) ([]byte, int, error) {

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

	for i := 0; i < 2; i++ {
		hashCache := &bitcoin_interpreter.SigHashCache{}
		unlockingScript, err := UnlockSignaturePreimageScript(ctx, tx, inputIndex, lockingScript, 1,
			value, sigHashType, hashCache)
		if err != nil {
			if errors.Cause(err) == TxNeedsMalleation {
				t.Logf("Tx needs malleation")
				tx.LockTime++
				continue
			}
			t.Fatalf("Failed to get signature preimage : %s", err)
		}

		interpreter := bitcoin_interpreter.NewInterpreter()

		hashCache = &bitcoin_interpreter.SigHashCache{}
		if err := interpreter.Execute(ctx, unlockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			t.Fatalf("Failed to interpret unlocking script : %s", err)
		}

		if err := interpreter.Execute(ctx, lockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			txBuf := &bytes.Buffer{}
			tx.Serialize(txBuf)
			return txBuf.Bytes(), 0, err
		}

		if !interpreter.IsUnlocked() {
			txBuf := &bytes.Buffer{}
			tx.Serialize(txBuf)
			return txBuf.Bytes(), 0, err
		}

		return nil, i, nil
	}

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	return txBuf.Bytes(), 0, errors.New("Failed to unlock script")
}

func Test_ComputeS(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
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

			check_Script_ComputeS(ctx, t, hash, lockingScript, k, privateKey, pubKey, true)
		})
	}

	hash := make([]byte, 32)
	for i := 0; i < 1000; i++ {
		rand.Read(hash)
		t.Run(fmt.Sprintf("Random Hash %d", i), func(t *testing.T) {
			t.Logf("Hash : %x", hash)
			check_Script_ComputeS(ctx, t, hash, lockingScript, k, privateKey, pubKey, false)
		})
	}
}

func check_Script_ComputeS(ctx context.Context, t *testing.T, hash []byte,
	lockingScript bitcoin.Script, k, privateKey *big.Int, pubKey bitcoin.PublicKey, verbose bool) {

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(reverseEndian(hash))}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	interpreter := bitcoin_interpreter.NewInterpreter()

	if err := interpreter.ExecuteFull(ctx, unlockingScript, nil, 0, 0, nil, verbose); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteFull(ctx, lockingScript, nil, 0, 0, nil, verbose); err != nil {
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

func Test_Script_EncodeFullSignature(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	lockingScript := Script_EncodeFullSignature

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
		// { // 1 in 256 chance of failure, fixed by preimage malleation
		// 	name: "short",
		// 	s:    "88d7c5823b491ab3fafbd85ef33179de731c3d9582cdd2172179da77cfcc5d",
		// },
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

			if err := interpreter.Execute(ctx, unlockingScript, nil, 0, 0, nil); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(ctx, lockingScript, nil, 0, 0, nil); err != nil {
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
