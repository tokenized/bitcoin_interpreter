package check_signature_preimage

import (
	"bytes"
	"context"
	"testing"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
)

func Test_CheckPreimageOutputsHashScript_Correct(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
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

	outputsHash := tx.TxOut[0].OutputHash()
	t.Logf("Output Hash : %x", outputsHash[:])

	lockingScript := CheckPreimageOutputsHashScript(outputsHash, true)
	t.Logf("CheckPreimageOutputsHashScript (%d bytes) : %s", len(lockingScript), lockingScript)

	// remove op dup so preimage won't be left on stack
	if lockingScript[0] != bitcoin.OP_DUP {
		t.Fatalf("Wrong first op code : %s", lockingScript[:1])
	}
	lockingScript = lockingScript[1:]

	// change op equal verify to just op equal so the script will evaluate to true
	if lockingScript[len(lockingScript)-1] != bitcoin.OP_EQUALVERIFY {
		t.Fatalf("Wrong last op code : %s", lockingScript[len(lockingScript)-1:])
	}
	lockingScript[len(lockingScript)-1] = bitcoin.OP_EQUAL

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	if err := interpreter.Error(); err != nil {
		t.Fatalf("Failed to interpret scripts : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckPreimageOutputsHashScript_Wrong(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	value := uint64(1000)

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))

	// Add output for preimage SigHashSingle
	receiveLockingScript, _ := bitcoin.StringToScript("OP_DUP OP_HASH160 0x4905c36bfbe7a2c41eefe947a70aeac36a31d70f OP_EQUALVERIFY OP_CHECKSIG")
	correctOutput := wire.NewTxOut(value, receiveLockingScript)

	wrongKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	wrongLockingScript, _ := wrongKey.LockingScript()
	tx.AddTxOut(wire.NewTxOut(value, wrongLockingScript))

	t.Logf("Tx : %s", tx)

	var outputBuf bytes.Buffer
	correctOutput.Serialize(&outputBuf, 0, 0)
	outputsHash, _ := bitcoin.NewHash32(bitcoin.DoubleSha256(outputBuf.Bytes()))

	t.Logf("Output Hash : %x", outputsHash[:])

	lockingScript := CheckPreimageOutputsHashScript(*outputsHash, true)
	t.Logf("CheckPreimageOutputsHashScript (%d bytes) : %s", len(lockingScript), lockingScript)

	// remove op dup so preimage won't be left on stack
	if lockingScript[0] != bitcoin.OP_DUP {
		t.Fatalf("Wrong first op code : %s", lockingScript[:1])
	}
	lockingScript = lockingScript[1:]

	// change op equal verify to just op equal so the script will evaluate to true
	if lockingScript[len(lockingScript)-1] != bitcoin.OP_EQUALVERIFY {
		t.Fatalf("Wrong last op code : %s", lockingScript[len(lockingScript)-1:])
	}
	lockingScript[len(lockingScript)-1] = bitcoin.OP_EQUAL

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if interpreter.IsUnlocked() {
		t.Fatalf("Should not have unlocked script")
	} else {
		t.Logf("Correctly did not unlock script : %s", interpreter.Error())
	}
}

func Test_CheckPreimageInputSequenceScript_Correct(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
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

	lockingScript := CheckPreimageInputSequenceScript(wire.MaxTxInSequenceNum, true)
	t.Logf("CheckPreimageInputSequenceScript (%d bytes) : %s", len(lockingScript), lockingScript)

	// remove op dup so preimage won't be left on stack
	if lockingScript[0] != bitcoin.OP_DUP {
		t.Fatalf("Wrong first op code : %s", lockingScript[:1])
	}
	lockingScript = lockingScript[1:]

	// change op equal verify to just op equal so the script will evaluate to true
	if lockingScript[len(lockingScript)-1] != bitcoin.OP_EQUALVERIFY {
		t.Fatalf("Wrong last op code : %s", lockingScript[len(lockingScript)-1:])
	}
	lockingScript[len(lockingScript)-1] = bitcoin.OP_EQUAL

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if !interpreter.IsUnlocked() {
		t.Fatalf("Failed to unlock script : %s", interpreter.Error())
	}
}

func Test_CheckPreimageInputSequenceScript_Wrong(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	value := uint64(1000)

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))
	tx.TxIn[0].Sequence = 1

	// Add output for preimage SigHashSingle
	receiveLockingScript, _ := bitcoin.StringToScript("OP_DUP OP_HASH160 0x4905c36bfbe7a2c41eefe947a70aeac36a31d70f OP_EQUALVERIFY OP_CHECKSIG")
	tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

	t.Logf("Tx : %s", tx)

	lockingScript := CheckPreimageInputSequenceScript(2, true)
	t.Logf("CheckPreimageInputSequenceScript (%d bytes) : %s", len(lockingScript), lockingScript)

	// remove op dup so preimage won't be left on stack
	if lockingScript[0] != bitcoin.OP_DUP {
		t.Fatalf("Wrong first op code : %s", lockingScript[:1])
	}
	lockingScript = lockingScript[1:]

	// change op equal verify to just op equal so the script will evaluate to true
	if lockingScript[len(lockingScript)-1] != bitcoin.OP_EQUALVERIFY {
		t.Fatalf("Wrong last op code : %s", lockingScript[len(lockingScript)-1:])
	}
	lockingScript[len(lockingScript)-1] = bitcoin.OP_EQUAL

	hashCache := &bitcoin_interpreter.SigHashCache{}
	preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1, value,
		sigHashType, hashCache)
	if err != nil {
		t.Fatalf("Failed to get signature preimage : %s", err)
	}
	t.Logf("Preimage : %x", preimage)

	unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
	unlockingScript, err := unlockingScriptItems.Script()
	if err != nil {
		t.Fatalf("Failed to create unlocking script : %s", err)
	}

	t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache = &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret locking script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if interpreter.IsUnlocked() {
		t.Fatalf("Should not have unlocked script")
	} else {
		t.Logf("Correctly did not unlock script : %s", interpreter.Error())
	}
}

func Test_CheckPreimageLockTimeScript(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	value := uint64(1000)

	tests := []struct {
		name                string
		txLockTime          uint32
		txInputSequence     uint32
		scriptCheckLockTime uint32
		shouldUnlock        bool
	}{
		{
			name:                "valid",
			txLockTime:          10000,
			txInputSequence:     1,
			scriptCheckLockTime: 10000,
			shouldUnlock:        true,
		},
		{
			name:                "input sequence is max",
			txLockTime:          10000,
			txInputSequence:     wire.MaxTxInSequenceNum,
			scriptCheckLockTime: 10000,
			shouldUnlock:        false,
		},
		{
			name:                "wrong lock time",
			txLockTime:          10000,
			txInputSequence:     1,
			scriptCheckLockTime: 11000,
			shouldUnlock:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := wire.NewMsgTx(1)

			// Add input to spend specified output.
			inputIndex := len(tx.TxIn)
			previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))
			tx.TxIn[0].Sequence = tt.txInputSequence

			// Add output for preimage SigHashSingle
			receiveLockingScript, _ := bitcoin.StringToScript("OP_DUP OP_HASH160 0x4905c36bfbe7a2c41eefe947a70aeac36a31d70f OP_EQUALVERIFY OP_CHECKSIG")
			tx.AddTxOut(wire.NewTxOut(value, receiveLockingScript))

			tx.LockTime = tt.txLockTime

			t.Logf("Tx : %s", tx)

			lockingScript := CheckPreimageLockTimeScript(tt.scriptCheckLockTime, true)
			t.Logf("CheckPreimageLockTimeScript (%d bytes) : %s", len(lockingScript), lockingScript)

			// remove second op dup so preimage won't be left on stack
			if lockingScript[18] != bitcoin.OP_DUP {
				t.Fatalf("Wrong op code where OP_DUP should be : %s", lockingScript[18:19])
			}
			lockingScript = append(lockingScript[:18], lockingScript[19:]...)

			// change op equal verify to just op equal so the script will evaluate to true
			if lockingScript[len(lockingScript)-1] != bitcoin.OP_VERIFY {
				t.Fatalf("Wrong last op code : %s", lockingScript[len(lockingScript)-1:])
			}
			lockingScript = lockingScript[:len(lockingScript)-1]
			t.Logf("Locking script : %s", lockingScript)

			hashCache := &bitcoin_interpreter.SigHashCache{}
			preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript, 1,
				value, sigHashType, hashCache)
			if err != nil {
				t.Fatalf("Failed to get signature preimage : %s", err)
			}
			t.Logf("Preimage : %x", preimage)

			unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(preimage)}
			unlockingScript, err := unlockingScriptItems.Script()
			if err != nil {
				t.Fatalf("Failed to create unlocking script : %s", err)
			}

			t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

			interpreter := bitcoin_interpreter.NewInterpreter()

			hashCache = &bitcoin_interpreter.SigHashCache{}
			if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
				hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
				hashCache); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			stack := interpreter.StackItems()
			t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

			if tt.shouldUnlock {
				if !interpreter.IsUnlocked() {
					t.Fatalf("Failed to unlock script : %s", interpreter.Error())
				}
			} else if interpreter.IsUnlocked() {
				t.Fatalf("Should not have unlocked script")
			} else {
				t.Logf("Correctly did not unlock script : %s", interpreter.Error())
			}
		})
	}
}
