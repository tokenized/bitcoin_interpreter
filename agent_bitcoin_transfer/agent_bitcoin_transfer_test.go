package agent_bitcoin_transfer

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

// Test_Unlock tests unlocking a generated script with correct and incorrect values.
func Test_Unlock(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle
	value := uint64(1000)

	agentKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	agentLockingScript, _ := agentKey.LockingScript()

	recoverKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	recoverLockingScript, _ := recoverKey.LockingScript()

	approveKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	approveLockingScript, _ := approveKey.LockingScript()

	refundKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	refundLockingScript, _ := refundKey.LockingScript()

	recoverLockTime := uint32(time.Now().Unix()) + 10000

	lockingScript, err := CreateScript(agentLockingScript, approveLockingScript,
		refundLockingScript, value, recoverLockingScript, recoverLockTime)
	if err != nil {
		t.Fatalf("Failed to create agent bitcoin transfer script : %s", err)
	}
	t.Logf("AgentBitcoinTransferScript (%d bytes) : %s", len(lockingScript), lockingScript)

	approveOutput := wire.NewTxOut(value, approveLockingScript)
	var approveOutputBuf bytes.Buffer
	approveOutput.Serialize(&approveOutputBuf, 0, 0)
	approveOutputsHash, _ := bitcoin.NewHash32(bitcoin.DoubleSha256(approveOutputBuf.Bytes()))

	refundOutput := wire.NewTxOut(value, refundLockingScript)
	var refundOutputBuf bytes.Buffer
	refundOutput.Serialize(&refundOutputBuf, 0, 0)
	refundOutputsHash, _ := bitcoin.NewHash32(bitcoin.DoubleSha256(refundOutputBuf.Bytes()))

	info, err := MatchScript(lockingScript)
	if err != nil {
		t.Fatalf("MatchScript failed : %s", err)
	}

	if !info.AgentLockingScript.Equal(agentLockingScript) {
		t.Fatalf("MatchScript provided wrong agent locking script : \n  got  : %s\n  want : %s",
			info.AgentLockingScript, agentLockingScript)
	}

	if !info.ApproveOutputHash.Equal(approveOutputsHash) {
		t.Fatalf("MatchScript provided wrong approve output hash : \n  got  : %s\n  want : %s",
			info.ApproveOutputHash, approveOutputsHash)
	}

	if !info.RefundOutputHash.Equal(refundOutputsHash) {
		t.Fatalf("MatchScript provided wrong refund output hash : \n  got  : %s\n  want : %s",
			info.RefundOutputHash, refundOutputsHash)
	}

	if !info.RecoverLockingScript.Equal(recoverLockingScript) {
		t.Fatalf("MatchScript provided wrong recover locking script : \n  got  : %s\n  want : %s",
			info.RecoverLockingScript, recoverLockingScript)
	}

	if info.RecoverLockTime != recoverLockTime {
		t.Fatalf("MatchScript provided wrong recover lock time : got %d, want %d",
			info.RecoverLockTime, recoverLockTime)
	}

	tests := []struct {
		name             string
		txLockTime       uint32
		txInputSequence  uint32
		txReceiverValue  uint64
		txReceiverScript bitcoin.Script
		txSigner         bitcoin.Key
		branch           byte
		shouldUnlock     bool
	}{
		{
			name:             "agent approve valid",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         agentKey,
			branch:           0,
			shouldUnlock:     true,
		},
		{
			name:             "agent approve wrong output value",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value - 1,
			txReceiverScript: approveLockingScript,
			txSigner:         agentKey,
			branch:           0,
			shouldUnlock:     false,
		},
		{
			name:             "agent approve wrong output script",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: agentLockingScript,
			txSigner:         agentKey,
			branch:           0,
			shouldUnlock:     false,
		},
		{
			name:             "agent approve wrong signer",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         refundKey,
			branch:           0,
			shouldUnlock:     false,
		},
		{
			name:             "agent refund valid",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: refundLockingScript,
			txSigner:         agentKey,
			branch:           1,
			shouldUnlock:     true,
		},
		{
			name:             "agent refund wrong output value",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value - 1,
			txReceiverScript: refundLockingScript,
			txSigner:         agentKey,
			branch:           1,
			shouldUnlock:     false,
		},
		{
			name:             "agent refund wrong output script",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         agentKey,
			branch:           1,
			shouldUnlock:     false,
		},
		{
			name:             "agent refund wrong signer",
			txLockTime:       0,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: refundLockingScript,
			txSigner:         approveKey,
			branch:           1,
			shouldUnlock:     false,
		},
		{
			name:             "recover valid",
			txLockTime:       recoverLockTime,
			txInputSequence:  1,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         recoverKey,
			branch:           2,
			shouldUnlock:     true,
		},
		{
			name:             "recover max sequence",
			txLockTime:       recoverLockTime,
			txInputSequence:  wire.MaxTxInSequenceNum,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         recoverKey,
			branch:           2,
			shouldUnlock:     false,
		},
		{
			name:             "recover wrong lock time",
			txLockTime:       10,
			txInputSequence:  1,
			txReceiverValue:  value,
			txReceiverScript: approveLockingScript,
			txSigner:         recoverKey,
			branch:           2,
			shouldUnlock:     false,
		},
		{
			name:             "recover wrong signer",
			txLockTime:       recoverLockTime,
			txInputSequence:  1,
			txReceiverValue:  value,
			txReceiverScript: agentLockingScript,
			txSigner:         agentKey,
			branch:           2,
			shouldUnlock:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tx := wire.NewMsgTx(1)

			inputIndex := len(tx.TxIn)
			previousTxHash, _ := bitcoin.NewHash32FromStr("79436eeaa792ea39bbda15d2061f836023014b6bf6384c692561152e04d22dd1")
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(previousTxHash, 0), nil))
			tx.TxIn[0].Sequence = tt.txInputSequence

			tx.AddTxOut(wire.NewTxOut(tt.txReceiverValue, tt.txReceiverScript))

			tx.LockTime = tt.txLockTime

			t.Logf("Tx : %s", tx)

			hashCache := &bitcoin_interpreter.SigHashCache{}
			preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript,
				-1, value, sigHashType, hashCache)
			if err != nil {
				t.Fatalf("Failed to get signature preimage : %s", err)
			}
			t.Logf("Preimage : %x", preimage)

			var unlockingScript bitcoin.Script
			switch tt.branch {
			case 0: // agent approve
				hashCache = &bitcoin_interpreter.SigHashCache{}
				sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
					value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
					hashCache)
				if err != nil {
					t.Fatalf("Failed to create sig hash : %s", err)
				}

				signature, err := tt.txSigner.Sign(*sigHash)
				if err != nil {
					t.Fatalf("Failed to create agent signature : %s", err)
				}

				agentUnlockingScript := bitcoin.ConcatScript(
					bitcoin.PushData(append(signature.Bytes(),
						byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
					bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
				)

				unlockingScript, err = UnlockApprove(ctx, tx, inputIndex, value,
					lockingScript, agentUnlockingScript)
				if err != nil {
					t.Fatalf("Failed to create unlocking script : %s", err)
				}

			case 1: // agent refund
				hashCache = &bitcoin_interpreter.SigHashCache{}
				sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
					value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
					hashCache)
				if err != nil {
					t.Fatalf("Failed to create sig hash : %s", err)
				}

				signature, err := tt.txSigner.Sign(*sigHash)
				if err != nil {
					t.Fatalf("Failed to create agent signature : %s", err)
				}

				agentUnlockingScript := bitcoin.ConcatScript(
					bitcoin.PushData(append(signature.Bytes(),
						byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
					bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
				)

				unlockingScript, err = UnlockRefund(ctx, tx, inputIndex, value,
					lockingScript, agentUnlockingScript)
				if err != nil {
					t.Fatalf("Failed to create unlocking script : %s", err)
				}

			case 2: // recover
				hashCache = &bitcoin_interpreter.SigHashCache{}
				sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
					value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
					hashCache)
				if err != nil {
					t.Fatalf("Failed to create sig hash : %s", err)
				}

				signature, err := tt.txSigner.Sign(*sigHash)
				if err != nil {
					t.Fatalf("Failed to create agent signature : %s", err)
				}

				agentUnlockingScript := bitcoin.ConcatScript(
					bitcoin.PushData(append(signature.Bytes(),
						byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
					bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
				)

				unlockingScript, err = UnlockRecover(ctx, tx, inputIndex, value,
					lockingScript, agentUnlockingScript)
				if err != nil {
					t.Fatalf("Failed to create unlocking script : %s", err)
				}

			default:
				t.Fatalf("Unsupported branch value : %d", tt.branch)
			}

			t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

			interpreter := bitcoin_interpreter.NewInterpreter()

			hashCache = &bitcoin_interpreter.SigHashCache{}
			if err := interpreter.Execute(ctx, unlockingScript, tx, inputIndex, value,
				hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			t.Logf("Execute locking script")

			if err := interpreter.Execute(ctx, lockingScript, tx, inputIndex, value,
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

func Test_MatchScript_NotMatching(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{
			name:   "P2PKH",
			script: "OP_DUP OP_HASH160 0xb33bb20086c0d75da054bcf06b2dbf17519a3d13 OP_EQUALVERIFY OP_CHECKSIG",
		},
		{
			name:   "Multi-P2PKH",
			script: "OP_0 OP_TOALTSTACK OP_IF OP_DUP OP_HASH160 0x9644d900d45516005343003213a161f264be2a5b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0xd864e6e4169f38021aa73a910c5f1e670f6bfcd1 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0x408a48bf23d9acee0d95ba4ad58b458d70d484b8 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_2 OP_FROMALTSTACK OP_LESSTHANOREQUAL",
		},
		{
			name:   "OP_RETURN",
			script: "OP_FALSE OP_RETURN 0x1234567890abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script, err := bitcoin.StringToScript(tt.script)
			if err != nil {
				t.Fatalf("Failed to convert string to script : %s", err)
			}

			if _, err := MatchScript(script); err == nil {
				t.Fatalf("Should have returned not matching")
			} else if errors.Cause(err) != bitcoin_interpreter.ScriptNotMatching {
				t.Fatalf("Should have returned ScriptNotMatching : %s", err)
			}
		})
	}
}
