package agent_bitcoin_tranfer

import (
	"context"
	"testing"
	"time"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
)

func Test_AgentBitcoinTransfer(t *testing.T) {
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

	lockingScript, err := AgentBitcoinTransferScript(agentLockingScript, approveLockingScript,
		refundLockingScript, value, recoverLockingScript, recoverLockTime)
	if err != nil {
		t.Fatalf("Failed to create agent bitcoin transfer script : %s", err)
	}
	t.Logf("AgentBitcoinTransferScript (%d bytes) : %s", len(lockingScript), lockingScript)

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

				unlockingScript, err = UnlockAgentBitcoinTransferApprove(tx, inputIndex, value,
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

				unlockingScript, err = UnlockAgentBitcoinTransferRefund(tx, inputIndex, value,
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

				unlockingScript, err = UnlockAgentBitcoinTransferRecover(tx, inputIndex, value,
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
			if err := interpreter.ExecuteVerbose(ctx, unlockingScript, tx, inputIndex, value,
				hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			t.Logf("Execute locking script")

			if err := interpreter.ExecuteVerbose(ctx, lockingScript, tx, inputIndex, value,
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
