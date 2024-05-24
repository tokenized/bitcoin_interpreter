package agent_bitcoin_transfer

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/bitcoin_interpreter/check_signature_preimage"
	"github.com/tokenized/bitcoin_interpreter/p2pkh"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/expanded_tx"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

// Test_Unlock_Raw tests unlocking a generated script with correct and incorrect values.
func Test_Unlock_Raw(t *testing.T) {
	// Run these tests a lot of times to ensure we hit tx malleation issues.
	for i := 0; i < 100; i++ {
		test_Unlock_Raw(t)
	}
}

func test_Unlock_Raw(t *testing.T) {
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

	agentLockingScriptVerify := agentLockingScript.Copy()
	agentLockingScriptVerify.AddHardVerify()
	if !info.AgentLockingScript.Equal(agentLockingScriptVerify) {
		t.Fatalf("MatchScript provided wrong agent locking script : \n  got  : %s\n  want : %s",
			info.AgentLockingScript, agentLockingScriptVerify)
	}

	if !info.ApproveOutputHash.Equal(approveOutputsHash) {
		t.Fatalf("MatchScript provided wrong approve output hash : \n  got  : %s\n  want : %s",
			info.ApproveOutputHash, approveOutputsHash)
	}

	if !info.RefundOutputHash.Equal(refundOutputsHash) {
		t.Fatalf("MatchScript provided wrong refund output hash : \n  got  : %s\n  want : %s",
			info.RefundOutputHash, refundOutputsHash)
	}

	recoverLockingScriptVerify := recoverLockingScript.Copy()
	recoverLockingScriptVerify.AddHardVerify()
	if !info.RecoverLockingScript.Equal(recoverLockingScriptVerify) {
		t.Fatalf("MatchScript provided wrong recover locking script : \n  got  : %s\n  want : %s",
			info.RecoverLockingScript, recoverLockingScriptVerify)
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
			writeSigPreimage := bitcoin_interpreter.TxWriteSignaturePreimage(tx, inputIndex, value,
				hashCache)
			preimage, err := bitcoin_interpreter.SignaturePreimage(tx, inputIndex, lockingScript,
				-1, value, sigHashType, hashCache)
			if err != nil {
				t.Fatalf("Failed to get signature preimage : %s", err)
			}
			t.Logf("Preimage : %x", preimage)

			var unlockingScript bitcoin.Script
			switch tt.branch {
			case 0: // agent approve
				for i := 0; i < 5; i++ {
					sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript,
						-1, value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
						hashCache)
					if err != nil {
						t.Fatalf("Failed to create sig hash : %s", err)
					}

					signature, err := tt.txSigner.Sign(sigHash)
					if err != nil {
						t.Fatalf("Failed to create agent signature : %s", err)
					}

					agentUnlockingScript := bitcoin.ConcatScript(
						bitcoin.PushData(append(signature.Bytes(),
							byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
						bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
					)

					unlockingScript, err = UnlockApprove(ctx, writeSigPreimage, lockingScript,
						agentUnlockingScript)
					if err != nil {
						if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
							hashCache.Clear()
							tx.LockTime++
							t.Logf("Malleated tx")
							continue
						}
						t.Fatalf("Failed to create unlocking script : %s", err)
					}

					break
				}

			case 1: // agent refund
				for i := 0; i < 5; i++ {
					sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript,
						-1, value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
						hashCache)
					if err != nil {
						t.Fatalf("Failed to create sig hash : %s", err)
					}

					signature, err := tt.txSigner.Sign(sigHash)
					if err != nil {
						t.Fatalf("Failed to create agent signature : %s", err)
					}

					agentUnlockingScript := bitcoin.ConcatScript(
						bitcoin.PushData(append(signature.Bytes(),
							byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
						bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
					)

					unlockingScript, err = UnlockRefund(ctx, writeSigPreimage, lockingScript,
						agentUnlockingScript)
					if err != nil {
						if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
							hashCache.Clear()
							tx.LockTime++
							t.Logf("Malleated tx")
							continue
						}
						t.Fatalf("Failed to create unlocking script : %s", err)
					}

					break
				}

			case 2: // recover
				for i := 0; i < 5; i++ {
					sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript,
						-1, value, bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
						hashCache)
					if err != nil {
						t.Fatalf("Failed to create sig hash : %s", err)
					}

					signature, err := tt.txSigner.Sign(sigHash)
					if err != nil {
						t.Fatalf("Failed to create agent signature : %s", err)
					}

					recoverUnlockingScript := bitcoin.ConcatScript(
						bitcoin.PushData(append(signature.Bytes(),
							byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
						bitcoin.PushData(tt.txSigner.PublicKey().Bytes()),
					)

					unlockingScript, err = UnlockRecover(ctx, writeSigPreimage, lockingScript,
						recoverUnlockingScript)
					if err != nil {
						if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
							hashCache.Clear()
							tx.TxOut[len(tx.TxOut)-1].Value--
							t.Logf("Malleated tx")
							continue
						}
						t.Fatalf("Failed to create unlocking script : %s", err)
					}

					break
				}

			default:
				t.Fatalf("Unsupported branch value : %d", tt.branch)
			}

			t.Logf("Unlocking Script (%d bytes) : %s", len(unlockingScript), unlockingScript)

			interpreter := bitcoin_interpreter.NewInterpreter()

			if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
				hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			t.Logf("Execute locking script")

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

func Test_Fixtures(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")

	tests := []struct {
		name       string
		filename   string
		inputIndex int
		baseErr    error
	}{
		{
			name:       "non-minimally encoded script number",
			filename:   "e4e3eec19b12432464dfadc112e8bfa9ba2fc207c7e1b89231cd46b441386c9b.hex",
			inputIndex: 0,
			baseErr:    bitcoin_interpreter.ErrNonMinimallyEncodedNumber,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := os.ReadFile("fixtures/" + tt.filename)
			if err != nil {
				t.Fatalf("Failed to read file : %s", err)
			}

			b, err := hex.DecodeString(string(h))
			if err != nil {
				t.Fatalf("Failed to convert hex : %s", err)
			}

			tx := &wire.MsgTx{}
			if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
				t.Fatalf("Failed to decode tx : %s", err)
			}

			etx := &expanded_tx.ExpandedTx{
				Tx: tx,
			}

			for _, txin := range tx.TxIn {
				if etx.Ancestors.GetTx(txin.PreviousOutPoint.Hash) != nil {
					continue
				}

				h, err := os.ReadFile("fixtures/input_" + txin.PreviousOutPoint.Hash.String() + ".hex")
				if err != nil {
					t.Fatalf("Failed to read input file : %s", err)
				}

				b, err := hex.DecodeString(string(h))
				if err != nil {
					t.Fatalf("Failed to convert input hex : %s", err)
				}

				tx := &wire.MsgTx{}
				if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
					t.Fatalf("Failed to decode input tx : %s", err)
				}

				etx.Ancestors = append(etx.Ancestors, &expanded_tx.AncestorTx{
					Tx: tx,
				})
			}

			t.Logf("Tx : %s", etx)

			hashCache := &bitcoin_interpreter.SigHashCache{}
			interpreter := bitcoin_interpreter.NewInterpreter()
			txin := etx.Tx.TxIn[tt.inputIndex]

			inputTx := etx.Ancestors.GetTx(txin.PreviousOutPoint.Hash)
			if inputTx == nil {
				t.Fatalf("Failed to get input tx")
			}

			if int(txin.PreviousOutPoint.Index) >= len(inputTx.Tx.TxOut) {
				t.Fatalf("Invalid outpoint index : %d >= %d", txin.PreviousOutPoint.Index,
					len(inputTx.Tx.TxOut))
			}

			output := inputTx.Tx.TxOut[txin.PreviousOutPoint.Index]

			t.Logf("Unlocking script")
			var finalErr error
			if err := interpreter.ExecuteTx(ctx, etx.Tx.TxIn[tt.inputIndex].UnlockingScript, etx.Tx,
				tt.inputIndex, output.Value, hashCache); err != nil {
				t.Logf("Failed to verify unlocking script : %s", err)
				finalErr = err
			}

			if finalErr == nil {
				t.Logf("Locking script")
				if err := interpreter.ExecuteTx(ctx, output.LockingScript, etx.Tx, tt.inputIndex,
					output.Value, hashCache); err != nil {
					t.Logf("Failed to verify locking script : %s", err)
					finalErr = err
				}
			}

			if finalErr == nil {
				if !interpreter.IsUnlocked() {
					t.Errorf("Script should be unlocked : %s", interpreter.Error())
				} else {
					t.Logf("Input %d unlocked", tt.inputIndex)
				}
			}

			if finalErr == nil {
				finalErr = interpreter.Error()
			}

			if tt.baseErr == nil {
				if interpreter.Error() != nil {
					t.Errorf("Interpreter error should be nil : %s", interpreter.Error())
				}
			} else if finalErr == nil {
				t.Errorf("Interpreter should have returned error")
			} else if errors.Cause(finalErr) != tt.baseErr {
				t.Errorf("Wrong interpreter error : got %s, want %s", finalErr, tt.baseErr)
			} else {
				t.Logf("Interpreter returned correct error : %s", finalErr)
			}
		})
	}
}

// Test_Check verifies that the Check function will detect when a tx malleation will be needed
// without needing to have the agent key to actually unlock it.
func Test_Check(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle

	totalMalleations := 0
	total := 1000
	for i := 0; i < total; i++ {
		t.Run(fmt.Sprintf("random%04d", i), func(t *testing.T) {
			if txBytes, malleations, err := check_Random(ctx, t, sigHashType); err != nil {
				t.Errorf("Failed Tx Bytes (%s) : %x", err, txBytes)
			} else {
				totalMalleations += malleations
			}
		})
	}

	t.Logf("%d of %d transaction malleations needed", totalMalleations, total)
}

func check_Random(ctx context.Context, t *testing.T,
	sigHashType bitcoin_interpreter.SigHashType) ([]byte, int, error) {

	agentKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	agentLockingScript, _ := agentKey.LockingScript()

	recoverKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	recoverLockingScript, _ := recoverKey.LockingScript()

	approveKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	approveLockingScript, _ := approveKey.LockingScript()

	refundKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	refundLockingScript, _ := refundKey.LockingScript()

	recoverLockTime := uint32(time.Now().Unix()) + uint32(rand.Intn(100000))

	value := uint64(rand.Intn(10000000) + 1)

	lockingScript, err := CreateScript(agentLockingScript, approveLockingScript,
		refundLockingScript, value, recoverLockingScript, recoverLockTime)
	if err != nil {
		return nil, 0, errors.Wrap(err, "create")
	}

	tx := wire.NewMsgTx(1)

	// Add input to spend specified output.
	inputIndex := len(tx.TxIn)
	var previousTxHash bitcoin.Hash32
	rand.Read(previousTxHash[:])
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&previousTxHash, 0), nil))

	tx.AddTxOut(wire.NewTxOut(value, approveLockingScript))

	for i := 0; i < 3; i++ {
		hashCache := &bitcoin_interpreter.SigHashCache{}
		writeSigPreimage := bitcoin_interpreter.TxWriteSignaturePreimage(tx, inputIndex, value,
			hashCache)

		needsMalleation := false
		if err := Check(ctx, writeSigPreimage, lockingScript); err != nil {
			if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
				t.Logf("Tx needs malleation")
				needsMalleation = true
			} else {
				t.Fatalf("Failed to get signature preimage : %s", err)
			}
		}

		agentSigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
			value, sigHashType, hashCache)
		if err != nil {
			t.Fatalf("Failed to create sig hash : %s", err)
		}

		agentSignature, err := agentKey.Sign(agentSigHash)
		if err != nil {
			t.Fatalf("Failed to create agent signature : %s", err)
		}

		agentUnlockingScript := bitcoin.ConcatScript(
			bitcoin.PushData(append(agentSignature.Bytes(), byte(sigHashType))),
			bitcoin.PushData(agentKey.PublicKey().Bytes()),
		)

		if _, err := UnlockApprove(ctx, writeSigPreimage, lockingScript,
			agentUnlockingScript); err != nil {
			if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
				if !needsMalleation {
					t.Errorf("Malleation need not detected by Check")
					txBuf := &bytes.Buffer{}
					tx.Serialize(txBuf)
					return txBuf.Bytes(), 0, err
				}
			} else {
				txBuf := &bytes.Buffer{}
				tx.Serialize(txBuf)
				return txBuf.Bytes(), 0, err
			}
		}

		if !needsMalleation {
			return nil, i, nil
		}

		tx.LockTime++
	}

	txBuf := &bytes.Buffer{}
	tx.Serialize(txBuf)
	return txBuf.Bytes(), 0, errors.New("Failed to unlock script")
}

func Test_Unlocker(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	sigHashType := bitcoin_interpreter.SigHashForkID | bitcoin_interpreter.SigHashSingle

	for i := 0; i < 1; i++ {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			test_Unlocker(t, ctx, sigHashType)
		})
	}
}

func test_Unlocker(t *testing.T, ctx context.Context, sigHashType bitcoin_interpreter.SigHashType) {
	value := uint64(rand.Intn(1000) + 1)

	agentKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	agentLockingScript := p2pkh.CreateScript(agentKey.PublicKey(), true)

	recoverKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	recoverLockingScript := p2pkh.CreateScript(recoverKey.PublicKey(), true)

	approveKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	approveLockingScript := p2pkh.CreateScript(approveKey.PublicKey(), false)

	refundKey, _ := bitcoin.GenerateKey(bitcoin.MainNet)
	refundLockingScript := p2pkh.CreateScript(refundKey.PublicKey(), false)

	recoverLockTime := uint32(time.Now().Unix()) + 10000

	lockingScript, err := CreateScript(agentLockingScript, approveLockingScript,
		refundLockingScript, value, recoverLockingScript, recoverLockTime)
	if err != nil {
		t.Fatalf("Failed to create agent bitcoin transfer script : %s", err)
	}
	t.Logf("AgentBitcoinTransferScript (%d bytes) : %s", len(lockingScript), lockingScript)

	agentUnlocker := p2pkh.NewUnlockerFull(agentKey, true,
		bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll, -1)

	recoverUnlocker := p2pkh.NewUnlockerFull(recoverKey, true,
		bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll, -1)

	// Create tx
	inputTx := wire.NewMsgTx(1)
	inputTx.AddTxOut(wire.NewTxOut(value, lockingScript))

	tx := wire.NewMsgTx(1)
	inputIndex := len(tx.TxIn)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(inputTx.TxHash(), 0), nil))

	tx.AddTxOut(wire.NewTxOut(value, approveLockingScript))

	// etx := &expanded_tx.ExpandedTx{
	// 	Tx: tx,
	// 	Ancestors: expanded_tx.AncestorTxs{
	// 		{
	// 			Tx: inputTx,
	// 		},
	// 	},
	// }

	// Test approve unlock #########################################################################
	approveUnlocker := NewAgentApproveUnlocker(agentUnlocker)

	hashCache := &bitcoin_interpreter.SigHashCache{}
	writeSigPreimage := bitcoin_interpreter.TxWriteSignaturePreimage(tx, inputIndex, value,
		hashCache)

	// Unlock tx
	if !approveUnlocker.CanUnlock(lockingScript) {
		t.Fatalf("CanUnlock should return true")
	}

	for {
		unlockingScript, err := approveUnlocker.Unlock(ctx, writeSigPreimage, lockingScript)
		if err != nil {
			t.Fatalf("Failed to unlock : %s", err)
		}

		unlockingSize, err := approveUnlocker.UnlockingSize(lockingScript)
		if err != nil {
			t.Fatalf("Failed to calculate unlocking size : %s", err)
		}

		if len(unlockingScript) > unlockingSize {
			t.Fatalf("Unlocking size above estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		if len(unlockingScript) > unlockingSize+5 {
			t.Fatalf("Unlocking size over estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		t.Logf("Unlock size %d is within %d of estimated %d", len(unlockingScript), 5, unlockingSize)

		tx.TxIn[inputIndex].UnlockingScript = unlockingScript

		// Verify unlocking script actually unlocks in the interpreter.
		interpreter := bitcoin_interpreter.NewInterpreter()

		if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			t.Fatalf("Failed to interpret unlocking script : %s", err)
		}

		if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
				tx.LockTime++
				hashCache.Clear()
				continue
			}
			t.Fatalf("Failed to interpret locking script : %s", err)
		}

		stack := interpreter.StackItems()
		t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

		if !interpreter.IsUnlocked() {
			t.Fatalf("Failed to unlock script : %s", interpreter.Error())
		}

		break
	}

	// Test refund unlock ##########################################################################
	refundUnlocker := NewAgentRefundUnlocker(agentUnlocker)

	hashCache.Clear()

	tx.TxOut[0] = wire.NewTxOut(value, refundLockingScript)

	// Unlock tx
	if !refundUnlocker.CanUnlock(lockingScript) {
		t.Fatalf("CanUnlock should return true")
	}

	for {
		unlockingScript, err := refundUnlocker.Unlock(ctx, writeSigPreimage, lockingScript)
		if err != nil {
			t.Fatalf("Failed to unlock : %s", err)
		}

		unlockingSize, err := refundUnlocker.UnlockingSize(lockingScript)
		if err != nil {
			t.Fatalf("Failed to calculate unlocking size : %s", err)
		}

		if len(unlockingScript) > unlockingSize {
			t.Fatalf("Unlocking size above estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		if len(unlockingScript) > unlockingSize+5 {
			t.Fatalf("Unlocking size over estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		t.Logf("Unlock size %d is within %d of estimated %d", len(unlockingScript), 5, unlockingSize)

		tx.TxIn[inputIndex].UnlockingScript = unlockingScript

		// Verify unlocking script actually unlocks in the interpreter.
		interpreter := bitcoin_interpreter.NewInterpreter()
		// interpreter.SetVerbose()

		if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			t.Fatalf("Failed to interpret unlocking script : %s", err)
		}

		if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
				tx.LockTime++
				hashCache.Clear()
				continue
			}
			t.Fatalf("Failed to interpret locking script : %s", err)
		}

		stack := interpreter.StackItems()
		t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

		if !interpreter.IsUnlocked() {
			t.Fatalf("Failed to unlock script : %s", interpreter.Error())
		}

		break
	}

	// Test recover unlock #########################################################################
	transferRecoverUnlocker := NewRecoverUnlocker(recoverUnlocker)

	hashCache.Clear()

	tx.TxOut[0] = wire.NewTxOut(value, refundLockingScript)
	tx.TxIn[inputIndex].Sequence = 1
	tx.LockTime = recoverLockTime

	// Unlock tx
	if !transferRecoverUnlocker.CanUnlock(lockingScript) {
		t.Fatalf("CanUnlock should return true")
	}

	for {
		unlockingScript, err := transferRecoverUnlocker.Unlock(ctx, writeSigPreimage, lockingScript)
		if err != nil {
			t.Fatalf("Failed to unlock : %s", err)
		}

		unlockingSize, err := transferRecoverUnlocker.UnlockingSize(lockingScript)
		if err != nil {
			t.Fatalf("Failed to calculate unlocking size : %s", err)
		}

		if len(unlockingScript) > unlockingSize {
			t.Fatalf("Unlocking size above estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		if len(unlockingScript) > unlockingSize+5 {
			t.Fatalf("Unlocking size over estimate : got %d, want %d", unlockingSize,
				len(unlockingScript))
		}

		t.Logf("Unlock size %d is within %d of estimated %d", len(unlockingScript), 5, unlockingSize)

		tx.TxIn[inputIndex].UnlockingScript = unlockingScript

		// Verify unlocking script actually unlocks in the interpreter.
		interpreter := bitcoin_interpreter.NewInterpreter()

		if err := interpreter.ExecuteTx(ctx, unlockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			t.Fatalf("Failed to interpret unlocking script : %s", err)
		}

		if err := interpreter.ExecuteTx(ctx, lockingScript, tx, inputIndex, value,
			hashCache); err != nil {
			if errors.Cause(err) == check_signature_preimage.TxNeedsMalleation {
				tx.LockTime++
				hashCache.Clear()
				continue
			}
			t.Fatalf("Failed to interpret locking script : %s", err)
		}

		stack := interpreter.StackItems()
		t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

		if !interpreter.IsUnlocked() {
			t.Fatalf("Failed to unlock script : %s", interpreter.Error())
		}

		break
	}
}

func within(x, target, within int) bool {
	if x > target+within {
		return false
	}

	if x < target-within {
		return false
	}

	return true
}
