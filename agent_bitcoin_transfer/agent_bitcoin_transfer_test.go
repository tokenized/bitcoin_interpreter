package agent_bitcoin_transfer

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
)

// This one failed on chain and now fails here after updating the interpreter to reverse SUB, MOD, and DIV
func Test_AgentBitcoinTransfer_ActualFail_1(t *testing.T) {
	t.Skip()

	ctx := logger.ContextWithLogger(context.Background(), true, false, "")

	b, err := hex.DecodeString("010000000271266f87fb58d5cb8f4b306e5a02f03cf6c5f916cd023393f4eee0d02b7dac9700000000fd0c014c9e010000009ba97bb3ec9e1acb6f64ab5ed63eca16f3a2918413804eac0d64ec59b6e2ad6c000000000000000000000000000000000000000000000000000000000000000071266f87fb58d5cb8f4b306e5a02f03cf6c5f916cd023393f4eee0d02b7dac970000000001ac6400000000000000ffffffff4fe97353057886c87f09a4fd46364a1cc45189f04a79b95d2252075229406c5c000000004300000000473044022033aa8f9d953b6a0a2d176fcb99be2bea56bacb6f9af1de79c8587b911dc416710220250d942d222ae46066f3ac9c3af0bd366793121b6438ef23039917524c9880824121022680aa566537a7650e13ebf9644156fd8a70b8953caec05de0ac72cf0f7c73a600ffffffff71266f87fb58d5cb8f4b306e5a02f03cf6c5f916cd023393f4eee0d02b7dac97010000006a473044022037c135edcf5c94d5bc2475ecb2de5a67de01c1db24f68eb49872bfd43078c1bd02207d2749cfe1b94a59218aa4166633013012585e1230fb695e367d5229aaad6c95412103aab023eda6068d1d247504551b1e5b574baff988b4637719ceddf52a64a7470fffffffff0264000000000000001976a914aeaa1bd67791f4c1d3ecb4a1641ae524ba1cb10d88ac5c260000000000001976a914b33bb20086c0d75da054bcf06b2dbf17519a3d1388ac00000000")
	if err != nil {
		t.Fatalf("Failed to decode tx hex : %s", err)
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("Failed to deserialize tx : %s", err)
	}

	b, err = hex.DecodeString("6476a91405f9adfd514e4a9f97a73842b3db7cad7d7ad43f88ad647682587c947f758201207c947f7c75204fe97353057886c87f09a4fd46364a1cc45189f04a79b95d2252075229406c5c88677682587c947f758201207c947f7c75204324664cc6bda3350c654da4f72b2336c5ea102f1a4e5463adfc392cd9aa93ec88686776a91443bf9c75ccbdde9f33c94628c1f58a38b2fb9cbf88ad7682547c947f7582547c947f7c75047cd3526488768201287c947f7582547c947f7c7504ffffffff87916968aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7600a063007e6840f608e7b277ed70a30a879f500cdc24ef395fab9966d07615541c27da0222143d1044147c0f5849d63e288e823215a090789e81be96c8a523e8214cfdba62d0079320e4985843644c24f6d3dca51da13ca4303f4de290393918fa3ddfa348f94aeb799521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00767b7c9776525379969f637c94677768012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e527c7e220220335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a7c7e827c7e01307c7e01437e2102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382abac")
	if err != nil {
		t.Fatalf("Failed to decode locking script hex : %s", err)
	}
	lockingScript := bitcoin.Script(b)
	value := uint64(100)
	inputIndex := 0

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache := &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteVerbose(ctx, tx.TxIn[0].UnlockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Fatalf("Failed to interpret unlocking script : %s", err)
	}

	t.Logf("Execute locking script")

	if err := interpreter.ExecuteVerbose(ctx, lockingScript, tx, inputIndex, value,
		hashCache); err != nil {
		t.Logf("Correctly did not unlock script : %s", err)
	}

	stack := interpreter.StackItems()
	t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

	if interpreter.IsUnlocked() {
		t.Fatalf("Should not have unlocked script")
	} else {
		t.Logf("Correctly did not unlock script : %s", interpreter.Error())
	}
}

func Test_AgentBitcoinTransfer_ActualFail_2(t *testing.T) {
	t.Skip()

	ctx := logger.ContextWithLogger(context.Background(), true, false, "")

	b, err := hex.DecodeString("010000000244de19e69e00c02526961e0d4a292842e9fc58e5d0588ff097a9e6365200fb9b00000000fd0d014c9e01000000aee8ed17730c73a302c08145d8ba39a4d50dd7040d363fc63029b7273e8464d4000000000000000000000000000000000000000000000000000000000000000044de19e69e00c02526961e0d4a292842e9fc58e5d0588ff097a9e6365200fb9b0000000001ac6400000000000000ffffffff4fe97353057886c87f09a4fd46364a1cc45189f04a79b95d2252075229406c5c000000004300000000483045022100e3348f2a70ea7e6ed8f47d463d18cd19dd0b5988ea5549afd51ab5cb9b98d4a902204f7bd7f0498aa8b6fcf80ad60fa67dcf9c608f81d808ba261d18f13183dbb38f4121022680aa566537a7650e13ebf9644156fd8a70b8953caec05de0ac72cf0f7c73a600ffffffff44de19e69e00c02526961e0d4a292842e9fc58e5d0588ff097a9e6365200fb9b010000006a473044022071747005f719b9820cfe51030b11ca18a4e092b28c2d1e68d6d1ad275c7d848a02205f2f635d51f28b612e8914b8674cc99a6b06a7da9fea9aae4ad0c3b8ef98998b412103aab023eda6068d1d247504551b1e5b574baff988b4637719ceddf52a64a7470fffffffff0264000000000000001976a914aeaa1bd67791f4c1d3ecb4a1641ae524ba1cb10d88acc8250000000000001976a914b33bb20086c0d75da054bcf06b2dbf17519a3d1388ac00000000")
	if err != nil {
		t.Fatalf("Failed to decode tx hex : %s", err)
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("Failed to deserialize tx : %s", err)
	}

	b, err = hex.DecodeString("6476a91405f9adfd514e4a9f97a73842b3db7cad7d7ad43f88ad64768258947f75820120947f7c75204fe97353057886c87f09a4fd46364a1cc45189f04a79b95d2252075229406c5c8867768258947f75820120947f7c75204324664cc6bda3350c654da4f72b2336c5ea102f1a4e5463adfc392cd9aa93ec88686776a91443bf9c75ccbdde9f33c94628c1f58a38b2fb9cbf88ad768254947f758254947f7c750484f452648876820128947f758254947f7c7504ffffffff87916968aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e76007ca063007e6840f608e7b277ed70a30a879f500cdc24ef395fab9966d07615541c27da0222143d1044147c0f5849d63e288e823215a090789e81be96c8a523e8214cfdba62d0079320e4985843644c24f6d3dca51da13ca4303f4de290393918fa3ddfa348f94aeb799521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff00767b97765253797c967c9f6394677768012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e527c7e220220335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a7c7e827c7e01307c7e01437e2102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382abac")
	if err != nil {
		t.Fatalf("Failed to decode locking script hex : %s", err)
	}
	lockingScript := bitcoin.Script(b)
	value := uint64(100)
	inputIndex := 0

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache := &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteVerbose(ctx, tx.TxIn[0].UnlockingScript, tx, inputIndex, value,
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

	if interpreter.IsUnlocked() {
		t.Fatalf("Should not have unlocked script")
	} else {
		t.Logf("Correctly did not unlock script : %s", interpreter.Error())
	}
}

func Test_AgentBitcoinTransfer_ActualFail_3(t *testing.T) {
	t.Skip()

	ctx := logger.ContextWithLogger(context.Background(), true, false, "")

	b, err := hex.DecodeString("0100000002b5cc0d5d1995dd5562829e8e3e66ee0f771dc91c07599dff0e88d4d531a095d600000000fd0c014c9e01000000bb9ebd27d9fc91d4001fb6fe19aaa7f31ec36c1b7c902362204c9eaf8b5d39b30000000000000000000000000000000000000000000000000000000000000000b5cc0d5d1995dd5562829e8e3e66ee0f771dc91c07599dff0e88d4d531a095d60000000001ac0100000000000000ffffffffe3e73b2804afe82f6c72f2b2e82ea9e8718563fd3a1fcdb7b5a928b7cfa51ca8000000004300000000473044022046c33c7af64f114c7c27d1dbf60a3b74e69984660a48b55e5e623c565641a0e202203c88f478c74e62b400555bf59046afd53afad2952b7c8c8379bff27383cfc3444121022680aa566537a7650e13ebf9644156fd8a70b8953caec05de0ac72cf0f7c73a600ffffffffb5cc0d5d1995dd5562829e8e3e66ee0f771dc91c07599dff0e88d4d531a095d6010000006b483045022100a8694bcbf7da9f17ce03020430caee36691fe9ede5a69bd4d77c5b99af159ab702204cb49f119f3116c0ce2537c4e860bf687a36312844a0c4b2ceb6da964717ea9d412103aab023eda6068d1d247504551b1e5b574baff988b4637719ceddf52a64a7470fffffffff0201000000000000001976a914aeaa1bd67791f4c1d3ecb4a1641ae524ba1cb10d88ac70240000000000001976a914b33bb20086c0d75da054bcf06b2dbf17519a3d1388ac00000000")
	if err != nil {
		t.Fatalf("Failed to decode tx hex : %s", err)
	}

	tx := &wire.MsgTx{}
	if err := tx.Deserialize(bytes.NewReader(b)); err != nil {
		t.Fatalf("Failed to deserialize tx : %s", err)
	}

	b, err = hex.DecodeString("6476a91405f9adfd514e4a9f97a73842b3db7cad7d7ad43f88ad64768258947f75820120947f7c7520e3e73b2804afe82f6c72f2b2e82ea9e8718563fd3a1fcdb7b5a928b7cfa51ca88867768258947f75820120947f7c7520a15b2d92a39c962c851a868cba3299d0b516d9860d2e2e7dfc7828fb8bf308f288686776a91443bf9c75ccbdde9f33c94628c1f58a38b2fb9cbf88ad768254947f758254947f7c7504e64254648876820128947f758254947f7c7504ffffffff87916968aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e76009f6301007e6840f608e7b277ed70a30a879f500cdc24ef395fab9966d07615541c27da0222143d1044147c0f5849d63e288e823215a090789e81be96c8a523e8214cfdba62d0079320e4985843644c24f6d3dca51da13ca4303f4de290393918fa3ddfa348f94aeb799521414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d977652795296a06394677768012080517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e527c7e220220335fbb3f993be0a0c12b70fbc38cbea95a8c4a259e7412192534d343422cbd7a7c7e827c7e01307c7e01437e2102ba79df5f8ae7604a9830f03c7933028186aede0675a16f025dc4f8be8eec0382abac")
	if err != nil {
		t.Fatalf("Failed to decode locking script hex : %s", err)
	}
	lockingScript := bitcoin.Script(b)
	value := uint64(1)
	inputIndex := 0

	interpreter := bitcoin_interpreter.NewInterpreter()

	hashCache := &bitcoin_interpreter.SigHashCache{}
	if err := interpreter.ExecuteVerbose(ctx, tx.TxIn[0].UnlockingScript, tx, inputIndex, value,
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

	if interpreter.IsUnlocked() {
		t.Fatalf("Should not have unlocked script")
	} else {
		t.Logf("Correctly did not unlock script : %s", interpreter.Error())
	}
}

func Test_AgentBitcoinTransfer_Cases(t *testing.T) {
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

				unlockingScript, err = UnlockAgentBitcoinTransferApprove(ctx, tx, inputIndex, value,
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

				unlockingScript, err = UnlockAgentBitcoinTransferRefund(ctx, tx, inputIndex, value,
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

				unlockingScript, err = UnlockAgentBitcoinTransferRecover(ctx, tx, inputIndex, value,
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
