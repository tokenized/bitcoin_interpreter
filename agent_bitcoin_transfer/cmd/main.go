package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/bitcoin_interpreter/agent_bitcoin_transfer"
	"github.com/tokenized/config"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/whatsonchain"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

type Config struct {
	Key      bitcoin.Key `envconfig:"KEY" json:"key" maske:"true"`
	AgentKey bitcoin.Key `envconfig:"AGENT_KEY" json:"agent_key" maske:"true"`

	ApproveKey bitcoin.Key `envconfig:"APPROVE_KEY" json:"approve_key" maske:"true"`
	RefundKey  bitcoin.Key `envconfig:"REFUND_KEY" json:"refund_key" maske:"true"`
	RecoverKey bitcoin.Key `envconfig:"RECOVER_KEY" json:"recover_key" maske:"true"`

	FeeRate     float32 `default:"0.05" envconfig:"FEE_RATE" json:"fee_rate"`
	DustFeeRate float32 `default:"0.0" envconfig:"DUST_FEE_RATE" json:"dust_fee_rate"`
}

func main() {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "cli.log")

	cfg := &Config{}
	if err := config.LoadConfig(ctx, cfg); err != nil {
		logger.Fatal(ctx, "Failed to load config : %s", err)
	}

	maskedConfig, err := config.MarshalJSONMaskedRaw(cfg)
	if err != nil {
		logger.Fatal(ctx, "Failed to marshal config : %s", err)
	}

	logger.InfoWithFields(ctx, []logger.Field{
		logger.JSON("config", maskedConfig),
	}, "Config")

	if len(os.Args) < 2 {
		logger.Fatal(ctx, "Not enough arguments. Need command (CreateAgentOutput)")
	}

	switch os.Args[1] {
	case "parse":
		if err := ParseAgentTransfer(ctx, cfg, os.Args[2:]); err != nil {
			logger.Fatal(ctx, "Failed to parse agent transfer : %s", err)
		}

	case "create_agent_output":
		if err := CreateAgentOutput(ctx, cfg, os.Args[2:]); err != nil {
			logger.Fatal(ctx, "Failed to create agent output : %s", err)
		}

	case "complete_agent_transfer":
		if err := CompleteAgentTransfer(ctx, cfg, os.Args[2:]); err != nil {
			logger.Fatal(ctx, "Failed to complete agent transfer : %s", err)
		}
	}
}

func ParseAgentTransfer(ctx context.Context, config *Config, args []string) error {
	if len(args) != 1 {
		return errors.New("Wrong argument count: parse [Script]")
	}

	b, err := hex.DecodeString(args[0])
	if err != nil {
		return errors.Wrap(err, "hex")
	}

	lockingScript := bitcoin.Script(b)
	fmt.Printf("Script : %s\n", lockingScript)

	info, err := agent_bitcoin_transfer.MatchScript(lockingScript)
	if err != nil {
		return errors.Wrap(err, "match")
	}

	js, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return errors.Wrap(err, "json marshal")
	}

	fmt.Printf("Info : %s\n", js)

	agentLockingScript := info.AgentLockingScript.Copy()
	agentLockingScript.RemoveHardVerify()
	fmt.Printf("Agent Locking Script : %s\n", agentLockingScript)
	agentRA, err := bitcoin.RawAddressFromLockingScript(agentLockingScript)
	if err != nil {
		return errors.Wrap(err, "agent address")
	}

	fmt.Printf("Agent Address : %s\n", bitcoin.NewAddressFromRawAddress(agentRA, bitcoin.MainNet))

	recoverLockingScript := info.RecoverLockingScript.Copy()
	recoverLockingScript.RemoveHardVerify()
	fmt.Printf("Recover Locking Script : %s\n", recoverLockingScript)
	recoverRA, err := bitcoin.RawAddressFromLockingScript(recoverLockingScript)
	if err != nil {
		return errors.Wrap(err, "recover address")
	}

	fmt.Printf("Recover Address : %s\n", bitcoin.NewAddressFromRawAddress(recoverRA,
		bitcoin.MainNet))

	refundOutputHash := wire.NewTxOut(10000, recoverLockingScript).OutputHash()
	fmt.Printf("Refund Output Hash : %s\n", refundOutputHash)

	return nil
}

func CreateAgentOutput(ctx context.Context, config *Config, args []string) error {
	if len(args) < 2 {
		return errors.New("Wrong argument count: create_agent_output [Value] [Outpoints]...")
	}

	v, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("Invalid value : %s : %s", args[0], err)
	}
	value := uint64(v)

	lockingScript, err := config.Key.LockingScript()
	if err != nil {
		return errors.Wrap(err, "locking script")
	}

	woc := whatsonchain.NewService("", bitcoin.MainNet, time.Second*10, time.Second*30)

	unlockSize := 0
	inputValue := uint64(0)
	var inputValues []uint64
	tx := wire.NewMsgTx(1)
	for i := 1; i < len(args); i++ {
		outpoint, err := wire.OutPointFromStr(args[i])
		if err != nil {
			return fmt.Errorf("Invalid outpoint : %s : %s", args[i], err)
		}

		outpointTx, err := woc.GetTx(ctx, outpoint.Hash)
		if err != nil {
			return fmt.Errorf("Failed to get outpoint tx : %s", err)
		}

		if outpoint.Index >= uint32(len(outpointTx.TxOut)) {
			return fmt.Errorf("Invalid outpoint index : %d >= %d", outpoint.Index,
				len(outpointTx.TxOut))
		}

		output := outpointTx.TxOut[outpoint.Index]
		if !lockingScript.Equal(output.LockingScript) {
			return fmt.Errorf("Wrong outpoint locking script : %s", output.LockingScript)
		}

		tx.AddTxIn(wire.NewTxIn(outpoint, nil))
		unlockSize += 108
		inputValue += output.Value
		inputValues = append(inputValues, output.Value)
	}

	agentLockingScript, err := config.AgentKey.LockingScript()
	if err != nil {
		return errors.Wrap(err, "agent locking script")
	}

	approveLockingScript, err := config.ApproveKey.LockingScript()
	if err != nil {
		return errors.Wrap(err, "approve locking script")
	}

	refundLockingScript, err := config.RefundKey.LockingScript()
	if err != nil {
		return errors.Wrap(err, "refund locking script")
	}

	recoverLockingScript, err := config.RecoverKey.LockingScript()
	if err != nil {
		return errors.Wrap(err, "recover locking script")
	}

	timelock := uint32(time.Now().Unix() + 3600)
	fmt.Printf("Timelock : %d\n", timelock)

	agentTransferLockingScript, err := agent_bitcoin_transfer.CreateScript(agentLockingScript,
		approveLockingScript, refundLockingScript, value, recoverLockingScript, timelock)
	outputValue := value

	tx.AddTxOut(wire.NewTxOut(value, agentTransferLockingScript))

	estimatedSize := unlockSize + tx.SerializeSize()
	estimatedFee := uint64(config.FeeRate*float32(estimatedSize)) + 5

	if inputValue < estimatedFee+outputValue {
		return fmt.Errorf("Insufficient value : outpoints %d, needed %d", inputValue, estimatedFee)
	} else if inputValue-(estimatedFee+outputValue) > 10 {
		estimatedFee += uint64(config.FeeRate * float32(34))

		tx.AddTxOut(wire.NewTxOut(inputValue-(estimatedFee+outputValue), lockingScript))
		outputValue += inputValue - (estimatedFee + outputValue)
	}

	hashCache := &bitcoin_interpreter.SigHashCache{}
	for inputIndex, txin := range tx.TxIn {
		sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
			inputValues[inputIndex], bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
			hashCache)
		if err != nil {
			return fmt.Errorf("Failed to create sig hash : %s", err)
		}

		signature, err := config.Key.Sign(sigHash)
		if err != nil {
			return fmt.Errorf("Failed to create signature : %s", err)
		}

		txin.UnlockingScript = bitcoin.ConcatScript(
			bitcoin.PushData(append(signature.Bytes(),
				byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
			bitcoin.PushData(config.Key.PublicKey().Bytes()),
		)
	}

	buf := &bytes.Buffer{}
	if err := tx.Serialize(buf); err != nil {
		return fmt.Errorf("Failed to serialize tx : %s", err)
	}

	fmt.Printf("Tx : %s\n", tx.String())
	size := tx.SerializeSize()
	fee := inputValue - outputValue
	fmt.Printf("Input value : %d\n", inputValue)
	fmt.Printf("Output value : %d\n", outputValue)

	feeRate := float32(fee) / float32(size)
	fmt.Printf("Fee : %d (%0.5f sat/byte)\n", fee, feeRate)

	fmt.Printf("Tx Hex (%d bytes) : %x\n", size, buf.Bytes())
	return nil
}

func CompleteAgentTransfer(ctx context.Context, config *Config, args []string) error {
	if len(args) < 4 {
		return errors.New("Wrong argument count: approve_agent_transfer [Option 0-2] [Agent Outpoint] [Value] [Outpoints]...")
	}

	woc := whatsonchain.NewService("", bitcoin.MainNet, time.Second*10, time.Second*30)

	option, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("Invalid option : %s : %s", args[0], err)
	}

	outpoint, err := wire.OutPointFromStr(args[1])
	if err != nil {
		return fmt.Errorf("Invalid outpoint : %s : %s", args[1], err)
	}

	outpointTx, err := woc.GetTx(ctx, outpoint.Hash)
	if err != nil {
		return fmt.Errorf("Failed to get outpoint tx : %s", err)
	}

	if outpoint.Index >= uint32(len(outpointTx.TxOut)) {
		return fmt.Errorf("Invalid outpoint index : %d >= %d", outpoint.Index,
			len(outpointTx.TxOut))
	}

	output := outpointTx.TxOut[outpoint.Index]
	agentTransferLockingScript := output.LockingScript
	// TODO Verify locking script matches template. --ce
	// if !agentLockingScript.Equal(output.LockingScript) {
	// 	return fmt.Errorf("Wrong agent outpoint locking script : %s", output.LockingScript)
	// }

	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(outpoint, nil))
	unlockSize := 268
	inputValue := output.Value
	inputValues := []uint64{output.Value}

	v, err := strconv.Atoi(args[2])
	if err != nil {
		return fmt.Errorf("Invalid value : %s : %s", args[2], err)
	}
	value := uint64(v)

	lockingScript, err := config.Key.LockingScript()
	if err != nil {
		return errors.Wrap(err, "locking script")
	}

	for _, arg := range args[3:] {
		outpoint, err := wire.OutPointFromStr(arg)
		if err != nil {
			return fmt.Errorf("Invalid outpoint : %s : %s", arg, err)
		}

		outpointTx, err := woc.GetTx(ctx, outpoint.Hash)
		if err != nil {
			return fmt.Errorf("Failed to get outpoint tx : %s", err)
		}

		if outpoint.Index >= uint32(len(outpointTx.TxOut)) {
			return fmt.Errorf("Invalid outpoint index : %d >= %d", outpoint.Index,
				len(outpointTx.TxOut))
		}

		output := outpointTx.TxOut[outpoint.Index]
		if !lockingScript.Equal(output.LockingScript) {
			return fmt.Errorf("Wrong outpoint locking script : %s", output.LockingScript)
		}

		tx.AddTxIn(wire.NewTxIn(outpoint, nil))
		unlockSize += 108
		inputValue += output.Value
		inputValues = append(inputValues, output.Value)
	}

	outputValue := uint64(0)

	if option == 0 { // approve
		// Verified payment to refund address fdac47bee81a92918467ee0193d850ddbf3452b7d1b39b280392a81775580844
		approveLockingScript, err := config.ApproveKey.LockingScript()
		if err != nil {
			return errors.Wrap(err, "approve locking script")
		}
		tx.AddTxOut(wire.NewTxOut(value, approveLockingScript))
		outputValue += value

		// Attempt to pay wrong amount (Verified signature invalid) --ce
		// tx.AddTxOut(wire.NewTxOut(value+1, approveLockingScript))
		// outputValue += value+1

		// Attempt to pay to the wrong script (Verified signature invalid) --ce
		// tx.AddTxOut(wire.NewTxOut(value, lockingScript))
		// outputValue += value
	} else if option == 1 { // refund
		// Verified payment to refund address 8ddc63d0a573ecec014e0f86ea1925f630357eda4ba8b553523bfe382e57bc3b
		refundLockingScript, err := config.RefundKey.LockingScript()
		if err != nil {
			return errors.Wrap(err, "refund locking script")
		}
		tx.AddTxOut(wire.NewTxOut(value, refundLockingScript))
		outputValue += value

		// Attempt to pay wrong amount (Verified signature invalid) --ce
		// tx.AddTxOut(wire.NewTxOut(value+1, refundLockingScript))
		// outputValue += value+1

		// Attempt to pay to the wrong script (Verified signature invalid) --ce
		// tx.AddTxOut(wire.NewTxOut(value, lockingScript))
		// outputValue += value
	} else { // recover
		// Verified recover payment to funding key 00276557da5bb5abd6f5701ddabd3a4184208f1cefbb677b4a05f0270ad161d3
		tx.AddTxOut(wire.NewTxOut(value, lockingScript))
		outputValue += value + 1 // Output script or value don't matter when signed by recovery key.

		// Attempt to pay without timelock (Verified signature invalid) --ce
		// Attempt to pay with timlock but max sequence (Verified signature invalid) --ce
		tx.TxIn[0].Sequence = 1
		tx.LockTime = 1683314836 // This has to be updated manually based on the creation of the output.
	}

	estimatedSize := unlockSize + tx.SerializeSize()
	estimatedFee := uint64(config.FeeRate*float32(estimatedSize)) + 5 // plus 5 for rounding issues

	if inputValue < estimatedFee+outputValue {
		return fmt.Errorf("Insufficient value : outpoints %d, needed %d", inputValue, estimatedFee)
	} else if inputValue-(estimatedFee+outputValue) > 10 {
		estimatedFee += uint64(config.FeeRate * float32(34))

		tx.AddTxOut(wire.NewTxOut(inputValue-(estimatedFee+outputValue), lockingScript))
		outputValue += inputValue - (estimatedFee + outputValue)
	}

	// tx.LockTime++

	hashCache := &bitcoin_interpreter.SigHashCache{}

	// Sign agent input
	sigHash, err := bitcoin_interpreter.SignatureHash(tx, 0, agentTransferLockingScript, -1,
		inputValues[0], bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
		hashCache)
	if err != nil {
		return fmt.Errorf("Failed to create sig hash : %s", err)
	}

	signature, err := config.AgentKey.Sign(sigHash)
	if err != nil {
		return fmt.Errorf("Failed to create signature : %s", err)
	}

	agentUnlockingScript := bitcoin.ConcatScript(
		bitcoin.PushData(append(signature.Bytes(),
			byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
		bitcoin.PushData(config.AgentKey.PublicKey().Bytes()),
	)

	// Sign recover input
	sigHash, err = bitcoin_interpreter.SignatureHash(tx, 0, agentTransferLockingScript, -1,
		inputValues[0], bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
		hashCache)
	if err != nil {
		return fmt.Errorf("Failed to create sig hash : %s", err)
	}

	signature, err = config.RecoverKey.Sign(sigHash)
	if err != nil {
		return fmt.Errorf("Failed to create signature : %s", err)
	}

	recoverUnlockingScript := bitcoin.ConcatScript(
		bitcoin.PushData(append(signature.Bytes(),
			byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
		bitcoin.PushData(config.RecoverKey.PublicKey().Bytes()),
	)

	if option == 0 { // approve
		unlockingScript, err := agent_bitcoin_transfer.UnlockApprove(ctx, tx, 0, inputValues[0],
			agentTransferLockingScript, agentUnlockingScript)
		if err != nil {
			return fmt.Errorf("Failed to create agent transfer approve unlocking script : %s", err)
		}
		tx.TxIn[0].UnlockingScript = unlockingScript
	} else if option == 1 { // refund
		unlockingScript, err := agent_bitcoin_transfer.UnlockRefund(ctx, tx, 0, inputValues[0],
			agentTransferLockingScript, agentUnlockingScript)
		if err != nil {
			return fmt.Errorf("Failed to create agent transfer refund unlocking script : %s", err)
		}
		tx.TxIn[0].UnlockingScript = unlockingScript
	} else { // recover
		unlockingScript, err := agent_bitcoin_transfer.UnlockRecover(ctx, tx, 0, inputValues[0],
			agentTransferLockingScript, recoverUnlockingScript)
		if err != nil {
			return fmt.Errorf("Failed to create agent transfer recover unlocking script : %s", err)
		}
		tx.TxIn[0].UnlockingScript = unlockingScript
	}

	// Sign funding inputs
	for i, txin := range tx.TxIn[1:] {
		inputIndex := i + 1
		sigHash, err := bitcoin_interpreter.SignatureHash(tx, inputIndex, lockingScript, -1,
			inputValues[inputIndex], bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll,
			hashCache)
		if err != nil {
			return fmt.Errorf("Failed to create sig hash : %s", err)
		}

		signature, err := config.Key.Sign(sigHash)
		if err != nil {
			return fmt.Errorf("Failed to create signature : %s", err)
		}

		txin.UnlockingScript = bitcoin.ConcatScript(
			bitcoin.PushData(append(signature.Bytes(),
				byte(bitcoin_interpreter.SigHashForkID|bitcoin_interpreter.SigHashAll))),
			bitcoin.PushData(config.Key.PublicKey().Bytes()),
		)
	}

	buf := &bytes.Buffer{}
	if err := tx.Serialize(buf); err != nil {
		return fmt.Errorf("Failed to serialize tx : %s", err)
	}

	fmt.Printf("Tx : %s\n", tx.String())
	size := tx.SerializeSize()
	fee := inputValue - outputValue
	fmt.Printf("Input value : %d\n", inputValue)
	fmt.Printf("Output value : %d\n", outputValue)

	feeRate := float32(fee) / float32(size)
	fmt.Printf("Fee : %d (%0.5f sat/byte)\n", fee, feeRate)

	fmt.Printf("Tx Hex (%d bytes) : %x\n", size, buf.Bytes())
	return nil
}
