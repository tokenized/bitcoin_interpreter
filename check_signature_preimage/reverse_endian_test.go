package check_signature_preimage

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/tokenized/bitcoin_interpreter"
	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/txbuilder"
)

func Test_Script_ReverseEndian32(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")
	lockingScript := Script_ReverseEndian32

	t.Logf("Script : %s", lockingScript)

	tests := []struct {
		name   string
		input  string
		result string
	}{
		{
			name:   "random",
			input:  "563875f57c997b191c20b7431d16f12f5bbed574e5fb6c2907e43d5b69ec13d0",
			result: "d013ec695b3de407296cfbe574d5be5b2ff1161d43b7201c197b997cf5753856",
		},
		{
			name:   "high bit",
			input:  "c63875f57c997b191c20b7431d16f12f5bbed574e5fb6c2907e43d5b69ec13d0",
			result: "d013ec695b3de407296cfbe574d5be5b2ff1161d43b7201c197b997cf57538c6",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("Failed to decode input hex : %s", err)
			}

			unlockingScriptItems := bitcoin.ScriptItems{bitcoin.NewPushDataScriptItem(input)}
			unlockingScript, err := unlockingScriptItems.Script()
			if err != nil {
				t.Fatalf("Failed to create unlocking script : %s", err)
			}

			interpreter := bitcoin_interpreter.NewInterpreter()
			hashCache := &txbuilder.SigHashCache{}

			if err := interpreter.Execute(ctx, unlockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(ctx, lockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			stack := interpreter.StackItems()
			t.Logf("Final Stack (%d items):\n%s", len(stack), interpreter.StackString())

			result, err := hex.DecodeString(tt.result)
			if err != nil {
				t.Fatalf("Failed to decode result hex : %s", err)
			}

			if len(stack) != 1 {
				t.Fatalf("Wrong stack size : got %d, want %d", len(stack), 1)
			}
			final := stack[0]

			if !bytes.Equal(final, result) {
				t.Fatalf("Wrong final stack value : got %x, want %x", final, result)
			}
		})
	}
}
