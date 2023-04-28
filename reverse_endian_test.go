package bitcoin_interpreter

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/txbuilder"
)

func Test_Script_ReverseEndian32(t *testing.T) {
	lockingScript, err := bitcoin.StringToScript(Script_ReverseEndian32)
	if err != nil {
		t.Fatalf("Failed to get locking script : %s", err)
	}

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
			result: "d013ec695b3de407296cfbe574d5be5b2ff1161d43b7201c197b997cf57538c600",
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

			interpreter := NewInterpreter()
			hashCache := &txbuilder.SigHashCache{}

			if err := interpreter.Execute(unlockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(lockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			t.Logf("Final Stack (%d items):\n%s", len(interpreter.stack), interpreter.StackString())

			result, err := hex.DecodeString(tt.result)
			if err != nil {
				t.Fatalf("Failed to decode result hex : %s", err)
			}

			if len(interpreter.stack) != 1 {
				t.Fatalf("Wrong stack size : got %d, want %d", len(interpreter.stack), 1)
			}
			final := interpreter.stack[0]

			if !bytes.Equal(final, result) {
				t.Fatalf("Wrong final stack value : got %x, want %x", final, result)
			}
		})
	}
}

func Test_Script_ReverseEndian32Or33(t *testing.T) {
	lockingScript, err := bitcoin.StringToScript(Script_ReverseEndian32Or33)
	if err != nil {
		t.Fatalf("Failed to get locking script : %s", err)
	}

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
			input:  "c63875f57c997b191c20b7431d16f12f5bbed574e5fb6c2907e43d5b69ec13d000",
			result: "00d013ec695b3de407296cfbe574d5be5b2ff1161d43b7201c197b997cf57538c6",
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

			interpreter := NewInterpreter()
			hashCache := &txbuilder.SigHashCache{}

			if err := interpreter.Execute(unlockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret unlocking script : %s", err)
			}

			if err := interpreter.Execute(lockingScript, nil, 0, 0, hashCache); err != nil {
				t.Fatalf("Failed to interpret locking script : %s", err)
			}

			t.Logf("Final Stack (%d items):\n%s", len(interpreter.stack), interpreter.StackString())

			result, err := hex.DecodeString(tt.result)
			if err != nil {
				t.Fatalf("Failed to decode result hex : %s", err)
			}

			if len(interpreter.stack) != 1 {
				t.Fatalf("Wrong stack size : got %d, want %d", len(interpreter.stack), 1)
			}
			final := interpreter.stack[0]

			if !bytes.Equal(final, result) {
				t.Fatalf("Wrong final stack value : got %x, want %x", final, result)
			}
		})
	}
}
