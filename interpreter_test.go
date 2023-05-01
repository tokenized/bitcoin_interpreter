package bitcoin_interpreter

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

func Test_Execute_Hex(t *testing.T) {
	ctx := logger.ContextWithLogger(context.Background(), true, false, "")

	tests := []struct {
		name          string
		lockingScript string
		txHex         string
		inputIndex    int
		inputValue    uint64
		isUnlocked    bool
		baseErr       error
	}{
		{
			name:          "PKH, 1 input",
			lockingScript: "OP_DUP OP_HASH160 0xb2bb65cbe4cc57576bfe8d9732100e9bf7f6e281 OP_EQUALVERIFY OP_CHECKSIG",
			txHex:         "010000000152fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649080000006b483045022100ed7b441fba044a88fe08fd5c67a97e518918284e3c92a3b8fb8754d0a94e23a502204495d7acfb36753974d657ba8f1a4ab15cd77c0000494b4d55a0bb63da49bbff4121032d33cef40a82cebf645f3910ce97c2544c8d3d2cd05939d256fdaf2be9c815caffffffff017e130000000000001976a91450b5f8b1a62782be8f43a22940e58c109b1355af88ac00000000",
			inputIndex:    0,
			inputValue:    5000,
			isUnlocked:    true,
		},
		{
			name:          "PKH, 2 inputs, first input",
			lockingScript: "OP_DUP OP_HASH160 0x6d94a857c8d5a58e8294166aded5d6c0a7e06737 OP_EQUALVERIFY OP_CHECKSIG",
			txHex:         "010000000252fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649080000006b483045022100b9ec36beb386e289810775019a0d2a0337774231aabf8d2af4348b1d94d7a9bd02206944a80d0ed0cb186d859b408087396a3450fdc1e7b8656fc210e89b04e7322c41210252b68e28ca54f5913b8380e32d5a666f2b1335cba797576cf04b956bc5e13219ffffffff81855a1e00167939cb6694d2c422acd208a0072939487f6999eb9d18a4478404010000006a473044022039baf4f3a4cd878d9542b863e730aadde853cf8248cabfa14003289c6a062de202203ccbe199f3230f0e16f26b45ad919653b180b100cc64eba0acd77f251d19ac834121024279ab2c70f2dd86bccac643959f55dc1eaa39c9ea24402f48d75f0d661ae48effffffff01e62a0000000000001976a914cde2d1a5dc71b682128b8e887025217a10d4173988ac00000000",
			inputIndex:    0,
			inputValue:    5000,
			isUnlocked:    true,
		},
		{
			name:          "PKH, 2 inputs, second input",
			lockingScript: "OP_DUP OP_HASH160 0x653ba1b07b927479e0daa248cea931d6c6d2c8d9 OP_EQUALVERIFY OP_CHECKSIG",
			txHex:         "010000000252fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c649080000006b483045022100b9ec36beb386e289810775019a0d2a0337774231aabf8d2af4348b1d94d7a9bd02206944a80d0ed0cb186d859b408087396a3450fdc1e7b8656fc210e89b04e7322c41210252b68e28ca54f5913b8380e32d5a666f2b1335cba797576cf04b956bc5e13219ffffffff81855a1e00167939cb6694d2c422acd208a0072939487f6999eb9d18a4478404010000006a473044022039baf4f3a4cd878d9542b863e730aadde853cf8248cabfa14003289c6a062de202203ccbe199f3230f0e16f26b45ad919653b180b100cc64eba0acd77f251d19ac834121024279ab2c70f2dd86bccac643959f55dc1eaa39c9ea24402f48d75f0d661ae48effffffff01e62a0000000000001976a914cde2d1a5dc71b682128b8e887025217a10d4173988ac00000000",
			inputIndex:    1,
			inputValue:    6000,
			isUnlocked:    true,
		},
		{
			name:          "MultiPKH 2 of 3, 1 input",
			lockingScript: "OP_0 OP_TOALTSTACK OP_IF OP_DUP OP_HASH160 0x9644d900d45516005343003213a161f264be2a5b OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0xd864e6e4169f38021aa73a910c5f1e670f6bfcd1 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0x408a48bf23d9acee0d95ba4ad58b458d70d484b8 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_2 OP_FROMALTSTACK OP_LESSTHANOREQUAL",
			txHex:         "010000000152fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c64908000000d80048304502210085f6bc4cd03fb7442b321a90347581ca897087104826b3f467266c4635b8b9f50220534af27b295f1bd0c43bd3dfee0da6cec4bbea73b1a3c23dc726e0808574422f412103079ba5bc55c0024f87670fa4f337e40a93f9a6451bb47fcf96ac981f76c3a7c8514730440220527655d788cf77019dc88e98de8c6224ae90456cdba55c8316690fc3695cdf17022012e886948d6b2f57759c7718ff1fa3aba94413d293fc52eb485293a5e84cbce2412102c1e15519c26df4c9a12805bc7211ac4826e2c4f0a2846a95d4e77c13a3e1b80351ffffffff0178130000000000001976a9146493e518399677c9d97d9c37e3c55624ec5e0e6f88ac00000000",
			inputIndex:    0,
			inputValue:    5000,
			isUnlocked:    true,
		},
		{
			name:          "MultiPKH 2 of 3, 1 input, wrong unlock order",
			lockingScript: "OP_0 OP_TOALTSTACK OP_IF OP_DUP OP_HASH160 0xe3992a17cc2d9f5a2c0bb1948b5765532ac18e25 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0xb809e970a46b91ab5c467489ca598f59dd130ac3 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_IF OP_DUP OP_HASH160 0x6966705863fae094ac8bf8c202b8a1ee84b5c6b0 OP_EQUALVERIFY OP_CHECKSIGVERIFY OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK OP_ENDIF OP_2 OP_FROMALTSTACK OP_LESSTHANOREQUAL",
			txHex:         "010000000152fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c64908000000d9483045022100a2f3c515a20fec7314aaad68bb03f99826fa8cff639d901d73adf5737850227302203732dd95f0d7bef7ca53c7a4ee6bad84b03dfea36f7caf5ab8768a08f25f89ce4121023af3c8fde6a13a71d2c25e8974c33a41e2dc1b0f2c73c7f391b31dfc6249161751483045022100ad53258a4811b6cd75bf48da7d503f403027c56cec34abf52d2eb8baf52cbd0902204ddb03371f88980273cdde210ca13465e84f957ac71c3d6d6dcb6dfc4628114d41210329056868d252a7ad26127a76934dc2f764b482842e1bb64c07dce8996bba714e5100ffffffff0178130000000000001976a9148e2a7a77858c761c1a02f9fdbffb465c2c7799f688ac00000000",
			inputIndex:    0,
			inputValue:    5000,
			isUnlocked:    false,
			baseErr:       ErrVerifyFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lockingScript, err := bitcoin.StringToScript(tt.lockingScript)
			if err != nil {
				t.Fatalf("Failed to decode locking script : %s", err)
			}

			txBytes, err := hex.DecodeString(tt.txHex)
			if err != nil {
				t.Fatalf("Failed to decode tx hex : %s", err)
			}

			tx := &wire.MsgTx{}
			if err := tx.Deserialize(bytes.NewReader(txBytes)); err != nil {
				t.Fatalf("Failed to decode tx : %s", err)
			}

			hashCache := &SigHashCache{}
			interpreter := NewInterpreter()

			if err := interpreter.Execute(ctx, tx.TxIn[tt.inputIndex].UnlockingScript, tx,
				tt.inputIndex, tt.inputValue, hashCache); err != nil {
				t.Errorf("Failed to verify unlocking script : %s", err)
			}

			if err := interpreter.Execute(ctx, lockingScript, tx, tt.inputIndex, tt.inputValue,
				hashCache); err != nil {
				t.Errorf("Failed to verify locking script : %s", err)
			}

			if tt.isUnlocked {
				if !interpreter.IsUnlocked() {
					t.Errorf("Script should be unlocked : %s", interpreter.Error())
				}
			} else {
				if interpreter.IsUnlocked() {
					t.Errorf("Script should not be unlocked")
				}
			}

			if tt.baseErr != nil {
				if errors.Cause(interpreter.Error()) != tt.baseErr {
					t.Errorf("Wrong interpreter base error : got \"%s\", want \"%s\"",
						errors.Cause(interpreter.Error()), tt.baseErr)
				} else {
					t.Logf("Correct interpreter base error : %s", interpreter.Error())
				}
			} else if interpreter.Error() != nil {
				t.Errorf("Interpreter error should be nil : %s", interpreter.Error())
			}
		})
	}
}
