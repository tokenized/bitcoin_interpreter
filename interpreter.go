package bitcoin_interpreter

import (
	"bytes"
	"encoding/hex"
	"math"
	"math/big"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"
	"github.com/tokenized/txbuilder"

	"github.com/pkg/errors"
)

var (
	ErrStackEmpty            = errors.New("Stack Empty")
	ErrAltStackEmpty         = errors.New("Alt Stack Empty")
	ErrScriptInvalid         = errors.New("Script Invalid")
	ErrVerifyFailed          = errors.New("Verify Failed")
	ErrSignatureDidNotVerify = errors.New("Signature Did Not Verify")
	ErrNotUnlocked           = errors.New("Not Unlocked")
	ErrOpCodeDisabled        = errors.New("Op Code Disabled")
	ErrNoOpCode              = errors.New("No Op Code")
	ErrBadOpCode             = errors.New("Bad Op Code")
	ErrNotImplemented        = errors.New("Not Implemented")
)

type Interpreter struct {
	stack              [][]byte
	altStack           [][]byte
	ifStack            []*ifStackItem
	scriptVerifyFailed bool // a verify op code found a zero
	err                error
}

type ifStackItem struct {
	execute   bool
	elseFound bool
}

func NewInterpreter() *Interpreter {
	return &Interpreter{}
}

func (i *Interpreter) Execute(script bitcoin.Script, tx *wire.MsgTx, inputIndex int,
	inputValue uint64, hashCache *txbuilder.SigHashCache) error {

	scriptBuf := bytes.NewReader(script)
	codeScript := script
	itemIndex := -1
	sigIndex := 0
	for scriptBuf.Len() > 0 {
		itemIndex++
		item, err := bitcoin.ParseScript(scriptBuf)
		if err != nil {
			return errors.Wrapf(err, "parse item: %d", itemIndex)
		}

		if !i.ifIsExecute() {
			if item.Type == bitcoin.ScriptItemTypePushData {
				if !isMinimalPush(item.OpCode, item.Data) {
					return errors.Wrapf(ErrScriptInvalid, "not minimal push: %s", item)
				}

				continue // don't push the item onto the stack
			}

			switch item.OpCode {
			case bitcoin.OP_IF:
				i.ifStack = append(i.ifStack, &ifStackItem{})

			case bitcoin.OP_NOTIF:
				i.ifStack = append(i.ifStack, &ifStackItem{})

			case bitcoin.OP_ELSE:
				l := len(i.ifStack)
				if l == 0 {
					return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
				}

				lastIfItem := i.ifStack[l-1]
				if lastIfItem.elseFound {
					return errors.Wrap(ErrScriptInvalid, "more than one OP_ELSE")
				}
				lastIfItem.elseFound = true

			case bitcoin.OP_ENDIF:
				l := len(i.ifStack)
				if l == 0 {
					return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
				}

				i.ifStack = i.ifStack[:l-1]
			}
			continue
		}

		if item.Type == bitcoin.ScriptItemTypePushData {
			if !isMinimalPush(item.OpCode, item.Data) {
				return errors.Wrapf(ErrScriptInvalid, "not minimal push: %s", item)
			}

			i.pushStack(item.Data)
			continue
		}

		if item.Type != bitcoin.ScriptItemTypeOpCode {
			return errors.Wrapf(bitcoin.ErrInvalidScriptItemType, "%d", item.Type)
		}

		switch item.OpCode {
		case bitcoin.OP_0: // OP_FALSE
			i.pushStack(encodePrimitiveInteger(0))
		case bitcoin.OP_1: // OP_TRUE
			i.pushStack(encodePrimitiveInteger(1))
		case bitcoin.OP_2:
			i.pushStack(encodePrimitiveInteger(2))
		case bitcoin.OP_3:
			i.pushStack(encodePrimitiveInteger(3))
		case bitcoin.OP_4:
			i.pushStack(encodePrimitiveInteger(4))
		case bitcoin.OP_5:
			i.pushStack(encodePrimitiveInteger(5))
		case bitcoin.OP_6:
			i.pushStack(encodePrimitiveInteger(6))
		case bitcoin.OP_7:
			i.pushStack(encodePrimitiveInteger(7))
		case bitcoin.OP_8:
			i.pushStack(encodePrimitiveInteger(8))
		case bitcoin.OP_9:
			i.pushStack(encodePrimitiveInteger(9))
		case bitcoin.OP_10:
			i.pushStack(encodePrimitiveInteger(10))
		case bitcoin.OP_11:
			i.pushStack(encodePrimitiveInteger(11))
		case bitcoin.OP_12:
			i.pushStack(encodePrimitiveInteger(12))
		case bitcoin.OP_13:
			i.pushStack(encodePrimitiveInteger(13))
		case bitcoin.OP_14:
			i.pushStack(encodePrimitiveInteger(14))
		case bitcoin.OP_15:
			i.pushStack(encodePrimitiveInteger(15))
		case bitcoin.OP_16:
			i.pushStack(encodePrimitiveInteger(16))

		case bitcoin.OP_1NEGATE:
			i.pushStack(encodePrimitiveInteger(-1))

		case bitcoin.OP_NOP: // Do nothing

		case bitcoin.OP_IF:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.ifStack = append(i.ifStack, &ifStackItem{
				execute:   isTrue(b),
				elseFound: false,
			})

		case bitcoin.OP_NOTIF:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.ifStack = append(i.ifStack, &ifStackItem{
				execute:   !isTrue(b),
				elseFound: false,
			})

		case bitcoin.OP_ELSE:
			l := len(i.ifStack)
			if l == 0 {
				return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
			}

			lastIfItem := i.ifStack[l-1]
			if lastIfItem.elseFound {
				return errors.Wrap(ErrScriptInvalid, "more than one OP_ELSE")
			}
			lastIfItem.elseFound = true
			lastIfItem.execute = !lastIfItem.execute

		case bitcoin.OP_ENDIF:
			l := len(i.ifStack)
			if l == 0 {
				return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
			}

			i.ifStack = i.ifStack[:l-1]

		case bitcoin.OP_VERIFY:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if !isTrue(b) {
				i.err = errors.Wrapf(ErrVerifyFailed, "op code: %s", item)
				i.scriptVerifyFailed = true
				return nil
			}

		case bitcoin.OP_RETURN:
			return nil

		case bitcoin.OP_TOALTSTACK:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushAltStack(b)

		case bitcoin.OP_FROMALTSTACK:
			b, err := i.popAltStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b)

		case bitcoin.OP_2DROP:
			if _, err := i.popStack(); err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if _, err := i.popStack(); err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

		case bitcoin.OP_2DUP:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(copyBytes(b2))
			i.pushStack(copyBytes(b1))
			i.pushStack(b2)
			i.pushStack(b1)

		case bitcoin.OP_3DUP:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(copyBytes(b3))
			i.pushStack(copyBytes(b2))
			i.pushStack(copyBytes(b1))
			i.pushStack(b3)
			i.pushStack(b2)
			i.pushStack(b1)

		case bitcoin.OP_2OVER:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b4, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(copyBytes(b2))
			i.pushStack(copyBytes(b1))
			i.pushStack(b4)
			i.pushStack(b3)
			i.pushStack(b2)
			i.pushStack(b1)

		case bitcoin.OP_2ROT:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b4, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b5, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b6, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b2)
			i.pushStack(b1)
			i.pushStack(b6)
			i.pushStack(b5)
			i.pushStack(b4)
			i.pushStack(b3)

		case bitcoin.OP_2SWAP:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b4, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b2)
			i.pushStack(b1)
			i.pushStack(b4)
			i.pushStack(b3)

		case bitcoin.OP_IFDUP:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b)

			if isTrue(b) {
				i.pushStack(copyBytes(b))
			}

		case bitcoin.OP_DEPTH:
			stackSize := len(i.stack)
			i.pushStack(encodePrimitiveInteger(stackSize))

		case bitcoin.OP_DROP:
			if _, err := i.popStack(); err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

		case bitcoin.OP_DUP:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b)
			i.pushStack(copyBytes(b))

		case bitcoin.OP_NIP:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if _, err := i.popStack(); err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b)

		case bitcoin.OP_OVER:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b1)
			i.pushStack(b2)
			i.pushStack(copyBytes(b1))

		case bitcoin.OP_PICK:
			n, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			c := decodeInteger(n)
			if !c.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
			}
			count := c.Int64()

			if count < 0 {
				return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
			}

			if count >= int64(len(i.stack)) {
				return errors.Wrapf(ErrScriptInvalid, "count more than stack depth: %s", item)
			}

			values := make([][]byte, count)
			for j := range values {
				b, err := i.popStack()
				if err != nil {
					return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
				}

				values[j] = b
			}

			for j := int(count) - 1; j >= 0; j-- {
				i.pushStack(values[j])
			}

			i.pushStack(copyBytes(values[count-1]))

		case bitcoin.OP_ROLL:
			n, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			c := decodeInteger(n)
			if !c.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
			}
			count := c.Int64()

			if count < 0 {
				return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
			}

			if count >= int64(len(i.stack)) {
				return errors.Wrapf(ErrScriptInvalid, "count more than stack depth: %s", item)
			}

			values := make([][]byte, count)
			for j := range values {
				b, err := i.popStack()
				if err != nil {
					return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
				}

				values[j] = b
			}

			for j := int(count) - 2; j >= 0; j-- {
				i.pushStack(values[j])
			}

			i.pushStack(values[count-1])

		case bitcoin.OP_ROT:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b1)
			i.pushStack(b3)
			i.pushStack(b2)

		case bitcoin.OP_SWAP:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b1)
			i.pushStack(b2)

		case bitcoin.OP_TUCK:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(b1)
			i.pushStack(b2)
			i.pushStack(copyBytes(b1))

		case bitcoin.OP_CAT:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(append(b1, b2...))

		case bitcoin.OP_SPLIT:
			n, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			c := decodeInteger(n)
			if !c.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
			}
			count := c.Int64()

			if count < 0 {
				return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
			}

			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if count > int64(len(b)) {
				return errors.Wrapf(ErrScriptInvalid,
					"count more than value size: %s: count: %d, size %d", item, count, len(b))
			}

			i.pushStack(copyBytes(b[:count]))
			i.pushStack(copyBytes(b[count:]))

		case bitcoin.OP_NUM2BIN:
			n, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			c := decodeInteger(n)
			if !c.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
			}
			count := c.Int64()

			if count < 0 {
				return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
			}

			if count > int64(math.MaxUint32) {
				return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
			}

			v, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			// Minimally encode number
			b := encodeInteger(decodeInteger(v))
			if count < int64(len(b)) {
				return errors.Wrapf(ErrScriptInvalid,
					"value size greater than count: %s: count %d, size %d", item, count, len(b))
			}

			b = padNumber(b, int(count))
			i.pushStack(b)

		case bitcoin.OP_BIN2NUM:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b = encodeInteger(decodeInteger(b))
			i.pushStack(b)

		case bitcoin.OP_SIZE:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(encodePrimitiveInteger(len(b1)))
			i.pushStack(b1)

		case bitcoin.OP_EQUAL:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) == 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_EQUALVERIFY:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) != 0 {
				i.err = errors.Wrapf(ErrVerifyFailed, "op code: %s", item)
				i.scriptVerifyFailed = true
				return nil
			}

		case bitcoin.OP_1ADD:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n := decodeInteger(b)

			i.pushStack(encodeInteger(n.Add(n, big.NewInt(1))))

		case bitcoin.OP_2MUL:
			return errors.Wrapf(ErrOpCodeDisabled, "op code: %s", item)

		case bitcoin.OP_2DIV:
			return errors.Wrapf(ErrOpCodeDisabled, "op code: %s", item)

		case bitcoin.OP_NEGATE:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n := decodeInteger(b)

			i.pushStack(encodeInteger(n.Neg(n)))

		case bitcoin.OP_ABS:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n := decodeInteger(b)

			i.pushStack(encodeInteger(n.Abs(n)))

		case bitcoin.OP_NOT:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n := decodeInteger(b)

			if n.Cmp(big.NewInt(0)) == 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_0NOTEQUAL:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n := decodeInteger(b)

			if n.Cmp(big.NewInt(0)) != 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_ADD:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			i.pushStack(encodeInteger(n1.Add(n1, n2)))

		case bitcoin.OP_SUB:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			i.pushStack(encodeInteger(n1.Sub(n1, n2)))

		case bitcoin.OP_MUL:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			i.pushStack(encodeInteger(n1.Mul(n1, n2)))

		case bitcoin.OP_DIV:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n2.Cmp(big.NewInt(0)) == 0 {
				return errors.Wrapf(ErrScriptInvalid, "divide by zero: %s", item)
			}

			i.pushStack(encodeInteger(n1.Div(n1, n2)))

		case bitcoin.OP_MOD:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n2.Cmp(big.NewInt(0)) == 0 {
				return errors.Wrapf(ErrScriptInvalid, "divide by zero: %s", item)
			}

			i.pushStack(encodeInteger(n1.Mod(n1, n2)))

		case bitcoin.OP_LSHIFT:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if !n2.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "shift count not int 64: %s", item)
			}

			n64 := n2.Int64()
			if n64 > math.MaxUint32 {
				return errors.Wrapf(ErrScriptInvalid, "shift count over 32 bits: %s", item)
			}

			i.pushStack(encodeInteger(n1.Lsh(n1, uint(n64))))

		case bitcoin.OP_RSHIFT:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if !n2.IsInt64() {
				return errors.Wrapf(ErrScriptInvalid, "shift count not int 64: %s", item)
			}

			n64 := n2.Int64()
			if n64 > math.MaxUint32 {
				return errors.Wrapf(ErrScriptInvalid, "shift count over 32 bits: %s", item)
			}

			i.pushStack(encodeInteger(n1.Rsh(n1, uint(n64))))

		case bitcoin.OP_BOOLAND:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			zero := big.NewInt(0)
			if n1.Cmp(zero) != 0 && n2.Cmp(zero) != 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_BOOLOR:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			zero := big.NewInt(0)
			if n1.Cmp(zero) != 0 || n2.Cmp(zero) != 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_NUMEQUAL:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) == 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_NUMEQUALVERIFY:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) != 0 {
				i.err = errors.Wrapf(ErrVerifyFailed, "op code: %s", item)
				i.scriptVerifyFailed = true
				return nil
			}

		case bitcoin.OP_NUMNOTEQUAL:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) != 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_MIN:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) < 0 {
				i.pushStack(encodeInteger(n1))
			} else {
				i.pushStack(encodeInteger(n2))
			}

		case bitcoin.OP_MAX:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			if n1.Cmp(n2) > 0 {
				i.pushStack(encodeInteger(n1))
			} else {
				i.pushStack(encodeInteger(n2))
			}

		case bitcoin.OP_WITHIN:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			b3, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n3 := decodeInteger(b3)

			if n2.Cmp(n1) <= 0 && n3.Cmp(n1) >= 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_LESSTHAN, bitcoin.OP_GREATERTHAN, bitcoin.OP_LESSTHANOREQUAL,
			bitcoin.OP_GREATERTHANOREQUAL:

			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n1 := decodeInteger(b1)

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}
			n2 := decodeInteger(b2)

			switch item.OpCode {
			case bitcoin.OP_LESSTHAN:
				if n1.Cmp(n2) < 0 {
					i.pushStack(encodePrimitiveInteger(1))
				} else {
					i.pushStack(encodePrimitiveInteger(0))
				}

			case bitcoin.OP_GREATERTHAN:
				if n1.Cmp(n2) > 0 {
					i.pushStack(encodePrimitiveInteger(1))
				} else {
					i.pushStack(encodePrimitiveInteger(0))
				}

			case bitcoin.OP_LESSTHANOREQUAL:
				if n1.Cmp(n2) <= 0 {
					i.pushStack(encodePrimitiveInteger(1))
				} else {
					i.pushStack(encodePrimitiveInteger(0))
				}

			case bitcoin.OP_GREATERTHANOREQUAL:
				if n1.Cmp(n2) >= 0 {
					i.pushStack(encodePrimitiveInteger(1))
				} else {
					i.pushStack(encodePrimitiveInteger(0))
				}
			}

		case bitcoin.OP_RIPEMD160:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(bitcoin.Ripemd160(b))

		case bitcoin.OP_SHA1:
			return errors.Wrapf(ErrNotImplemented, "op code: %s", item)

		case bitcoin.OP_SHA256:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(bitcoin.Sha256(b))

		case bitcoin.OP_HASH160:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(bitcoin.Hash160(b))

		case bitcoin.OP_HASH256:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			i.pushStack(bitcoin.DoubleSha256(b))

		case bitcoin.OP_CODESEPARATOR:
			l := len(codeScript)
			codeScript = codeScript[l-scriptBuf.Len():]

		case bitcoin.OP_CHECKSIG, bitcoin.OP_CHECKSIGVERIFY:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2Len := len(b2)
			if b2Len < 2 {
				return errors.Wrapf(ErrScriptInvalid, "invalid signature: too short %d", b2Len)
			}

			hashType := txbuilder.SigHashType(b2[b2Len-1])
			signature, err := bitcoin.SignatureFromBytes(b2[:b2Len-1])
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "invalid signature: %s", err)
			}

			publicKey, err := bitcoin.PublicKeyFromBytes(b1)
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "invalid public key: %s", err)
			}

			sigHash, err := txbuilder.SignatureHash(tx, inputIndex, codeScript, inputValue,
				hashType, hashCache)
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "calculate sig hash: %s", err)
			}

			verified := signature.Verify(*sigHash, publicKey)

			switch item.OpCode {
			case bitcoin.OP_CHECKSIG:
				if verified {
					i.pushStack(encodePrimitiveInteger(1))
				} else {
					i.pushStack(encodePrimitiveInteger(0))
				}

			case bitcoin.OP_CHECKSIGVERIFY:
				if !verified {
					i.err = errors.Wrapf(ErrVerifyFailed, "op code: %s (sig index %d)", item,
						sigIndex)
					i.scriptVerifyFailed = true
					return nil
				}
			}

			sigIndex++

		case bitcoin.OP_CHECKMULTISIG:
			return errors.Wrapf(ErrNotImplemented, "op code: %s", item)
		case bitcoin.OP_CHECKMULTISIGVERIFY:
			return errors.Wrapf(ErrNotImplemented, "op code: %s", item)

		case bitcoin.OP_INVERT:
			b, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			for i, bt := range b {
				b[i] = -bt
			}
			i.pushStack(b)

		// Bitwise logical operators
		case bitcoin.OP_AND:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if len(b1) != len(b2) {
				return errors.Wrapf(ErrScriptInvalid, "sizes don't match: %s", item)
			}

			for i, bt := range b2 {
				b1[i] &= bt
			}
			i.pushStack(b1)

		case bitcoin.OP_OR:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if len(b1) != len(b2) {
				return errors.Wrapf(ErrScriptInvalid, "sizes don't match: %s", item)
			}

			for i, bt := range b2 {
				b1[i] |= bt
			}
			i.pushStack(b1)

		case bitcoin.OP_XOR:
			b1, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			b2, err := i.popStack()
			if err != nil {
				return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
			}

			if len(b1) != len(b2) {
				return errors.Wrapf(ErrScriptInvalid, "sizes don't match: %s", item)
			}

			for i, bt := range b2 {
				b1[i] ^= bt
			}
			i.pushStack(b1)

		case bitcoin.OP_NOP1, bitcoin.OP_NOP2, bitcoin.OP_NOP3, bitcoin.OP_NOP4, bitcoin.OP_NOP5,
			bitcoin.OP_NOP6, bitcoin.OP_NOP7, bitcoin.OP_NOP8, bitcoin.OP_NOP9, bitcoin.OP_NOP10:
			return errors.Wrapf(ErrNoOpCode, "op code: %s", item)

		case bitcoin.OP_VER, bitcoin.OP_VERIF, bitcoin.OP_VERNOTIF:
			return errors.Wrapf(ErrBadOpCode, "op code: %s", item)

		default:
			return errors.Wrapf(ErrBadOpCode, "op code: %s", item)
		}
	}

	return nil
}

func (i *Interpreter) IsUnlocked() bool {
	if i.scriptVerifyFailed {
		return false
	}

	stackLen := len(i.stack)
	if stackLen == 0 {
		return false
	}

	return isTrue(i.stack[stackLen-1])
}

func (i *Interpreter) VerifyFailed() bool {
	return i.scriptVerifyFailed
}

func (i *Interpreter) Error() error {
	if i.scriptVerifyFailed {
		return i.err
	}

	stackLen := len(i.stack)
	if stackLen == 0 {
		return errors.Wrap(ErrNotUnlocked, "stack empty")
	}

	if isTrue(i.stack[stackLen-1]) {
		return nil
	}

	return errors.Wrapf(ErrNotUnlocked, "final stack item: 0x%x",
		hex.EncodeToString(i.stack[stackLen-1]))
}

// ifIsExecute returns true if the current state of the if stack specifies that the current op code
// should be executed.
func (i *Interpreter) ifIsExecute() bool {
	l := len(i.ifStack)
	if l == 0 {
		return true
	}

	return i.ifStack[l-1].execute
}

func (i *Interpreter) pushStack(b []byte) {
	i.stack = append(i.stack, b)
}

func (i *Interpreter) popStack() ([]byte, error) {
	if len(i.stack) == 0 {
		return nil, ErrStackEmpty
	}

	stackLen := len(i.stack)
	b := i.stack[stackLen-1]
	i.stack = i.stack[:stackLen-1]
	return b, nil
}

func (i *Interpreter) pushAltStack(b []byte) {
	i.altStack = append(i.altStack, b)
}

func (i *Interpreter) popAltStack() ([]byte, error) {
	if len(i.altStack) == 0 {
		return nil, ErrAltStackEmpty
	}

	stackLen := len(i.altStack)
	b := i.altStack[stackLen-1]
	i.altStack = i.altStack[:stackLen-1]
	return b, nil
}

func isTrue(b []byte) bool {
	i := decodeInteger(b)
	return i.Cmp(big.NewInt(0)) != 0
}

func encodePrimitiveInteger(value int) []byte {
	// Encode to little endian.  The maximum number of encoded bytes is 9
	// (8 bytes for max int64 plus a potential byte for sign extension).
	result := make([]byte, 0, 10)
	for value > 0 {
		result = append(result, byte(value&0xff))
		value >>= 8
	}

	if len(result) == 0 {
		// zero value
		result = append(result, 0)
		return result
	}

	// When the most significant byte already has the high bit set, an
	// additional high byte is required to indicate whether the number is
	// negative or positive.  The additional byte is removed when converting
	// back to an integral and its high bit is used to denote the sign.
	//
	// Otherwise, when the most significant byte does not already have the
	// high bit set, use it to indicate the value is negative, if needed.
	if result[len(result)-1]&0x80 != 0 {
		extraByte := byte(0x00)
		result = append(result, extraByte)
	}

	return result
}

func encodeInteger(value *big.Int) []byte {
	// Encode to little endian.  The maximum number of encoded bytes is 9
	// (8 bytes for max int64 plus a potential byte for sign extension).
	result := make([]byte, 0, 10)
	zero := big.NewInt(0)
	for value.Cmp(zero) > 0 {
		// result = append(result, byte(value&0xff))
		// value >>= 8
		lastByte := big.NewInt(0xff)
		lastByte.And(value, lastByte)
		value.Rsh(value, 8)
		result = append(result, byte(lastByte.Int64()))
	}

	if len(result) == 0 {
		// zero value
		result = append(result, 0)
		return result
	}

	// When the most significant byte already has the high bit set, an
	// additional high byte is required to indicate whether the number is
	// negative or positive.  The additional byte is removed when converting
	// back to an integral and its high bit is used to denote the sign.
	//
	// Otherwise, when the most significant byte does not already have the
	// high bit set, use it to indicate the value is negative, if needed.
	if result[len(result)-1]&0x80 != 0 {
		extraByte := byte(0x00)
		result = append(result, extraByte)
	}

	return result
}

func padNumber(b []byte, n int) []byte {
	l := len(b)
	if l == 0 {
		return make([]byte, n)
	}

	if l == n {
		return b
	}

	result := make([]byte, n)
	copy(result, b)

	last := b[l-1]
	if last&0x80 != 0 {
		result[l-1] &= 0x7f
		result[n-1] = 0x80
	}

	return result
}

func decodeInteger(b []byte) *big.Int {
	result := &big.Int{}
	for i, val := range b {
		// result |= int64(val) << uint8(8*i)
		v := big.NewInt(int64(val))
		s := uint(8 * i)
		l := v.Lsh(v, s)
		result.Or(result, l)
	}

	// When the most significant byte of the input bytes has the sign bit set, the result is
	// negative.  So, remove the sign bit from the result and make it negative.
	if b[len(b)-1]&0x80 != 0 {
		// The maximum length of v has already been determined to be 4 above, so uint8 is enough to
		// cover the max possible shift value of 24.
		// result &= ^(int64(0x80) << uint8(8*(len(b)-1)))
		// result = -result
		v := big.NewInt(int64(0x80))
		s := uint(8 * (len(b) - 1))
		l := v.Lsh(v, s)
		l.Not(l)
		result.And(result, l)
		result.Neg(result)
	}

	return result
}

func copyBytes(b []byte) []byte {
	r := make([]byte, len(b))
	copy(r, b)
	return r
}

func isMinimalPush(opCode byte, b []byte) bool {
	l := len(b)

	if l == 0 {
		return false // Should be OP_0
	}
	if l == 1 && b[0] >= 1 && b[0] <= 16 {
		return false // Should be OP_1 through OP_16
	}
	if l == 1 && b[0] == 0x81 {
		return false // Should be OP_1NEGATE
	}

	if l <= 75 {
		return int(opCode) == l // Should be single byte push data
	}
	if l <= 255 {
		return opCode == bitcoin.OP_PUSH_DATA_1 // Should be OP_PUSH_DATA_1
	}
	if l <= 65535 {
		return opCode == bitcoin.OP_PUSH_DATA_2 // Should be OP_PUSH_DATA_2
	}

	return true
}
