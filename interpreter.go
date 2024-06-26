package bitcoin_interpreter

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/tokenized/logger"
	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

var (
	ErrStackEmpty                = errors.New("Stack Empty")
	ErrAltStackEmpty             = errors.New("Alt Stack Empty")
	ErrScriptInvalid             = errors.New("Script Invalid")
	ErrVerifyFailed              = errors.New("Verify Failed")
	ErrMalformedSignature        = errors.New("Malformed Signature")
	ErrNonMinimallyEncodedNumber = errors.New("Non-Minimally Encoded Number")
	ErrNotUnlocked               = errors.New("Not Unlocked")
	ErrOpCodeDisabled            = errors.New("Op Code Disabled")
	ErrBadOpCode                 = errors.New("Bad Op Code")
	ErrNotImplemented            = errors.New("Not Implemented")
)

type Interpreter struct {
	stack              [][]byte
	altStack           [][]byte
	ifStack            []*ifStackItem
	scriptVerifyFailed bool // a verify op code found a zero
	verbose            bool
	err                error
}

type ifStackItem struct {
	execute   bool
	elseFound bool
}

func Verify(ctx context.Context, writeSigPreimage WriteSignaturePreimage,
	lockingScript, unlockingScript bitcoin.Script) error {

	interpreter := NewInterpreter()

	if err := interpreter.Execute(ctx, unlockingScript, writeSigPreimage); err != nil {
		return errors.Wrapf(err, "unlocking script")
	}

	if err := interpreter.Execute(ctx, lockingScript, writeSigPreimage); err != nil {
		return errors.Wrapf(err, "locking script")
	}

	if !interpreter.IsUnlocked() {
		return interpreter.Error()
	}

	return nil
}

func VerifyTx(ctx context.Context, tx TransactionWithOutputs) error {
	hashCache := &SigHashCache{}
	msgTx := tx.GetMsgTx()

	for inputIndex, txin := range msgTx.TxIn {
		inputOutput, err := tx.InputOutput(inputIndex)
		if err != nil {
			return errors.Wrapf(err, "input %d output", inputIndex)
		}

		interpreter := NewInterpreter()

		if err := interpreter.ExecuteTx(ctx, txin.UnlockingScript, msgTx, inputIndex,
			inputOutput.Value, hashCache); err != nil {
			return errors.Wrapf(err, "input %d unlocking script", inputIndex)
		}

		if err := interpreter.ExecuteTx(ctx, inputOutput.LockingScript, msgTx, inputIndex,
			inputOutput.Value, hashCache); err != nil {
			return errors.Wrapf(err, "input %d locking script", inputIndex)
		}

		if !interpreter.IsUnlocked() {
			return errors.Wrapf(interpreter.Error(), "input %d", inputIndex)
		}
	}

	return nil
}

func NewInterpreter() *Interpreter {
	return &Interpreter{}
}

func (i *Interpreter) SetVerbose() {
	i.verbose = true
}

func (i *Interpreter) ClearVerbose() {
	i.verbose = false
}

func (i *Interpreter) ExecuteTx(ctx context.Context, script bitcoin.Script, tx *wire.MsgTx,
	inputIndex int, inputValue uint64, hashCache *SigHashCache) error {

	writeSigPreimage := TxWriteSignaturePreimage(tx, inputIndex, inputValue, hashCache)
	return i.Execute(ctx, script, writeSigPreimage)
}

func (i *Interpreter) ExecuteTxVerbose(ctx context.Context, script bitcoin.Script,
	tx *wire.MsgTx, inputIndex int, inputValue uint64, hashCache *SigHashCache) error {

	writeSigPreimage := TxWriteSignaturePreimage(tx, inputIndex, inputValue, hashCache)
	return i.Execute(ctx, script, writeSigPreimage)
}

func (i *Interpreter) Execute(ctx context.Context, script bitcoin.Script,
	writeSigPreimage WriteSignaturePreimage) error {

	scriptBuf := bytes.NewReader(script)
	codeScript := script
	itemIndex := -1
	for scriptBuf.Len() > 0 {
		itemIndex++
		item, err := bitcoin.ParseScript(scriptBuf)
		if err != nil {
			return errors.Wrapf(err, "parse item: %d", itemIndex)
		}

		if err := i.ExecuteOpCode(ctx, item, itemIndex, scriptBuf, &codeScript,
			writeSigPreimage); err != nil {
			return errors.Wrapf(err, "execute item: %d", itemIndex)
		}

		if i.verbose {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("size", len(i.stack)),
				logger.Strings("stack", i.StackStrings()),
			}, "Stack")
		}
	}

	return nil
}

func (i *Interpreter) ExecuteOpCode(ctx context.Context, item *bitcoin.ScriptItem, itemIndex int,
	scriptBuf *bytes.Reader, codeScript *bitcoin.Script,
	writeSigPreimage WriteSignaturePreimage) error {

	if !i.ifIsExecute() {
		if i.verbose && ctx != nil {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("item_index", itemIndex),
				logger.Stringer("item", item),
			}, "Not executing")
		}

		if item.Type == bitcoin.ScriptItemTypePushData {
			if !isMinimalPush(item.OpCode, item.Data) {
				return errors.Wrapf(ErrScriptInvalid, "not minimal push: %s", item)
			}

			return nil // don't push the item onto the stack
		}

		switch item.OpCode {
		case bitcoin.OP_IF:
			if i.verbose && ctx != nil {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
					logger.Int("if_depth", len(i.ifStack)),
				}, "Not executing if statement")
			}

			i.ifStack = append(i.ifStack, &ifStackItem{})

		case bitcoin.OP_NOTIF:
			if i.verbose && ctx != nil {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
					logger.Int("if_depth", len(i.ifStack)),
				}, "Not executing \"not if\" statement")
			}

			i.ifStack = append(i.ifStack, &ifStackItem{})

		case bitcoin.OP_ELSE:
			l := len(i.ifStack)
			if l == 0 {
				return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
			}

			if i.verbose && ctx != nil {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
					logger.Int("if_depth", len(i.ifStack)),
				}, "Not executing else statement")
			}

			lastIfItem := i.ifStack[l-1]
			if lastIfItem.elseFound {
				return errors.Wrap(ErrScriptInvalid, "more than one OP_ELSE")
			}
			lastIfItem.elseFound = true

			if len(i.ifStack) == 1 || i.ifStack[l-2].execute {
				lastIfItem.execute = !lastIfItem.execute
			}

		case bitcoin.OP_ENDIF:
			l := len(i.ifStack)
			if l == 0 {
				return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
			}

			if i.verbose && ctx != nil {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
					logger.Int("if_depth", len(i.ifStack)),
				}, "Not executing end if statement")
			}

			i.ifStack = i.ifStack[:l-1]
		}

		return nil
	}

	if i.verbose && ctx != nil {
		logger.VerboseWithFields(ctx, []logger.Field{
			logger.Int("item_index", itemIndex),
			logger.Stringer("item", item),
		}, "Executing")
	}

	if item.Type == bitcoin.ScriptItemTypePushData {
		if !isMinimalPush(item.OpCode, item.Data) {
			return errors.Wrapf(ErrScriptInvalid, "not minimal push: %s", item)
		}

		i.pushStack(item.Data)
		return nil
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

		if len(b) > 1 {
			return errors.Wrapf(ErrScriptInvalid, "Not minimal if: %s", item)
		}

		execute := isTrue(b)
		if i.verbose && ctx != nil {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("item_index", itemIndex),
				logger.Int("if_depth", len(i.ifStack)),
				logger.Bool("execute", execute),
			}, "If statement")
		}
		i.ifStack = append(i.ifStack, &ifStackItem{
			execute:   execute,
			elseFound: false,
		})

	case bitcoin.OP_NOTIF:
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		if len(b) > 1 {
			return errors.Wrapf(ErrScriptInvalid, "Not minimal if: %s", item)
		}

		execute := !isTrue(b)
		if i.verbose && ctx != nil {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("item_index", itemIndex),
				logger.Int("if_depth", len(i.ifStack)),
				logger.Bool("execute", execute),
			}, "Not if statement")
		}
		i.ifStack = append(i.ifStack, &ifStackItem{
			execute:   execute,
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
		if i.verbose && ctx != nil {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("item_index", itemIndex),
				logger.Int("if_depth", len(i.ifStack)),
				logger.Bool("execute", lastIfItem.execute),
			}, "Else statement")
		}

	case bitcoin.OP_ENDIF:
		l := len(i.ifStack)
		if l == 0 {
			return errors.Wrapf(ErrScriptInvalid, "if stack empty: %s", item)
		}

		if i.verbose && ctx != nil {
			logger.VerboseWithFields(ctx, []logger.Field{
				logger.Int("item_index", itemIndex),
				logger.Int("if_depth", len(i.ifStack)),
			}, "End if statement")
		}

		i.ifStack = i.ifStack[:l-1]

	case bitcoin.OP_VERIFY:
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		if !isTrue(b) {
			if i.verbose && ctx != nil {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
				}, "Verify failed")
			}
			i.err = errors.Wrapf(ErrVerifyFailed, "op code (%d): %s", itemIndex, item)
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
		b, err := i.getStack(0, false)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		if isTrue(b) {
			i.pushStack(copyBytes(b))
		}

	case bitcoin.OP_DEPTH: // Push the number of items in the stack onto the stack
		stackSize := len(i.stack)
		i.pushStack(encodePrimitiveInteger(stackSize))

	case bitcoin.OP_DROP: // Remove the top stack item
		if _, err := i.getStack(0, true); err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

	case bitcoin.OP_DUP: // Duplicate top item on stack
		b, err := i.getStack(0, false)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(copyBytes(b))

	case bitcoin.OP_NIP: // Remove second item deep in stack
		if _, err := i.getStack(1, true); err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

	case bitcoin.OP_OVER: // Copy second stack item to the top
		b, err := i.getStack(1, false)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(copyBytes(b))

	case bitcoin.OP_PICK: // Copy item that is n deep in stack and push onto stack
		n, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}
		c, err := decodeInteger(n)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		if !c.IsInt64() {
			return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
		}
		count := c.Int64()

		if count < 0 {
			return errors.Wrapf(ErrScriptInvalid, "negative count: %s", item)
		}

		b, err := i.getStack(int(count), false)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(copyBytes(b))

	case bitcoin.OP_ROLL: // Move item n deep in stack to the top
		n, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}
		c, err := decodeInteger(n)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		if !c.IsInt64() {
			return errors.Wrapf(ErrScriptInvalid, "count more than 64 bits: %s", item)
		}
		count := c.Int64()

		if count < 0 {
			return errors.Wrapf(ErrScriptInvalid, "count not more than zero: %s", item)
		}

		b, err := i.getStack(int(count), true)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(b)

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

		i.pushStack(b2)
		i.pushStack(b1)
		i.pushStack(b3)

	case bitcoin.OP_SWAP: // Reverse the order of the top two stack items
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

	case bitcoin.OP_TUCK: // Copy the item at the top of the stack into before the second item on the stack
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

	case bitcoin.OP_CAT: // Concatenate the top to stack items
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(append(b2, b1...))

	case bitcoin.OP_SPLIT: // Split the second item at the index specified in the top item
		n, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}
		c, err := decodeInteger(n)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

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

	case bitcoin.OP_NUM2BIN: // Convert second item on the stack into a byte sequence the length specified by the first stack item
		n, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}
		c, err := decodeInteger(n)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

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
		vc, err := decodeInteger(v)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		b := encodeInteger(vc)
		if count < int64(len(b)) {
			return errors.Wrapf(ErrScriptInvalid,
				"value size greater than count: %s: count %d, size %d", item, count, len(b))
		}

		b, err = padNumber(b, int(count))
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		i.pushStack(b)

	case bitcoin.OP_BIN2NUM: // Convert the top stack item into a number value
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		c, err := decodeIntegerFull(b, false)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		b = encodeInteger(c)
		i.pushStack(b)

	case bitcoin.OP_SIZE: // Push the length of the top stack item onto the stack
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		i.pushStack(b1)
		i.pushStack(encodePrimitiveInteger(len(b1)))

	case bitcoin.OP_EQUAL:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		if bytes.Equal(b1, b2) {
			i.pushStack(encodePrimitiveInteger(1))
		} else {
			i.pushStack(encodePrimitiveInteger(0))
		}

	case bitcoin.OP_EQUALVERIFY:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		if !bytes.Equal(b1, b2) {
			if i.verbose {
				logger.VerboseWithFields(ctx, []logger.Field{
					logger.Int("item_index", itemIndex),
				}, "Verify equal failed")
			}

			i.err = errors.Wrapf(ErrVerifyFailed, "op code (%d): %s", itemIndex, item)
			i.scriptVerifyFailed = true
			return nil
		}

	case bitcoin.OP_1ADD:
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n, err := decodeInteger(b)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

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

		n, err := decodeInteger(b)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		i.pushStack(encodeInteger(n.Neg(n)))

	case bitcoin.OP_ABS:
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n, err := decodeInteger(b)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

		i.pushStack(encodeInteger(n.Abs(n)))

	case bitcoin.OP_NOT:
		b, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n, err := decodeInteger(b)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

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

		n, err := decodeInteger(b)
		if err != nil {
			return errors.Wrapf(err, "%s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		i.pushStack(encodeInteger(n1.Add(n1, n2)))

	case bitcoin.OP_SUB: // second stack item minus top stack item
		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		i.pushStack(encodeInteger(n1.Sub(n1, n2)))

	case bitcoin.OP_MUL:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		i.pushStack(encodeInteger(n1.Mul(n1, n2)))

	case bitcoin.OP_DIV: // second stack item divided by top stack item
		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		if n2.Sign() == 0 {
			return errors.Wrapf(ErrScriptInvalid, "divide by zero: %s", item)
		}

		r := n1.Div(n1, n2)
		i.pushStack(encodeInteger(r))

	case bitcoin.OP_MOD: // Divide second stack item by top stack item and put the remainder on the stack
		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		if n2.Sign() == 0 {
			return errors.Wrapf(ErrScriptInvalid, "divide by zero: %s", item)
		}

		i.pushStack(encodeInteger(n1.Mod(n1, n2)))

	case bitcoin.OP_LSHIFT:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		if n1.Cmp(n2) != 0 {
			i.err = errors.Wrapf(ErrVerifyFailed, "op code (%d): %s", itemIndex, item)
			i.scriptVerifyFailed = true
			return nil
		}

	case bitcoin.OP_NUMNOTEQUAL:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

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

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		b3, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n3, err := decodeInteger(b3)
		if err != nil {
			return errors.Wrapf(err, "b3: %s", item)
		}

		if n2.Cmp(n1) <= 0 && n3.Cmp(n1) >= 0 {
			i.pushStack(encodePrimitiveInteger(1))
		} else {
			i.pushStack(encodePrimitiveInteger(0))
		}

	case bitcoin.OP_LESSTHAN, bitcoin.OP_GREATERTHAN, bitcoin.OP_LESSTHANOREQUAL,
		bitcoin.OP_GREATERTHANOREQUAL:

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n2, err := decodeInteger(b2)
		if err != nil {
			return errors.Wrapf(err, "b2: %s", item)
		}

		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		n1, err := decodeInteger(b1)
		if err != nil {
			return errors.Wrapf(err, "b1: %s", item)
		}

		switch item.OpCode {
		case bitcoin.OP_LESSTHAN: // second stack item is less than top stack item
			if n1.Cmp(n2) < 0 {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_GREATERTHAN: // second stack item is greater than top stack item
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
		l := len(*codeScript)
		*codeScript = (*codeScript)[l-scriptBuf.Len():]

	case bitcoin.OP_CHECKSIG, bitcoin.OP_CHECKSIGVERIFY:
		b1, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		publicKey, err := bitcoin.PublicKeyFromBytes(b1)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "invalid public key: %s", err)
		}

		b2, err := i.popStack()
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "stack empty: %s", item)
		}

		b2Len := len(b2)
		if b2Len < 2 {
			return errors.Wrapf(ErrScriptInvalid, "invalid signature: too short %d", b2Len)
		}

		hashType := SigHashType(b2[b2Len-1])
		signature, err := bitcoin.SignatureFromBytes(b2[:b2Len-1])
		if err != nil {
			return errors.Wrap(ErrMalformedSignature, err.Error())
		}

		sigHash, err := CalculateSignatureHash(writeSigPreimage, hashType, *codeScript, -1)
		if err != nil {
			return errors.Wrapf(ErrScriptInvalid, "calculate sig hash: %s", err)
		}

		verified := signature.Verify(sigHash, publicKey)
		if i.verbose && ctx != nil {
			if verified {
				logger.Verbose(ctx, "Sig verified")
			} else {
				logger.InfoWithFields(ctx, []logger.Field{
					logger.Formatter("sig_hash", "%x", sigHash[:]),
				}, "Sig not verified")
			}
		}

		switch item.OpCode {
		case bitcoin.OP_CHECKSIG:
			if verified {
				i.pushStack(encodePrimitiveInteger(1))
			} else {
				i.pushStack(encodePrimitiveInteger(0))
			}

		case bitcoin.OP_CHECKSIGVERIFY:
			if !verified {
				i.err = errors.Wrapf(ErrVerifyFailed, "op code (%d): %s", itemIndex, item)
				i.scriptVerifyFailed = true
				return nil
			}
		}

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

	case bitcoin.OP_RESERVED, bitcoin.OP_RESERVED1, bitcoin.OP_RESERVED2:
		return errors.Wrapf(ErrBadOpCode, "op code: %s", item)

	case bitcoin.OP_NOP1, bitcoin.OP_NOP2, bitcoin.OP_NOP3, bitcoin.OP_NOP4, bitcoin.OP_NOP5,
		bitcoin.OP_NOP6, bitcoin.OP_NOP7, bitcoin.OP_NOP8, bitcoin.OP_NOP9, bitcoin.OP_NOP10:
		// ignore

	case bitcoin.OP_PUBKEYHASH_ACTUAL, bitcoin.OP_PUBKEY_ACTUAL,
		bitcoin.OP_INVALIDOPCODE_ACTUAL:
		return errors.Wrapf(ErrBadOpCode, "op code: %s", item)

	case bitcoin.OP_VER, bitcoin.OP_VERIF, bitcoin.OP_VERNOTIF:
		return errors.Wrapf(ErrBadOpCode, "op code: %s", item)

	default:
		return errors.Wrapf(ErrBadOpCode, "op code: %s", item)
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

	return errors.Wrapf(ErrNotUnlocked, "final stack item: 0x%x", i.stack[stackLen-1])
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

func (i *Interpreter) StackItems() [][]byte {
	l := len(i.stack)
	result := make([][]byte, l)
	k := 0
	for j := l - 1; j >= 0; j-- {
		// for j := 0; j < l; j++ {
		result[k] = copyBytes(i.stack[j])
		k++
	}

	return result
}

func (i *Interpreter) StackStrings() []string {
	l := len(i.stack)
	result := make([]string, l)
	k := 0
	for j := l - 1; j >= 0; j-- {
		// for j := 0; j < l; j++ {
		result[k] = fmt.Sprintf("%x", i.stack[j])
		k++
	}

	return result
}

func (i *Interpreter) StackString() string {
	return strings.Join(i.StackStrings(), "\n")
}

func (i *Interpreter) pushStack(b []byte) {
	i.stack = append(i.stack, b)
}

func (i *Interpreter) popStack() ([]byte, error) {
	stackLen := len(i.stack)
	if stackLen == 0 {
		return nil, ErrStackEmpty
	}

	b := i.stack[stackLen-1]
	i.stack = i.stack[:stackLen-1]
	return b, nil
}

func (i *Interpreter) getStack(depth int, remove bool) ([]byte, error) {
	stackLen := len(i.stack)
	if depth >= stackLen {
		return nil, ErrStackEmpty
	}

	index := stackLen - 1 - depth // last item minus depth (zero depth means last item)
	b := i.stack[index]
	if remove {
		i.stack = append(i.stack[:index], i.stack[index+1:]...)
	}
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
	if len(b) == 0 {
		return false
	}

	i, err := decodeInteger(b)
	if err != nil {
		return false
	}

	return i.Cmp(big.NewInt(0)) != 0
}

func encodePrimitiveInteger(value int) []byte {
	return encodeInteger(new(big.Int).SetInt64(int64(value)))
}

func encodeInteger(value *big.Int) []byte {
	if value.Sign() == 0 {
		return nil
	}

	var result []byte
	isNegative := value.Sign() < 0
	remaining := new(big.Int).Set(value)
	remaining.Abs(remaining)
	byteMask := new(big.Int).SetBytes([]byte{0xff})
	for {
		lastByte := byte(new(big.Int).And(remaining, byteMask).Int64())
		remaining.Rsh(remaining, 8)

		if remaining.Sign() != 0 {
			result = append(result, lastByte)
			continue
		}

		// remaining is zero
		if lastByte&0x80 == 0x80 {
			result = append(result, lastByte)
			if isNegative {
				result = append(result, 0x80)
			} else {
				result = append(result, 0x00)
			}
		} else {
			if isNegative {
				result = append(result, lastByte|0x80)
			} else {
				result = append(result, lastByte)
			}
		}

		break
	}

	// l := len(result)
	// if l > 0 && result[l-1]&0x7f == 0 {
	// 	if l <= 1 || (result[l-2]&0x80) == 0 {
	// 		panic(errors.Wrapf(ErrNonMinimallyEncodedNumber, "%x", result))
	// 	}
	// }

	return result
}

func reverseEndian(b []byte) []byte {
	l := len(b)
	result := make([]byte, l)
	r := l - 1
	for _, v := range b {
		result[r] = v
		r--
	}
	return result
}

func padNumber(b []byte, size int) ([]byte, error) {
	n, err := decodeInteger(b)
	if err != nil {
		return nil, err
	}
	b = encodeInteger(n)

	l := len(b)
	if l == 0 {
		return make([]byte, size), nil
	}

	if l == size {
		return b, nil
	}

	result := make([]byte, size)
	copy(result, b)

	return result, nil
}

func decodeInteger(b []byte) (*big.Int, error) {
	return decodeIntegerFull(b, true)
}

func decodeIntegerFull(b []byte, requireMinimal bool) (*big.Int, error) {
	result := new(big.Int).SetInt64(0)
	l := len(b)
	if l == 0 {
		return result, nil
	}

	// check minimal encoding
	if requireMinimal && b[l-1]&0x7f == 0 {
		if l <= 1 || (b[l-2]&0x80) == 0 {
			return nil, errors.Wrapf(ErrNonMinimallyEncodedNumber, "%x", b)
		}
	}

	for i, bt := range b[:l-1] {
		byt := new(big.Int).SetBytes([]byte{bt})
		byt.Lsh(byt, uint(i*8))
		result.Add(result, byt)
	}

	var byt *big.Int
	isNegative := b[l-1]&0x80 == 0x80
	if isNegative {
		byt = new(big.Int).SetBytes([]byte{b[l-1] & 0x7f})
	} else {
		byt = new(big.Int).SetBytes([]byte{b[l-1]})
	}

	byt.Lsh(byt, uint((l-1)*8))
	result.Add(result, byt)
	if isNegative {
		result.Neg(result)
	}

	return result, nil
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

func minimalEncode(b []byte) []byte {
	l := len(b)
	if l == 0 {
		return b
	}

	// If the last byte is not 0x00 or 0x80, we are minimally encoded.
	if b[l-1]&0x7f != 0 {
		return b
	}

	// If the script is one byte long, then we have a zero, which encodes as an empty array.
	if l == 1 {
		return nil
	}

	// If the next byte has it sign bit set, then we are minimaly encoded.
	if b[l-2]&0x80 != 0 {
		return b
	}

	// We are not minimally encoded, we need to figure out how much to trim.
	last := b[l-1]
	for i := l - 1; i > 0; i-- {
		// We found a non zero byte, time to encode.
		if b[i-1] != 0 {
			if b[i-1]&0x80 != 0 {
				// We found a byte with it sign bit set so we need one more byte.
				b[i] = last
				i++
			} else {
				// the sign bit is clear, we can use it.
				b[i-1] |= last
			}

			return b
		}
	}

	// If we the whole thing is zeros, then we have a zero.
	return nil
}
