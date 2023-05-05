package bitcoin_interpreter

import (
	"bytes"

	"github.com/tokenized/pkg/bitcoin"

	"github.com/pkg/errors"
)

var (
	// ScriptNotMatching means the script doesn't match what it was being parsed against.
	ScriptNotMatching = errors.New("Script Not Matching")
)

// MatchScript parses the script items against the script. If the script doesn't completely match
// the beginning of the items then it returns ScriptNotMatching. Otherwise it returns the remaining
// script items.
func MatchScript(items bitcoin.ScriptItems, script bitcoin.Script) (bitcoin.ScriptItems, error) {
	matchItems, err := bitcoin.ParseScriptItems(bytes.NewReader(script), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse script")
	}

	for {
		if len(matchItems) == 0 {
			println("full match")
			return items, nil // all match items matched
		}
		matchItem := matchItems[0]
		matchItems = matchItems[1:]

		if len(items) == 0 {
			return nil, errors.Wrap(ScriptNotMatching, "too short")
		}
		item := items[0]
		items = items[1:]

		println("check match", matchItem.String(), item.String())

		if !matchItem.Equal(*item) {
			return nil, errors.Wrapf(ScriptNotMatching, "item %s should be %s", item, matchItem)
		}
	}
}

func MatchNextOpCode(items bitcoin.ScriptItems, opCode byte) (bitcoin.ScriptItems, error) {
	if len(items) == 0 {
		return nil, errors.Wrapf(ScriptNotMatching, "missing %s",
			bitcoin.OpCodeToString(opCode))
	}
	item := items[0]

	println("check match", bitcoin.OpCodeToString(opCode), item.String())

	if item.Type != bitcoin.ScriptItemTypeOpCode || item.OpCode != opCode {
		return nil, errors.Wrapf(ScriptNotMatching, "should be %s: %s",
			bitcoin.OpCodeToString(opCode), item)
	}

	return items[1:], nil
}

func MatchNextPushDataSize(items bitcoin.ScriptItems,
	size int) (bitcoin.ScriptItems, []byte, error) {

	if len(items) == 0 {
		return nil, nil, errors.Wrapf(ScriptNotMatching, "missing push data size %d", size)
	}
	item := items[0]

	println("check match", "push data size", size, item.String())

	if item.Type != bitcoin.ScriptItemTypePushData || len(item.Data) != size {
		return nil, nil, errors.Wrapf(ScriptNotMatching, "should be size %d: %s", size, item)
	}

	return items[1:], item.Data, nil
}
