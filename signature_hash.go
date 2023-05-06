package bitcoin_interpreter

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/tokenized/pkg/bitcoin"
	"github.com/tokenized/pkg/wire"

	"github.com/pkg/errors"
)

// SigHashType represents hash type bits at the end of a signature.
type SigHashType uint32

const (
	// BasePreimageSize is the size of the preimage not including the code script since that is
	// variable.
	BasePreimageSize = 4 + // version
		32 + // previous outputs hash
		32 + // inputs sequence hash
		32 + 4 + // previous outpoint
		// variable length code script with varint size value
		8 + // spent output value
		4 + // spending input sequence
		32 + // outputs hash
		4 + // lock time
		4 // sig hash type

	SigHashAll          SigHashType = 0x01 // Sign all inputs, all outputs
	SigHashNone         SigHashType = 0x02 // Sign all inputs, no outputs
	SigHashSingle       SigHashType = 0x03 // Sign all inputs, only the output at same index as input
	SigHashAnyOneCanPay SigHashType = 0x80 // When combined, only sign contained input
	SigHashForkID       SigHashType = 0x40

	// sigHashTypeMask defines masks the bits of the hash type used to identify which outputs are
	// signed.
	sigHashTypeMask = 0x1f
)

var (
	InvalidSingleSigHash = bitcoin.Hash32{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
)

func (v SigHashType) HasForkID() bool {
	return v&SigHashForkID == SigHashForkID
}

func (v SigHashType) HasAnyOneCanPay() bool {
	return v&SigHashAnyOneCanPay == SigHashAnyOneCanPay
}

func (v SigHashType) HasSingle() bool {
	return v&SigHashSingle == SigHashSingle
}

func (v SigHashType) HasNone() bool {
	return v&SigHashNone == SigHashNone
}

func (v SigHashType) IsAll() bool {
	return v&sigHashTypeMask == SigHashAll
}

func (v SigHashType) String() string {
	var parts []string
	if SigHashForkID&v != 0 {
		parts = append(parts, "FORK_ID")
	}
	if SigHashAnyOneCanPay&v != 0 {
		parts = append(parts, "ANYONE_CAN_PAY")
	}
	switch v & sigHashTypeMask {
	case SigHashAll:
		parts = append(parts, "ALL")
	case SigHashNone:
		parts = append(parts, "NONE")
	case SigHashSingle:
		parts = append(parts, "SINGLE")
	}

	return strings.Join(parts, "|")
}

func SigHashTypeFromString(s string) (SigHashType, error) {
	var result SigHashType
	parts := strings.Split(s, "|")
	for _, part := range parts {
		switch part {
		case "FORK_ID":
			result |= SigHashForkID
		case "ANYONE_CAN_PAY":
			result |= SigHashAnyOneCanPay
		case "ALL":
			result |= SigHashAll
		case "NONE":
			result |= SigHashNone
		case "SINGLE":
			result |= SigHashSingle
		}
	}

	return result, nil
}

func (v *SigHashType) SetString(s string) error {
	newV, err := SigHashTypeFromString(s)
	if err != nil {
		return err
	}

	*v = newV
	return nil
}

func (v SigHashType) MarshalText() ([]byte, error) {
	return []byte(v.String()), nil
}

func (v *SigHashType) UnmarshalText(b []byte) error {
	return v.SetString(string(b))
}

// SigHashCache allows caching of previously calculated hashes used to calculate the signature hash
//   for signing tx inputs.
// This allows validation to re-use previous hashing computation, reducing the complexity of
//   validating SigHashAll inputs rom  O(N^2) to O(N).
type SigHashCache struct {
	hashPrevOuts []byte
	hashSequence []byte
	hashOutputs  []byte
}

// Clear resets all the hashes. This should be used if anything in the transaction changes and the
//   signatures need to be recalculated.
func (shc *SigHashCache) Clear() {
	shc.hashPrevOuts = nil
	shc.hashSequence = nil
	shc.hashOutputs = nil
}

// ClearOutputs resets the outputs hash. This should be used if anything in the transaction outputs
//   changes and the signatures need to be recalculated.
func (shc *SigHashCache) ClearOutputs() {
	shc.hashOutputs = nil
}

// HashPrevOuts calculates a single hash of all the previous outputs (txid:index) referenced within
//   the specified transaction.
func (shc *SigHashCache) HashPrevOuts(tx *wire.MsgTx) []byte {
	if shc.hashPrevOuts != nil {
		return shc.hashPrevOuts
	}

	var buf bytes.Buffer
	for _, in := range tx.TxIn {
		in.PreviousOutPoint.Serialize(&buf)
	}

	shc.hashPrevOuts = bitcoin.DoubleSha256(buf.Bytes())
	return shc.hashPrevOuts
}

// HashSequence computes an aggregated hash of each of the sequence numbers within the inputs of the
//   passed transaction.
func (shc *SigHashCache) HashSequence(tx *wire.MsgTx) []byte {
	if shc.hashSequence != nil {
		return shc.hashSequence
	}

	var buf bytes.Buffer
	for _, in := range tx.TxIn {
		binary.Write(&buf, binary.LittleEndian, in.Sequence)
	}

	shc.hashSequence = bitcoin.DoubleSha256(buf.Bytes())
	return shc.hashSequence
}

// HashOutputs computes a hash digest of all outputs created by the transaction encoded using the
//   wire format.
func (shc *SigHashCache) HashOutputs(tx *wire.MsgTx) []byte {
	if shc.hashOutputs != nil {
		return shc.hashOutputs
	}

	var buf bytes.Buffer
	for _, out := range tx.TxOut {
		out.Serialize(&buf, 0, 0)
	}

	shc.hashOutputs = bitcoin.DoubleSha256(buf.Bytes())
	return shc.hashOutputs
}

// SignatureHash computes the hash to be signed for a transaction's input using the new, optimized
//   digest calculation algorithm defined in BIP0143:
//   https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki.
// This function makes use of pre-calculated hash fragments stored within the passed SigHashCache to
//   eliminate duplicate hashing computations when calculating the final digest, reducing the
//   complexity from O(N^2) to O(N).
// Additionally, signatures now cover the input value of the referenced unspent output. This allows
//   offline, or hardware wallets to compute the exact amount being spent, in addition to the final
//   transaction fee. In the case the wallet if fed an invalid input amount, the real sighash will
//   differ causing the produced signature to be invalid.
// opCodeSeparatorIndex of -1 means to ignore op code separators.
func SignatureHash(tx *wire.MsgTx, index int, lockingScript bitcoin.Script,
	opCodeSeparatorIndex int, value uint64, hashType SigHashType,
	hashCache *SigHashCache) (*bitcoin.Hash32, error) {

	if hashType.HasSingle() && index >= len(tx.TxOut) {
		return &InvalidSingleSigHash, nil
	}

	codeScript, err := afterOpCodeSeparator(lockingScript, opCodeSeparatorIndex)
	if err != nil {
		return nil, errors.Wrap(err, "after code separator")
	}

	s := sha256.New()

	if err := writeSignatureHashPreimageBytes(s, tx, index, codeScript, value, hashType,
		hashCache); err != nil {
		return nil, errors.Wrap(err, "write sig hash bytes")
	}

	hash := bitcoin.Hash32(sha256.Sum256(s.Sum(nil)))
	return &hash, nil
}

func SignaturePreimage(tx *wire.MsgTx, index int, lockingScript bitcoin.Script,
	opCodeSeparatorIndex int, value uint64, hashType SigHashType,
	hashCache *SigHashCache) ([]byte, error) {

	if hashType.HasSingle() && index >= len(tx.TxOut) {
		return nil, errors.New("SigHashSingle: Missing output for input index")
	}

	codeScript, err := afterOpCodeSeparator(lockingScript, opCodeSeparatorIndex)
	if err != nil {
		return nil, errors.Wrap(err, "after code separator")
	}

	buf := &bytes.Buffer{}
	if err := writeSignatureHashPreimageBytes(buf, tx, index, codeScript, value, hashType,
		hashCache); err != nil {
		return nil, errors.Wrap(err, "write sig hash bytes")
	}

	return buf.Bytes(), nil
}

func writeSignatureHashPreimageBytes(w io.Writer, tx *wire.MsgTx, index int,
	codeScript bitcoin.Script, value uint64, hashType SigHashType, hashCache *SigHashCache) error {

	// As a sanity check, ensure the passed input index for the transaction is valid.
	if index > len(tx.TxIn)-1 {
		return fmt.Errorf("SignatureHash error: index %d but %d txins", index, len(tx.TxIn))
	}

	// First write out, then encode the transaction's version number.
	binary.Write(w, binary.LittleEndian, tx.Version)

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash [32]byte

	// If anyone can pay is active we just write zeroes for the prev outs hash.
	if hashType.HasAnyOneCanPay() {
		w.Write(zeroHash[:])
	} else {
		w.Write(hashCache.HashPrevOuts(tx))
	}

	// If the sighash is anyone can pay, single, or none we write all zeroes for the sequence hash.
	if !hashType.HasAnyOneCanPay() && !hashType.HasSingle() && !hashType.HasNone() {
		w.Write(hashCache.HashSequence(tx))
	} else {
		w.Write(zeroHash[:])
	}

	// Next, write the outpoint being spent.
	tx.TxIn[index].PreviousOutPoint.Serialize(w)

	// Write the portion of the locking script being spent that is after the last executed
	// OP_CODE_SEPARATOR.
	wire.WriteVarBytes(w, 0, codeScript)

	// Next, add the input amount, and sequence number of the input being signed.
	binary.Write(w, binary.LittleEndian, value)
	binary.Write(w, binary.LittleEndian, tx.TxIn[index].Sequence)

	// If the current signature mode is single, or none, then we'll serialize and add only the
	//   target output index to the signature pre-image.
	if hashType.IsAll() {
		w.Write(hashCache.HashOutputs(tx))
	} else if hashType.HasSingle() {
		if index >= len(tx.TxOut) {
			return fmt.Errorf("SigHashSingle does not contain output at input index : %d", index)
		}
		var b bytes.Buffer
		tx.TxOut[index].Serialize(&b, 0, 0)
		w.Write(bitcoin.DoubleSha256(b.Bytes()))
	} else {
		w.Write(zeroHash[:])
	}

	// Finally, write out the transaction's locktime, and the sig hash type.
	binary.Write(w, binary.LittleEndian, tx.LockTime)
	binary.Write(w, binary.LittleEndian, uint32(hashType))

	return nil
}

// afterOpCodeSeparator returns the portion of the locking script after the last OP_CODESEPARATOR.
// NOTE: This is only correct if the last OP_CODESEPARATOR is actually executed when the script is
// executed, so there is room for error here depending on the locking script. --ce
func afterOpCodeSeparator(lockingScript bitcoin.Script, index int) (bitcoin.Script, error) {
	if index == -1 {
		return lockingScript, nil
	}

	items, err := bitcoin.ParseScriptItems(bytes.NewReader(lockingScript), -1)
	if err != nil {
		return nil, errors.Wrap(err, "parse")
	}

	remaining := index
	itemCount := len(items)
	lastIndex := -1
	for i := 0; i < itemCount; i++ {
		item := items[i]
		if item.Type == bitcoin.ScriptItemTypeOpCode && item.OpCode == bitcoin.OP_CODESEPARATOR {
			if i == itemCount-1 {
				return nil, nil // OP_CODESEPARATOR is the last op code of the script
			}

			if remaining == 0 {
				return items[i+1:].Script()
			}
			lastIndex = i
			remaining--
		}
	}

	if lastIndex != -1 {
		return items[lastIndex+1:].Script()
	}

	// No OP_CODESEPARATOR found so return the full locking script.
	return lockingScript, nil
}
