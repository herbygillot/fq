package bitcoin

// TODO: rename package to bitcoin?
// TODO: split into bitcoin_blkdat, bitcoin_block?

// https://learnmeabitcoin.com/technical/blkdat

import (
	"time"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/bitcoin/base58"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
)

var bitcoinScriptFormat decode.Group

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.BITCOIN_TRANSCATION,
		Description: "Bitcoin transcation",
		Dependencies: []decode.Dependency{
			{Names: []string{format.BITCOIN_SCRIPT}, Group: &bitcoinScriptFormat},
		},
		DecodeFn: decodeBitcoinTranscation,
	})
}

// Prefix with fd, and the next 2 bytes is the VarInt (in little-endian).
// Prefix with fe, and the next 4 bytes is the VarInt (in little-endian).
// Prefix with ff, and the next 8 bytes is the VarInt (in little-endian).
func decodeVarInt(d *decode.D) uint64 {
	n := d.U8()
	switch n {
	case 0xfd:
		return d.U16()
	case 0xfe:
		return d.U32()
	case 0xff:
		return d.U64()
	default:
		return n
	}
}

var rawBase58 = scalar.Fn(func(s scalar.S) (scalar.S, error) {
	return scalar.RawSym(s, -1, base58.Encode)
})

var timeUnixEpoch = scalar.Fn(func(s scalar.S) (scalar.S, error) {
	uv, ok := s.Actual.(uint64)
	if !ok {
		return s, nil
	}
	s.Description = time.Unix(int64(uv), 0).Format(time.RFC3339)
	return s, nil
})

func decodeBitcoinTranscation(d *decode.D, in interface{}) interface{} {
	d.Endian = decode.LittleEndian

	d.FieldU32("version")
	witness := false
	if d.PeekBits(8) == 0 {
		witness = true
		d.FieldU8("marker")
		d.FieldU8("flag")
	}
	inputCount := d.FieldUFn("input_count", decodeVarInt)
	d.FieldArray("inputs", func(d *decode.D) {
		for i := uint64(0); i < inputCount; i++ {
			d.FieldStruct("input", func(d *decode.D) {
				d.FieldRawLen("txid", 32*8, rawHexReverse)
				d.FieldU32("vout")
				scriptSigSize := d.FieldUFn("scriptsig_size", decodeVarInt)
				d.FieldFormatLen("scriptsig", int64(scriptSigSize)*8, bitcoinScriptFormat, nil)
				d.FieldU32("sequence", scalar.Hex)
			})
		}
	})
	outputCount := d.FieldUFn("output_count", decodeVarInt)
	d.FieldArray("outputs", func(d *decode.D) {
		for i := uint64(0); i < outputCount; i++ {
			d.FieldStruct("output", func(d *decode.D) {
				d.FieldU64("value")
				scriptSigSize := d.FieldUFn("scriptpub_size", decodeVarInt)
				d.FieldFormatLen("scriptpub", int64(scriptSigSize)*8, bitcoinScriptFormat, nil)
			})
		}
	})

	if witness {
		d.FieldArray("witnesses", func(d *decode.D) {
			for i := uint64(0); i < inputCount; i++ {
				d.FieldStruct("witness", func(d *decode.D) {
					witnessSize := d.FieldUFn("witness_size", decodeVarInt)
					d.FieldArray("items", func(d *decode.D) {
						for j := uint64(0); j < witnessSize; j++ {
							itemSize := d.FieldUFn("item_size", decodeVarInt)
							d.FieldRawLen("item", int64(itemSize)*8)
						}
					})
				})
			}
		})
	}
	d.FieldU32("locktime")

	return nil
}
