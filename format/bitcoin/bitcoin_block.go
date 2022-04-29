package bitcoin

// TODO: rename package to bitcoin?
// TODO: split into bitcoin_blkdat, bitcoin_block?

// https://learnmeabitcoin.com/technical/blkdat

import (
	"fmt"

	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
)

var bitcoinTranscationFormat decode.Group

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.BITCOIN_BLOCK,
		Description: "Bitcoin block",
		Dependencies: []decode.Dependency{
			{Names: []string{format.BITCOIN_TRANSCATION}, Group: &bitcoinTranscationFormat},
		},
		DecodeFn: decodeBitcoinBlock,
	})
}

var rawHexReverse = scalar.Fn(func(s scalar.S) (scalar.S, error) {
	return scalar.RawSym(s, -1, func(b []byte) string {
		decode.ReverseBytes(b)
		return fmt.Sprintf("%x", b)
	})
})

func decodeBitcoinBlock(d *decode.D, in interface{}) interface{} {
	size := d.BitsLeft()

	// TODO: move to blkdat but how to model it?
	switch d.PeekBits(32) {
	case 0xf9beb4d9,
		0x0b110907,
		0xfabfb5da:
		d.FieldU32("magic", scalar.UToSymStr{
			0xf9beb4d9: "mainnet",
			0x0b110907: "testnet3",
			0xfabfb5da: "regtest",
		}, scalar.Hex)
		size = int64(d.FieldU32LE("size")) * 8
	}

	d.Endian = decode.LittleEndian

	d.FramedFn(size, func(d *decode.D) {
		d.FieldStruct("header", func(d *decode.D) {
			d.FieldU32("version", scalar.Hex)
			d.FieldRawLen("previous_block_hash", 32*8, rawHexReverse)
			d.FieldRawLen("merkle_root", 32*8, rawHexReverse)
			d.FieldU32("time", timeUnixEpoch)
			d.FieldU32("bits", scalar.Hex)
			d.FieldU32("nonce", scalar.Hex)
		})

		// TODO: remove? support header only decode this way?
		if d.BitsLeft() == 0 {
			return
		}

		txCount := d.FieldUFn("tx_count", decodeVarInt)
		d.FieldArray("transactions", func(d *decode.D) {
			for i := uint64(0); i < txCount; i++ {
				d.FieldFormat("transcation", bitcoinTranscationFormat, nil)
			}
		})
	})

	return nil
}
