package bitcoin

import (
	"github.com/wader/fq/format"
	"github.com/wader/fq/format/registry"
	"github.com/wader/fq/pkg/decode"
	"github.com/wader/fq/pkg/scalar"
)

type opcodeEntry struct {
	r [2]byte
	s scalar.S
	d func(d *decode.D, opcode byte)
}

type opcodeEntries []opcodeEntry

func (ops opcodeEntries) lookup(u byte) (opcodeEntry, bool) {
	for _, fe := range ops {
		if u >= fe.r[0] && u <= fe.r[1] {
			return fe, true
		}
	}
	return opcodeEntry{}, false
}

func (ops opcodeEntries) MapScalar(s scalar.S) (scalar.S, error) {
	u := s.ActualU()
	if fe, ok := ops.lookup(byte(u)); ok {
		s = fe.s
		s.Actual = u
	}
	return s, nil
}

func init() {
	registry.MustRegister(decode.Format{
		Name:        format.BITCOIN_SCRIPT,
		Description: "Bitcoin script",
		DecodeFn:    decodeBitcoinScript,
		RootArray:   true,
		RootName:    "opcodes",
	})
}

func decodeBitcoinScript(d *decode.D, in interface{}) interface{} {
	opcodeEntries := opcodeEntries{
		{r: [2]byte{0x00, 0x00}, s: scalar.S{Sym: "false"}},
		// TODO: name op code?
		{r: [2]byte{0x01, 0x4b}, s: scalar.S{Sym: "pushself"}, d: func(d *decode.D, opcode byte) { d.FieldRawLen("arg", int64(opcode)*8) }},
		{r: [2]byte{0x04c, 0x4e}, s: scalar.S{Sym: "pushdata1"}, d: func(d *decode.D, opcode byte) {
			argLen := d.FieldU8("arg_length")
			d.FieldRawLen("arg", int64(argLen)*8)
		}},
		{r: [2]byte{0x04c, 0x4e}, s: scalar.S{Sym: "pushdata2"}, d: func(d *decode.D, opcode byte) {
			argLen := d.FieldU16("arg_length")
			d.FieldRawLen("arg", int64(argLen)*8)
		}},
		{r: [2]byte{0x04c, 0x4e}, s: scalar.S{Sym: "pushdata4"}, d: func(d *decode.D, opcode byte) {
			argLen := d.FieldU32("arg_length")
			d.FieldRawLen("arg", int64(argLen)*8)
		}},
		{r: [2]byte{0x4f, 0x4f}, s: scalar.S{Sym: "1negate"}},
		{r: [2]byte{0x51, 0x51}, s: scalar.S{Sym: "true"}},
		// TODO: name
		{r: [2]byte{0x52, 0x60}, s: scalar.S{Sym: "push"}, d: func(d *decode.D, opcode byte) {
			d.FieldValueU("arg", uint64(opcode-0x50))
		}},
		{r: [2]byte{0x61, 0x61}, s: scalar.S{Sym: "nop"}},
		{r: [2]byte{0x62, 0x62}, s: scalar.S{Sym: "ver"}},
		{r: [2]byte{0x63, 0x63}, s: scalar.S{Sym: "if"}},
		{r: [2]byte{0x64, 0x64}, s: scalar.S{Sym: "notif"}},
		{r: [2]byte{0x65, 0x65}, s: scalar.S{Sym: "verif"}},
		{r: [2]byte{0x66, 0x66}, s: scalar.S{Sym: "vernotif"}},
		{r: [2]byte{0x67, 0x67}, s: scalar.S{Sym: "else"}},
		{r: [2]byte{0x68, 0x68}, s: scalar.S{Sym: "endif"}},
		{r: [2]byte{0x69, 0x69}, s: scalar.S{Sym: "verify"}},
		{r: [2]byte{0x6a, 0x6a}, s: scalar.S{Sym: "return"}},
		{r: [2]byte{0x6b, 0x6b}, s: scalar.S{Sym: "toaltstack"}},
		{r: [2]byte{0x6c, 0x6c}, s: scalar.S{Sym: "fromaltstack"}},
		{r: [2]byte{0x6d, 0x6d}, s: scalar.S{Sym: "2drop"}},
		{r: [2]byte{0x6e, 0x6e}, s: scalar.S{Sym: "2dup"}},
		{r: [2]byte{0x6f, 0x6f}, s: scalar.S{Sym: "3dup"}},
		{r: [2]byte{0x70, 0x70}, s: scalar.S{Sym: "2over"}},
		{r: [2]byte{0x71, 0x71}, s: scalar.S{Sym: "2rot"}},
		{r: [2]byte{0x72, 0x72}, s: scalar.S{Sym: "2swap"}},
		{r: [2]byte{0x73, 0x73}, s: scalar.S{Sym: "ifdup"}},
		{r: [2]byte{0x74, 0x74}, s: scalar.S{Sym: "depth"}},
		{r: [2]byte{0x75, 0x75}, s: scalar.S{Sym: "drop"}},
		{r: [2]byte{0x76, 0x76}, s: scalar.S{Sym: "dup"}},
		{r: [2]byte{0x77, 0x77}, s: scalar.S{Sym: "nip"}},
		{r: [2]byte{0x78, 0x78}, s: scalar.S{Sym: "over"}},
		{r: [2]byte{0x79, 0x79}, s: scalar.S{Sym: "pick"}},
		{r: [2]byte{0x7a, 0x7a}, s: scalar.S{Sym: "roll"}},
		{r: [2]byte{0x7b, 0x7b}, s: scalar.S{Sym: "rot"}},
		{r: [2]byte{0x7c, 0x7c}, s: scalar.S{Sym: "swap"}},
		{r: [2]byte{0x7d, 0x7d}, s: scalar.S{Sym: "tuck"}},
		{r: [2]byte{0x7e, 0x7e}, s: scalar.S{Sym: "cat"}},
		{r: [2]byte{0x7f, 0x7f}, s: scalar.S{Sym: "split"}},
		{r: [2]byte{0x80, 0x80}, s: scalar.S{Sym: "num2bin"}},
		{r: [2]byte{0x81, 0x81}, s: scalar.S{Sym: "bin2num"}},
		{r: [2]byte{0x82, 0x82}, s: scalar.S{Sym: "size"}},
		{r: [2]byte{0x83, 0x83}, s: scalar.S{Sym: "invert"}},
		{r: [2]byte{0x84, 0x84}, s: scalar.S{Sym: "and"}},
		{r: [2]byte{0x85, 0x85}, s: scalar.S{Sym: "or"}},
		{r: [2]byte{0x86, 0x86}, s: scalar.S{Sym: "xor"}},
		{r: [2]byte{0x87, 0x87}, s: scalar.S{Sym: "equal"}},
		{r: [2]byte{0x88, 0x88}, s: scalar.S{Sym: "equalverify"}},
		{r: [2]byte{0x89, 0x89}, s: scalar.S{Sym: "reserved1"}},
		{r: [2]byte{0x8a, 0x8a}, s: scalar.S{Sym: "reserved2"}},
		{r: [2]byte{0x8b, 0x8b}, s: scalar.S{Sym: "1add"}},
		{r: [2]byte{0x8c, 0x8c}, s: scalar.S{Sym: "1sub"}},
		{r: [2]byte{0x8d, 0x8d}, s: scalar.S{Sym: "2mul"}},
		{r: [2]byte{0x8e, 0x8e}, s: scalar.S{Sym: "2div"}},
		{r: [2]byte{0x8f, 0x8f}, s: scalar.S{Sym: "negate"}},
		{r: [2]byte{0x90, 0x90}, s: scalar.S{Sym: "abs"}},
		{r: [2]byte{0x91, 0x91}, s: scalar.S{Sym: "not"}},
		{r: [2]byte{0x92, 0x92}, s: scalar.S{Sym: "0notequal"}},
		{r: [2]byte{0x93, 0x93}, s: scalar.S{Sym: "add"}},
		{r: [2]byte{0x94, 0x94}, s: scalar.S{Sym: "sub"}},
		{r: [2]byte{0x95, 0x95}, s: scalar.S{Sym: "mul"}},
		{r: [2]byte{0x96, 0x96}, s: scalar.S{Sym: "div"}},
		{r: [2]byte{0x97, 0x97}, s: scalar.S{Sym: "mod"}},
		{r: [2]byte{0x98, 0x98}, s: scalar.S{Sym: "lshift"}},
		{r: [2]byte{0x99, 0x99}, s: scalar.S{Sym: "rshift"}},
		{r: [2]byte{0x9a, 0x9a}, s: scalar.S{Sym: "booland"}},
		{r: [2]byte{0x9b, 0x9b}, s: scalar.S{Sym: "boolor"}},
		{r: [2]byte{0x9c, 0x9c}, s: scalar.S{Sym: "numequal"}},
		{r: [2]byte{0x9d, 0x9d}, s: scalar.S{Sym: "numequalverify"}},
		{r: [2]byte{0x9e, 0x9e}, s: scalar.S{Sym: "numnotequal"}},
		{r: [2]byte{0x9f, 0x9f}, s: scalar.S{Sym: "lessthan"}},
		{r: [2]byte{0xa0, 0xa0}, s: scalar.S{Sym: "greaterthan"}},
		{r: [2]byte{0xa1, 0xa1}, s: scalar.S{Sym: "lessthanorequal"}},
		{r: [2]byte{0xa2, 0xa2}, s: scalar.S{Sym: "greaterthanorequal"}},
		{r: [2]byte{0xa3, 0xa3}, s: scalar.S{Sym: "min"}},
		{r: [2]byte{0xa4, 0xa4}, s: scalar.S{Sym: "max"}},
		{r: [2]byte{0xa5, 0xa5}, s: scalar.S{Sym: "within"}},
		{r: [2]byte{0xa6, 0xa6}, s: scalar.S{Sym: "ripemd160"}},
		{r: [2]byte{0xa7, 0xa7}, s: scalar.S{Sym: "sha1"}},
		{r: [2]byte{0xa8, 0xa8}, s: scalar.S{Sym: "sha256"}},
		{r: [2]byte{0xa9, 0xa9}, s: scalar.S{Sym: "hash160"}},
		{r: [2]byte{0xaa, 0xaa}, s: scalar.S{Sym: "hash256"}},
		{r: [2]byte{0xab, 0xab}, s: scalar.S{Sym: "codeseparator"}},
		{r: [2]byte{0xac, 0xac}, s: scalar.S{Sym: "checksig"}},
		{r: [2]byte{0xad, 0xad}, s: scalar.S{Sym: "checksigverify"}},
		{r: [2]byte{0xae, 0xae}, s: scalar.S{Sym: "checkmultisig"}},
		{r: [2]byte{0xaf, 0xaf}, s: scalar.S{Sym: "checkmultisigverify"}},
		{r: [2]byte{0xb0, 0xb0}, s: scalar.S{Sym: "nop1"}},
		{r: [2]byte{0xb1, 0xb1}, s: scalar.S{Sym: "nop2"}},
		{r: [2]byte{0xb1, 0xb1}, s: scalar.S{Sym: "checklocktimeverify"}},
		{r: [2]byte{0xb2, 0xb2}, s: scalar.S{Sym: "nop3"}},
		{r: [2]byte{0xb2, 0xb2}, s: scalar.S{Sym: "checksequenceverify"}},
		{r: [2]byte{0xb3, 0xb3}, s: scalar.S{Sym: "nop4"}},
		{r: [2]byte{0xb4, 0xb4}, s: scalar.S{Sym: "nop5"}},
		{r: [2]byte{0xb5, 0xb5}, s: scalar.S{Sym: "nop6"}},
		{r: [2]byte{0xb6, 0xb6}, s: scalar.S{Sym: "nop7"}},
		{r: [2]byte{0xb7, 0xb7}, s: scalar.S{Sym: "nop8"}},
		{r: [2]byte{0xb8, 0xb8}, s: scalar.S{Sym: "nop9"}},
		{r: [2]byte{0xb9, 0xb9}, s: scalar.S{Sym: "nop10"}},
		{r: [2]byte{0xba, 0xba}, s: scalar.S{Sym: "checkdatasig"}},
		{r: [2]byte{0xbb, 0xbb}, s: scalar.S{Sym: "checkdatasigverif"}},
		{r: [2]byte{0xfa, 0xfa}, s: scalar.S{Sym: "smallinteger"}},
		{r: [2]byte{0xfb, 0xfb}, s: scalar.S{Sym: "pubkeys"}},
		{r: [2]byte{0xfc, 0xfc}, s: scalar.S{Sym: "unknown252"}},
		{r: [2]byte{0xfd, 0xfd}, s: scalar.S{Sym: "pubkeyhash"}},
		{r: [2]byte{0xfe, 0xfe}, s: scalar.S{Sym: "pubkey"}},
		{r: [2]byte{0xff, 0xff}, s: scalar.S{Sym: "invalidopcode"}},
	}

	for !d.End() {
		opcode := byte(d.PeekBits(8))
		ope, ok := opcodeEntries.lookup(opcode)
		if !ok {
			d.Fatalf("unknown opcode %x", opcode)
		}

		d.FieldStruct("opcode", func(d *decode.D) {
			d.FieldU8("op", opcodeEntries)
			if ope.d != nil {
				ope.d(d, opcode)
			}
		})
	}

	return nil
}

/*

OP_0, OP_FALSE	0	0x00	Nothing.	(empty value)	An empty array of bytes is pushed onto the stack. (This is not a no-op: an item is added to the stack.)
N/A	1-75	0x01-0x4b	(special)	data	The next opcode bytes is data to be pushed onto the stack
OP_PUSHDATA1	76	0x4c	(special)	data	The next byte contains the number of bytes to be pushed onto the stack.
OP_PUSHDATA2	77	0x4d	(special)	data	The next two bytes contain the number of bytes to be pushed onto the stack in little endian order.
OP_PUSHDATA4	78	0x4e	(special)	data	The next four bytes contain the number of bytes to be pushed onto the stack in little endian order.
OP_1NEGATE	79	0x4f	Nothing.	-1	The number -1 is pushed onto the stack.
OP_1, OP_TRUE	81	0x51	Nothing.	1	The number 1 is pushed onto the stack.
OP_2-OP_16	82-96	0x52-0x60	Nothing.	2-16	The number in the word name (2-16) is pushed onto the stack.

OP_NOP	97	0x61	Nothing	Nothing	Does nothing.
OP_IF	99	0x63	<expression> if [statements] [else [statements]]* endif	If the top stack value is not False, the statements are executed. The top stack value is removed.
OP_NOTIF	100	0x64	<expression> notif [statements] [else [statements]]* endif	If the top stack value is False, the statements are executed. The top stack value is removed.
OP_ELSE	103	0x67	<expression> if [statements] [else [statements]]* endif	If the preceding OP_IF or OP_NOTIF or OP_ELSE was not executed then these statements are and if the preceding OP_IF or OP_NOTIF or OP_ELSE was executed then these statements are not.
OP_ENDIF	104	0x68	<expression> if [statements] [else [statements]]* endif	Ends an if/else block. All blocks must end, or the transaction is invalid. An OP_ENDIF without OP_IF earlier is also invalid.
OP_VERIFY	105	0x69	True / false	Nothing / fail	Marks transaction as invalid if top stack value is not true. The top stack value is removed.
OP_RETURN	106	0x6a	Nothing	fail	Marks transaction as invalid. Since bitcoin 0.9, a standard way of attaching extra data to transactions is to add a zero-value output with a scriptPubKey consisting of OP_RETURN followed by data. Such outputs are provably unspendable and specially discarded from storage in the UTXO set, reducing their cost to the network. Since 0.12, standard relay rules allow a single output with OP_RETURN, that contains any sequence of push statements (or OP_RESERVED[1]) after the OP_RETURN provided the total scriptPubKey length is at most 83 bytes.

OP_TOALTSTACK	107	0x6b	x1	(alt)x1	Puts the input onto the top of the alt stack. Removes it from the main stack.
OP_FROMALTSTACK	108	0x6c	(alt)x1	x1	Puts the input onto the top of the main stack. Removes it from the alt stack.
OP_IFDUP	115	0x73	x	x / x x	If the top stack value is not 0, duplicate it.
OP_DEPTH	116	0x74	Nothing	<Stack size>	Puts the number of stack items onto the stack.
OP_DROP	117	0x75	x	Nothing	Removes the top stack item.
OP_DUP	118	0x76	x	x x	Duplicates the top stack item.
OP_NIP	119	0x77	x1 x2	x2	Removes the second-to-top stack item.
OP_OVER	120	0x78	x1 x2	x1 x2 x1	Copies the second-to-top stack item to the top.
OP_PICK	121	0x79	xn ... x2 x1 x0 <n>	xn ... x2 x1 x0 xn	The item n back in the stack is copied to the top.
OP_ROLL	122	0x7a	xn ... x2 x1 x0 <n>	... x2 x1 x0 xn	The item n back in the stack is moved to the top.
OP_ROT	123	0x7b	x1 x2 x3	x2 x3 x1	The 3rd item down the stack is moved to the top.
OP_SWAP	124	0x7c	x1 x2	x2 x1	The top two items on the stack are swapped.
OP_TUCK	125	0x7d	x1 x2	x2 x1 x2	The item at the top of the stack is copied and inserted before the second-to-top item.
OP_2DROP	109	0x6d	x1 x2	Nothing	Removes the top two stack items.
OP_2DUP	110	0x6e	x1 x2	x1 x2 x1 x2	Duplicates the top two stack items.
OP_3DUP	111	0x6f	x1 x2 x3	x1 x2 x3 x1 x2 x3	Duplicates the top three stack items.
OP_2OVER	112	0x70	x1 x2 x3 x4	x1 x2 x3 x4 x1 x2	Copies the pair of items two spaces back in the stack to the front.
OP_2ROT	113	0x71	x1 x2 x3 x4 x5 x6	x3 x4 x5 x6 x1 x2	The fifth and sixth items back are moved to the top of the stack.
OP_2SWAP	114	0x72	x1 x2 x3 x4	x3 x4 x1 x2	Swaps the top two pairs of items.

OP_CAT	126	0x7e	x1 x2	out	Concatenates two strings. disabled.
OP_SUBSTR	127	0x7f	in begin size	out	Returns a section of a string. disabled.
OP_LEFT	128	0x80	in size	out	Keeps only characters left of the specified point in a string. disabled.
OP_RIGHT	129	0x81	in size	out	Keeps only characters right of the specified point in a string. disabled.
OP_SIZE	130	0x82	in	in size	Pushes the string length of the top element of the stack (without popping it).

OP_INVERT	131	0x83	in	out	Flips all of the bits in the input. disabled.
OP_AND	132	0x84	x1 x2	out	Boolean and between each bit in the inputs. disabled.
OP_OR	133	0x85	x1 x2	out	Boolean or between each bit in the inputs. disabled.
OP_XOR	134	0x86	x1 x2	out	Boolean exclusive or between each bit in the inputs. disabled.
OP_EQUAL	135	0x87	x1 x2	True / false	Returns 1 if the inputs are exactly equal, 0 otherwise.
OP_EQUALVERIFY	136	0x88	x1 x2	Nothing / fail	Same as OP_EQUAL, but runs OP_VERIFY afterward.

OP_1ADD	139	0x8b	in	out	1 is added to the input.
OP_1SUB	140	0x8c	in	out	1 is subtracted from the input.
OP_2MUL	141	0x8d	in	out	The input is multiplied by 2. disabled.
OP_2DIV	142	0x8e	in	out	The input is divided by 2. disabled.
OP_NEGATE	143	0x8f	in	out	The sign of the input is flipped.
OP_ABS	144	0x90	in	out	The input is made positive.
OP_NOT	145	0x91	in	out	If the input is 0 or 1, it is flipped. Otherwise the output will be 0.
OP_0NOTEQUAL	146	0x92	in	out	Returns 0 if the input is 0. 1 otherwise.
OP_ADD	147	0x93	a b	out	a is added to b.
OP_SUB	148	0x94	a b	out	b is subtracted from a.
OP_MUL	149	0x95	a b	out	a is multiplied by b. disabled.
OP_DIV	150	0x96	a b	out	a is divided by b. disabled.
OP_MOD	151	0x97	a b	out	Returns the remainder after dividing a by b. disabled.
OP_LSHIFT	152	0x98	a b	out	Shifts a left b bits, preserving sign. disabled.
OP_RSHIFT	153	0x99	a b	out	Shifts a right b bits, preserving sign. disabled.
OP_BOOLAND	154	0x9a	a b	out	If both a and b are not 0, the output is 1. Otherwise 0.
OP_BOOLOR	155	0x9b	a b	out	If a or b is not 0, the output is 1. Otherwise 0.
OP_NUMEQUAL	156	0x9c	a b	out	Returns 1 if the numbers are equal, 0 otherwise.
OP_NUMEQUALVERIFY	157	0x9d	a b	Nothing / fail	Same as OP_NUMEQUAL, but runs OP_VERIFY afterward.
OP_NUMNOTEQUAL	158	0x9e	a b	out	Returns 1 if the numbers are not equal, 0 otherwise.
OP_LESSTHAN	159	0x9f	a b	out	Returns 1 if a is less than b, 0 otherwise.
OP_GREATERTHAN	160	0xa0	a b	out	Returns 1 if a is greater than b, 0 otherwise.
OP_LESSTHANOREQUAL	161	0xa1	a b	out	Returns 1 if a is less than or equal to b, 0 otherwise.
OP_GREATERTHANOREQUAL	162	0xa2	a b	out	Returns 1 if a is greater than or equal to b, 0 otherwise.
OP_MIN	163	0xa3	a b	out	Returns the smaller of a and b.
OP_MAX	164	0xa4	a b	out	Returns the larger of a and b.
OP_WITHIN	165	0xa5	x min max	out	Returns 1 if x is within the specified range (left-inclusive), 0 otherwise.

OP_RIPEMD160	166	0xa6	in	hash	The input is hashed using RIPEMD-160.
OP_SHA1	167	0xa7	in	hash	The input is hashed using SHA-1.
OP_SHA256	168	0xa8	in	hash	The input is hashed using SHA-256.
OP_HASH160	169	0xa9	in	hash	The input is hashed twice: first with SHA-256 and then with RIPEMD-160.
OP_HASH256	170	0xaa	in	hash	The input is hashed two times with SHA-256.
OP_CODESEPARATOR	171	0xab	Nothing	Nothing	All of the signature checking words will only match signatures to the data after the most recently-executed OP_CODESEPARATOR.
OP_CHECKSIG	172	0xac	sig pubkey	True / false	The entire transaction's outputs, inputs, and script (from the most recently-executed OP_CODESEPARATOR to the end) are hashed. The signature used by OP_CHECKSIG must be a valid signature for this hash and public key. If it is, 1 is returned, 0 otherwise.
OP_CHECKSIGVERIFY	173	0xad	sig pubkey	Nothing / fail	Same as OP_CHECKSIG, but OP_VERIFY is executed afterward.
OP_CHECKMULTISIG	174	0xae	x sig1 sig2 ... <number of signatures> pub1 pub2 <number of public keys>	True / False	Compares the first signature against each public key until it finds an ECDSA match. Starting with the subsequent public key, it compares the second signature against each remaining public key until it finds an ECDSA match. The process is repeated until all signatures have been checked or not enough public keys remain to produce a successful result. All signatures need to match a public key. Because public keys are not checked again if they fail any signature comparison, signatures must be placed in the scriptSig using the same order as their corresponding public keys were placed in the scriptPubKey or redeemScript. If all signatures are valid, 1 is returned, 0 otherwise. Due to a bug, one extra unused value is removed from the stack.
OP_CHECKMULTISIGVERIFY	175	0xaf	x sig1 sig2 ... <number of signatures> pub1 pub2 ... <number of public keys>	Nothing / fail	Same as OP_CHECKMULTISIG, but OP_VERIFY is executed afterward.

OP_CHECKLOCKTIMEVERIFY (previously OP_NOP2)	177	0xb1	x	x / fail	Marks transaction as invalid if the top stack item is greater than the transaction's nLockTime field, otherwise script evaluation continues as though an OP_NOP was executed. Transaction is also invalid if 1. the stack is empty; or 2. the top stack item is negative; or 3. the top stack item is greater than or equal to 500000000 while the transaction's nLockTime field is less than 500000000, or vice versa; or 4. the input's nSequence field is equal to 0xffffffff. The precise semantics are described in BIP 0065.
OP_CHECKSEQUENCEVERIFY (previously OP_NOP3)	178	0xb2	x	x / fail	Marks transaction as invalid if the relative lock time of the input (enforced by BIP 0068 with nSequence) is not equal to or longer than the value of the top stack item. The precise semantics are described in BIP 0112.

OP_PUBKEYHASH	253	0xfd	Represents a public key hashed with OP_HASH160.
OP_PUBKEY	254	0xfe	Represents a public key compatible with OP_CHECKSIG.
OP_INVALIDOPCODE	255	0xff	Matches any opcode that is not yet assigned.

OP_RESERVED	80	0x50	Transaction is invalid unless occuring in an unexecuted OP_IF branch
OP_VER	98	0x62	Transaction is invalid unless occuring in an unexecuted OP_IF branch
OP_VERIF	101	0x65	Transaction is invalid even when occuring in an unexecuted OP_IF branch
OP_VERNOTIF	102	0x66	Transaction is invalid even when occuring in an unexecuted OP_IF branch
OP_RESERVED1	137	0x89	Transaction is invalid unless occuring in an unexecuted OP_IF branch
OP_RESERVED2	138	0x8a	Transaction is invalid unless occuring in an unexecuted OP_IF branch
OP_NOP1, OP_NOP4-OP_NOP10	176, 179-185	0xb0, 0xb3-0xb9	The word is ignored. Does not mark transaction as invalid.

*/
