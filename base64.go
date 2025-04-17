package base64

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unsafe"
)

// Error is a base64 error.
type Error string

// Error returns error as a string.
func (e Error) Error() string {
	return string(e)
}

// ErrInvalid sentinel error
const ErrInvalid Error = "base64"

// ErrDecode is returned by decoding methods and provide the offset of the error.
type ErrDecode struct {
	err error
	pos int
}

// newDecodeError returns an error with an offset.
func newDecodeError(err error, pos int) error {
	return ErrDecode{err: err, pos: pos}
}

// Offset returns the offset of the error.
func (e ErrDecode) Offset() int {
	return e.pos
}

// Unwrap extracts the parent error.
func (e ErrDecode) Unwrap() error {
	return e.err
}

// Error returns the error as a string.
func (e ErrDecode) Error() string {
	var buf strings.Builder
	buf.WriteString(e.err.Error())
	buf.WriteString(" at ")
	buf.WriteString(strconv.Itoa(e.pos))
	return buf.String()
}

var ErrBadCharacter = fmt.Errorf("%w: bad character", ErrInvalid)
var ErrBadBitPadding = fmt.Errorf("%w: bad bit padding", ErrInvalid)
var ErrBadPadding = fmt.Errorf("%w: bad padding", ErrInvalid)
var ErrBadLength = fmt.Errorf("%w: bad length", ErrInvalid)

// An Encoding is a radix 64 encoding/decoding scheme, defined by a
// 64-character alphabet. The most common encoding is the "base64"
// encoding defined in RFC 4648 and used in MIME (RFC 2045) and PEM
// (RFC 1421).  RFC 4648 also defines an alternate encoding, which is
// the standard encoding with - and _ substituted for + and /.
type Encoding struct {
	encodeMap [64]byte  // encoding byte map
	decodeMap [256]byte // decoding byte map
	padding   rune      // StdPadding, NoPadding, or user defined byte
	lax       bool      // don’t check padding bits when true
	ignore    bool      // true if there are characters to ignore
}

type BitPadding bool

const (
	NoPadding  rune       = -1     // No padding characters are appended.
	StdPadding rune       = '='    // Appends the padding character '='.
	Strict     BitPadding = false  // Requires zero padding bits.
	Lax        BitPadding = true   // Ignores padding bits.
	Ignore     byte       = 1 << 6 // Code of character to ignore.
	Invalid    byte       = 2 << 6 // Code of invalid character.
	padCode    byte       = 3 << 6 // Code of padding character.
	badCode    byte       = 3 << 6 // bad code mask.
)

// NewEncoding returns a new base64 encoding using the given 64 letter alphabet.
// The decoding rule tells which byte should be ignored of considered invalid.
// Use MakeDecodingRule to create a decoding rule. The padding defines the
// padding character. It may be StdPadding ('='), NoPadding, or a user
// specified padding character whose value must be smaller than 128.
// The bitPadding checking rule is Strict or Lax. When strict, it is an error
// when the padding bits are not zero. When lax, they are not checked. Strict
// should be used by default for security.
func NewEncoding(alphabet string, ignore []byte, padding rune, bitPadding BitPadding) (*Encoding, error) {
	if ignore == nil {
		ignore = IgnoreNone
	}
	if padding > 127 {
		return nil, fmt.Errorf("%w padding: invalid padding character %v", ErrInvalid, padding)
	}
	if len(alphabet) != 64 {
		return nil, fmt.Errorf("%w alphabet: expect 64 bytes, got %d", ErrInvalid, len(alphabet))
	}
	if len(ignore) != 256 {
		return nil, fmt.Errorf("%w ignore: expect 256 bytes, got %d", ErrInvalid, len(ignore))
	}
	for i, c := range alphabet {
		if c >= 127 {
			return nil, fmt.Errorf("%w alphabet: letter %d is invalid", ErrInvalid, i)
		}
	}
	var hasIgnore bool
	for i, c := range ignore {
		if c != Ignore && c != Invalid {
			return nil, fmt.Errorf("%w ignore: expect Ignore or Invalid at %d", ErrInvalid, i)
		}
		if c == Ignore {
			hasIgnore = true
		}
	}
	enc := &Encoding{
		padding: padding,
		lax:     bool(bitPadding),
		ignore:  hasIgnore,
	}
	copy(enc.encodeMap[:], alphabet)
	copy(enc.decodeMap[:], ignore)
	for i, c := range enc.encodeMap[:] {
		if enc.decodeMap[c] < Ignore {
			return nil, fmt.Errorf("%w alphabet: duplicate letter %c", ErrInvalid, rune(c))
		}
		enc.decodeMap[c] = byte(i)
	}
	if padding != NoPadding {
		if enc.decodeMap[padding] < 64 {
			return nil, fmt.Errorf("%w padding: the padding letter %v is in the alphabet", ErrInvalid, padding)
		}
		enc.decodeMap[padding] = padCode
	}
	return enc, nil
}

// MustNewEncoding is like NewEncoding, but it panics in case of error.
func MustNewEncoding(alphabet string, ignore []byte, padding rune, bitPadding BitPadding) *Encoding {
	enc, err := NewEncoding(alphabet, ignore, padding, bitPadding)
	if err != nil {
		panic(err)
	}
	return enc
}

// EncodedLen returns the resulting byte length when encoding l bytes.
func (enc *Encoding) EncodedLen(l int) int {
	if enc.padding == NoPadding {
		return (l*8 + 5) / 6
	} else {
		return ((l + 2) / 3) * 4
	}
}

// Encode encodes src into dst. Panics when dst is smaller than the size returned by EncodeLength.
func (enc *Encoding) Encode(dst []byte, src []byte) []byte {
	if len(src) == 0 {
		return dst[:0]
	}
	var i, j int
	c := enc.encodeMap[:64]
	if strconv.IntSize == 64 {
		for l := len(src) - 8; i <= l; i += 6 {
			v := binary.BigEndian.Uint64(src[i:])
			t := dst[j : j+8]
			t[0] = c[v>>58&63]
			t[1] = c[v>>52&63]
			t[2] = c[v>>46&63]
			t[3] = c[v>>40&63]
			t[4] = c[v>>34&63]
			t[5] = c[v>>28&63]
			t[6] = c[v>>22&63]
			t[7] = c[v>>16&63]
			j += 8
		}
	}
	if len(src)-i >= 4 {
		v := binary.BigEndian.Uint32(src[i:])
		t := dst[j : j+4]
		t[0] = c[v>>26&63]
		t[1] = c[v>>20&63]
		t[2] = c[v>>14&63]
		t[3] = c[v>>8&63]
		j += 4
		i += 3
	}
	if len(src)-i >= 3 {
		v := uint32(src[i])<<16 | uint32(binary.BigEndian.Uint16(src[i+1:]))
		t := dst[j : j+4]
		t[0] = c[v>>18&63]
		t[1] = c[v>>12&63]
		t[2] = c[v>>6&63]
		t[3] = c[v&63]
		j += 4
		i += 3
	}
	if len(src)-i == 2 {
		v := uint32(binary.BigEndian.Uint16(src[i:])) << 2
		t := dst[j : j+3]
		t[0] = c[v>>12&63]
		t[1] = c[v>>6&63]
		t[2] = c[v&63]
		j += 3
		i += 2
	} else if len(src)-i == 1 {
		v := uint16(src[i]) << 4
		t := dst[j : j+2]
		t[0] = c[v>>6&0x3F]
		t[1] = c[v&0x3F]
		j += 2
		i += 1
	}
	if enc.padding != NoPadding {
		switch j % 4 {
		case 2:
			dst[j] = byte(enc.padding)
			j++
			fallthrough
		case 3:
			dst[j] = byte(enc.padding)
			j++
		}
	}
	return dst[:j]
}

// AppendEncode appends the encoding of src to dst.
func (enc *Encoding) AppendEncode(dst []byte, src []byte) []byte {
	n := enc.EncodedLen(len(src))
	dst = slices.Grow(dst, n)
	enc.Encode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n]
}

// EncodeToString encodes src into a string.
func (enc *Encoding) EncodeToString(src []byte) string {
	dst := enc.Encode(make([]byte, enc.EncodedLen(len(src))), src)
	return unsafe.String(&dst[0], len(dst))
}

// DecodedLen returns the maximum resulting byte length when decoding l bytes.
func (enc *Encoding) DecodedLen(l int) int {
	if enc.padding == NoPadding {
		return (l * 3) / 4
	}
	return (l / 4) * 3
}

// Decode decodes the base64 encoded src into dst. Panics if dst is not big enough.
// The required size is determined with the DecodedLength method.
func (enc *Encoding) Decode(dst, src []byte) (int, error) {
	if enc.ignore {
		return enc.decodeIgnore(dst, src)
	}
	c := enc.decodeMap[:256]
	if enc.padding != NoPadding {
		n := len(src)
		if n&0x3 != 0 {
			return 0, newDecodeError(ErrBadPadding, len(src))
		}
		if n > 0 && rune(src[n-1]) == enc.padding {
			n--
		}
		if n > 0 && rune(src[n-1]) == enc.padding {
			n--
		}
		src = src[:n]
	}

	var i, j int
	if strconv.IntSize == 64 {
		for range min(len(src)/8, (len(dst)-2)/6) {
			var out uint64
			s := src[i : i+8]
			i += 8
			f := c[s[0]]
			out = out<<6 | uint64(f)
			b := c[s[1]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[2]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[3]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[4]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[5]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[6]]
			out = out<<6 | uint64(b)
			f |= b
			b = c[s[7]]
			out = out<<6 | uint64(b)
			f |= b
			if f&badCode != 0 {
				return j, newDecodeError(ErrBadCharacter, i+enc.offsetInvalid(s))
			}
			binary.BigEndian.PutUint64(dst[j:], out<<16)
			j += +6
		}
		if i == len(src) {
			return j, nil
		}
	}
	n := min((len(src)-i)/4, (len(dst)-j-2)/3)
	for range n {
		var out uint32
		s := src[i : i+4]
		i += 4
		f := c[s[0]]
		out = out<<6 | uint32(f)
		b := c[s[1]]
		out = out<<6 | uint32(b)
		f |= b
		b = c[s[2]]
		out = out<<6 | uint32(b)
		f |= b
		b = c[s[3]]
		out = out<<6 | uint32(b)
		f |= b
		if f&badCode != 0 {
			return j, newDecodeError(ErrBadCharacter, i+enc.offsetInvalid(s))
		}
		binary.BigEndian.PutUint32(dst[j:], out<<8)
		j += 3
	}
	rl := len(src) - i
	if rl == 0 {
		return j, nil
	}
	if rl == 4 {
		var out uint32
		s := src[i : i+4]
		f := c[s[0]]
		out = out<<6 | uint32(f)
		b := c[s[1]]
		out = out<<6 | uint32(b)
		f |= b
		b = c[s[2]]
		out = out<<6 | uint32(b)
		f |= b
		b = c[s[3]]
		out = out<<6 | uint32(b)
		f |= b
		if f&badCode != 0 {
			return j, newDecodeError(ErrBadCharacter, i+enc.offsetInvalid(s))
		}
		d := dst[j : j+3]
		d[0] = byte(out >> 16)
		d[1] = byte(out >> 8)
		d[2] = byte(out)
		return j + 3, nil
	}
	if rl == 3 {
		var out uint32
		s := src[i : i+3]
		f := c[s[0]]
		out = out<<6 | uint32(f)
		b := c[s[1]]
		out = out<<6 | uint32(b)
		f |= b
		b = c[s[2]]
		out = out<<6 | uint32(b)
		f |= b
		if f&badCode != 0 {
			return j, newDecodeError(ErrBadCharacter, i+enc.offsetInvalid(s))
		}
		if !enc.lax && out&3 != 0 {
			return j, newDecodeError(ErrBadBitPadding, i+2)
		}
		binary.BigEndian.PutUint16(dst[j:], uint16(out>>2))
		return j + 2, nil
	}
	if rl == 2 {
		var out uint16
		s := src[i : i+2]
		f := c[s[0]]
		out = out<<6 | uint16(f)
		b := c[s[1]]
		out = out<<6 | uint16(b)
		f |= b
		if f&badCode != 0 {
			return j, newDecodeError(ErrBadCharacter, i+enc.offsetInvalid(s))
		}
		if !enc.lax && out&15 != 0 {
			return j, newDecodeError(ErrBadBitPadding, i+1)
		}
		dst[j] = byte(out >> 4)
		return j + 1, nil
	}
	return j, newDecodeError(ErrBadLength, len(src))
}

// decodeIgnore is like Decode but it has characters to ignore. It returns an ErrOffset. decodes src into dst and returns the number of bytes written and read.
// When error is not nil, the number of bytes read is the offset in src of the
// character that caused the error.
func (enc *Encoding) decodeIgnore(dst, src []byte) (int, error) {
	var i, j int
	if len(src) == 0 {
		return 0, nil
	}
	var b0, b1, b2, b3 byte
	var abort bool
	var v uint64
	c := enc.decodeMap[0:256]
	if strconv.IntSize == 64 {
		iMax := len(src) - 8
		jMax := len(dst) - 8
		for i <= iMax && j <= jMax {
			b := src[i : i+8]
			m := c[b[0]]
			f := m
			v = uint64(m)
			m = c[b[1]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[2]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[3]]
			f |= m
			v = v<<6 | uint64(m)
			g := f
			m = c[b[4]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[5]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[6]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[7]]
			f |= m
			v = v<<6 | uint64(m)
			v <<= 16
			if f&badCode == 0 {
				binary.BigEndian.PutUint64(dst[j:], v)
				i += 8
				j += 6
				continue
			}
			if g&badCode == 0 {
				binary.BigEndian.PutUint32(dst[j:], uint32(v>>32))
				i += 4
				j += 3
			}
			b0, i = enc.readSkip(src, i)
			v = uint64(b0 & 0x3F)
			b1, i = enc.readSkip(src, i)
			v = v<<6 | uint64(b1&0x3F)
			b2, i = enc.readSkip(src, i)
			v = v<<6 | uint64(b2&0x3F)
			b3, i = enc.readSkip(src, i)
			v = v<<6 | uint64(b3&0x3F)
			if abort = (b0|b1|b2|b3)&badCode != 0; abort {
				// we met the end of src, an invalid character or a padding characters
				break
			}
			binary.BigEndian.PutUint32(dst[j:], uint32(v<<8))
			j += 3
		}
	}
	if !abort {
		if i == len(src) {
			return j, nil
		}
		iMax := len(src) - 4
		for i <= iMax {
			b := src[i : i+4]
			m := c[b[0]]
			f := m
			v = uint64(m)
			m = c[b[1]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[2]]
			f |= m
			v = v<<6 | uint64(m)
			m = c[b[3]]
			f |= m
			v = v<<6 | uint64(m)
			if f&badCode == 0 {
				i += 4
			} else {
				b0, i = enc.readSkip(src, i)
				v = uint64(b0 & 0x3F)
				b1, i = enc.readSkip(src, i)
				v = v<<6 | uint64(b1&0x3F)
				b2, i = enc.readSkip(src, i)
				v = v<<6 | uint64(b2&0x3F)
				b3, i = enc.readSkip(src, i)
				v = v<<6 | uint64(b3&0x3F)
				if abort = (b0|b1|b2|b3)&badCode != 0; abort {
					// we met the end of src, an invalid character or padding characters
					break
				}
			}
			b = dst[j : j+3]
			b[0] = byte(v >> 16)
			b[1] = byte(v >> 8)
			b[2] = byte(v)
			j += 3
		}
	}
	if !abort {
		if i == len(src) {
			return j, nil
		}
		b0, i = enc.readSkip(src, i)
		v = uint64(b0 & 0x3F)
		b1, i = enc.readSkip(src, i)
		v = v<<6 | uint64(b1&0x3F)
		b2, i = enc.readSkip(src, i)
		v = v<<6 | uint64(b2&0x3F)
		b3, i = enc.readSkip(src, i)
		v = v<<6 | uint64(b3&0x3F)
	}
	if b3 == Invalid {
		return j, newDecodeError(ErrBadCharacter, i)
	}
	if b0 == Ignore {
		return j, nil
	}
	if enc.padding != NoPadding {
		if b3 != padCode || i != len(src) {
			return j, newDecodeError(ErrBadPadding, i)
		}
		if b0 == padCode || b1 == padCode {
			return j, newDecodeError(ErrBadPadding, i)
		}
		// fallback to no padding decoding
		b3 = Ignore
		if b2 == padCode {
			b2 = Ignore
		}
	} else if b1 == Ignore || b3 != Ignore {
		return j, newDecodeError(ErrBadLength, i)
	}
	if b2 == Ignore {
		v >>= 12
		if !enc.lax && v&0xf != 0 {
			if enc.padding != NoPadding {
				i -= 2
			}
			return j, newDecodeError(ErrBadBitPadding, i-1)
		}
		dst[j] = byte(v >> 4)
		return j + 1, nil
	}
	v >>= 6
	if !enc.lax && v&0x3 != 0 {
		if enc.padding != NoPadding {
			i -= 1
		}
		return j, newDecodeError(ErrBadBitPadding, i-1)
	}
	v >>= 2
	b := dst[j : j+2]
	b[0] = byte(v >> 8)
	b[1] = byte(v)
	return j + 2, nil
}

// readSkip returns the next valid character or padCode with the index just after it,
// skipping characters to ignore. It returns Ignore and len(src) when the end of src
// is reached. Returns Invalid and its index when an invalid character is met.
func (enc *Encoding) readSkip(src []byte, i int) (byte, int) {
	c := enc.decodeMap[:256]
	for i < len(src) {
		m := c[src[i]]
		if m == Invalid {
			// blocks on invalid character
			return m, i
		}
		i++
		if m != Ignore {
			// consumes valid and padding characters
			return m, i
		}
	}
	// blocks on end of src and return Ignore code
	return Ignore, i
}

// AppendDecode appends the decoded src to dst and returns the number of bytes read.
// When error is not nil, the number is the offset in src to the character that caused
// the error.
func (enc *Encoding) AppendDecode(dst, src []byte) ([]byte, error) {
	n := len(src)
	if enc.padding != NoPadding {
		for n > 0 && rune(src[n-1]) == enc.padding {
			n--
		}
	}
	n = (n * 6) / 8
	dst = slices.Grow(dst, n)
	n, err := enc.Decode(dst[len(dst):][:n], src)
	return dst[:len(dst)+n], err
}

// StdAlphabet is the standard base64 alphabet (see RFC4648).
const StdAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// URLAlphabet is an url compatible alphabet (see RFC4648).
const URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// MakeIgnore constructs an ignoring rule map. All the map is set to value b (Invalid or Ignore),
// o lists the indexes with the opposite value.
func MakeIgnore(b byte, inverse ...byte) []byte {
	if b != Invalid && b != Ignore {
		panic("invalid decoding rule value")
	}
	s := make([]byte, 256)
	for i := range s {
		s[i] = b
	}
	if b == Invalid {
		b = Ignore
	} else {
		b = Invalid
	}
	for _, c := range inverse {
		s[c] = b
	}
	return s
}

var (
	// Only the alphabet and the padding characters are valid.
	IgnoreNone = MakeIgnore(Invalid)

	// Only the alphabet and the padding characters are valid,
	// and the \n and \r characters are skipped.
	IgnoreNewlinesOnly = MakeIgnore(Invalid, '\n', '\r')

	// All characters not in the alphabet are ignored and skipped.
	IgnoreAll = MakeIgnore(Ignore)
)

var (
	// StdEncoding uses the standard base64 alphabet, skips
	// newlines, and appends = padding.
	StdEncoding = MustNewEncoding(StdAlphabet, IgnoreNewlinesOnly, StdPadding, Strict)

	// RawStdEncoding uses the standard base64 alphabet,
	// skips newlines, and doesn’t append padding.
	RawStdEncoding = MustNewEncoding(StdAlphabet, IgnoreNewlinesOnly, NoPadding, Strict)

	// URLEncoding uses the URL compatible base64 alphabet,
	// skips newlines, and appends = padding.
	URLEncoding = MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, StdPadding, Strict)

	// RawURLEncoding uses the URL compatible base64 alphabet,
	// skips newlines, and doesn’t append padding.
	RawURLEncoding = MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, NoPadding, Strict)
)
