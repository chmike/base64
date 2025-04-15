package base64

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func TestError(t *testing.T) {
	err := newDecodeError(ErrBadCharacter, 10)
	if !errors.Is(err, ErrBadCharacter) {
		t.Fatal("expect ErrBadCharacter")
	}
	var errDecode ErrDecode
	if errors.As(err, &errDecode) {
		if errDecode.Offset() != 10 {
			t.Fatalf("expect 10, got %d", errDecode.Offset())
		}
	} else {
		t.Fatal("expect err is ErrDecode")
	}

	exp := "base64: bad character at 10"
	got := err.Error()
	if exp != got {
		t.Fatalf("expect %q, got %q", exp, got)
	}

	if !errors.Is(err, ErrInvalid) {
		t.Fatal("expected invalid error")
	}
}

func TestNewEncoding(t *testing.T) {

	// alphabet with duplicate letters
	dupAlphabet := "ABBBEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	badAlphabet := "éCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	badIgnore := [256]byte{}
	tests := []struct {
		alphabet   string
		ignore     []byte
		padding    rune
		bitPadding BitPadding
		err        bool
	}{
		// 0
		{alphabet: URLAlphabet, ignore: nil, padding: NoPadding, bitPadding: Strict, err: false},
		{alphabet: "", ignore: nil, padding: NoPadding, bitPadding: Strict, err: true},
		{alphabet: URLAlphabet[:10], ignore: nil, padding: NoPadding, bitPadding: Strict, err: true},
		{alphabet: URLAlphabet, ignore: nil, padding: 'é', bitPadding: Strict, err: true},
		{alphabet: URLAlphabet, ignore: IgnoreNone[:10], padding: NoPadding, bitPadding: Strict, err: true},
		// 5
		{alphabet: dupAlphabet, ignore: nil, padding: NoPadding, bitPadding: Strict, err: true},
		{alphabet: badAlphabet, ignore: nil, padding: NoPadding, bitPadding: Strict, err: true},
		{alphabet: URLAlphabet, ignore: nil, padding: 'A', bitPadding: Strict, err: true},
		{alphabet: URLAlphabet, ignore: badIgnore[:], padding: NoPadding, bitPadding: Strict, err: true},
		{alphabet: URLAlphabet, ignore: IgnoreAll, padding: NoPadding, bitPadding: Strict, err: false},
	}

	for i, test := range tests {
		out, err := NewEncoding(test.alphabet, test.ignore, test.padding, test.bitPadding)
		if test.err && err == nil {
			t.Fatalf("%d expect error, got nil", i)
		} else if !test.err && err != nil {
			t.Fatalf("%d expect nil error, got %q", i, err)
		}
		if err != nil && out != nil {
			t.Fatalf("%d expect nil output with error", i)
		} else if err == nil && out == nil {
			t.Fatalf("%d expect output with nil error", i)
		}
	}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expect a panic")
			}
		}()
		MustNewEncoding("", nil, NoPadding, Strict)
		t.Fatal("expect a panic")
	}()

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expect a panic")
			}
		}()
		MakeIgnore(10, '\n')
		t.Fatal("expect a panic")
	}()
}

func TestEncodeLen(t *testing.T) {
	// test without padding
	for i := range 16 {
		expLen := base64.RawURLEncoding.EncodedLen(i)
		gotLen := RawURLEncoding.EncodedLen(i)
		if expLen != gotLen {
			t.Fatalf("for %d expect len %d, got %d", i, expLen, gotLen)
		}
	}

	// test with padding
	for i := range 16 {
		expLen := base64.URLEncoding.EncodedLen(i)
		gotLen := URLEncoding.EncodedLen(i)
		if expLen != gotLen {
			t.Fatalf("for %d expect len %d, got %d", i, expLen, gotLen)
		}
	}
}

func TestRawEncodeStrict(t *testing.T) {

	expBuf := make([]byte, 22)
	gotBuf := make([]byte, 22)
	srcBuf := make([]byte, 11)

	stdEnc := base64.RawURLEncoding.Strict()

	for range 100000 {
		// generate random byte slice of 0 to 11 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%12]
		rand.Read(src)

		// encode
		expRes := expBuf[:stdEnc.EncodedLen(len(src))]
		stdEnc.Encode(expRes, src)

		gotRes := gotBuf[:RawURLEncoding.EncodedLen(len(src))]
		RawURLEncoding.Encode(gotRes, src)

		if len(expRes) != len(gotRes) {
			t.Fatalf("for 0x%s expect len %d got %d", hex.EncodeToString(src), len(expRes), len(gotRes))
		}
		if !bytes.Equal(expRes, gotRes) {
			t.Fatalf("for 0x%s expect %s got %s", hex.EncodeToString(src), string(expRes), string(gotRes))
		}
	}
}

func TestStdEncodeStrict(t *testing.T) {

	expBuf := make([]byte, 22)
	gotBuf := make([]byte, 22)
	srcBuf := make([]byte, 11)

	stdEnc := base64.URLEncoding.Strict()

	for range 100000 {
		// generate random byte slice of 0 to 11 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%12]
		rand.Read(src)

		// encode
		expRes := expBuf[:stdEnc.EncodedLen(len(src))]
		stdEnc.Encode(expRes, src)

		gotRes := gotBuf[:URLEncoding.EncodedLen(len(src))]
		URLEncoding.Encode(gotRes, src)

		if len(expRes) != len(gotRes) {
			t.Fatalf("for 0x%s expect len %d got %d", hex.EncodeToString(src), len(expRes), len(gotRes))
		}
		if !bytes.Equal(expRes, gotRes) {
			t.Fatalf("for 0x%s expect %s got %s", hex.EncodeToString(src), string(expRes), string(gotRes))
		}
	}
}

func TestEncodeMisc(t *testing.T) {
	buf := []byte("base64:")
	buf = RawURLEncoding.AppendEncode(buf, []byte{0, 1, 2})
	exp := "base64:AAEC"
	got := string(buf)
	if exp != got {
		t.Fatalf("expect %q, got %q", exp, got)
	}

	got = RawURLEncoding.EncodeToString([]byte{0, 1, 2})
	exp = "AAEC"
	if exp != got {
		t.Fatalf("expect %q, got %q", exp, got)
	}
}

func TestDecodeLen(t *testing.T) {
	// test without padding
	for i := range 16 {
		expLen := base64.RawURLEncoding.DecodedLen(i)
		gotLen := RawURLEncoding.DecodedLen(i)
		if expLen != gotLen {
			t.Fatalf("for %d expect len %d, got %d", i, expLen, gotLen)
		}
	}

	// test with padding
	for i := range 16 {
		expLen := base64.URLEncoding.DecodedLen(i)
		gotLen := URLEncoding.DecodedLen(i)
		if expLen != gotLen {
			t.Fatalf("for %d expect len %d, got %d", i, expLen, gotLen)
		}
	}
}

func TestRawDecodeIgnoreStrict(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)
	srcBuf := make([]byte, 16)

	stdDec := base64.RawURLEncoding.Strict()
	pkgDec := MustNewEncoding(URLAlphabet, nil, NoPadding, Strict)

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%16]
		rand.Read(src)
		for j := range src {
			src[j] = URLAlphabet[src[j]&63]
		}

		// insert random invalid character 10% of the time at random position
		//var invalid bool
		rand.Read(l[:])
		if l[0] < 25 && len(src) > 0 {
			pos := int(l[0]) % len(src)
			src[pos] = '!'
		}

		// decode
		expN, expErr := stdDec.Decode(expBuf, src)
		gotN, gotErr := pkgDec.Decode(gotBuf, src)

		if expErr != nil && gotErr == nil {
			t.Fatalf("\"%s\" expect error %q, got nil error", src, expErr)
		}
		if expErr == nil && gotErr != nil {
			t.Fatalf("for \"%s\" expect nil error, got %s", src, gotErr)
		}
		if expErr == nil && gotN != expN {
			t.Fatalf("expect %d bytes decoded, got %d", expN, gotN)
		}
		if expErr == nil && !bytes.Equal(expBuf[:expN], gotBuf[:gotN]) {
			t.Fatalf("for \"%s\" expect \"%s\", got \"%s\"", src, hex.EncodeToString(expBuf[:expN]), hex.EncodeToString(gotBuf[:gotN]))
		}
	}
}

func TestStdDecodeIgnoreStrict(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)

	stdDec := base64.URLEncoding.Strict()
	pkgDec := MustNewEncoding(URLAlphabet, nil, StdPadding, Strict)

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		data := make([]byte, l[0]%13)
		// url encode with padding
		src := URLEncoding.AppendEncode(nil, data)

		// insert = character 10% of the time at random position
		rand.Read(l[:])
		if l[0] < 25 && len(src) > 0 {
			pos := int(l[0]) % len(src)
			src[pos] = '='
		}

		rand.Read(l[:])
		if l[0] < 5 && len(src) > 0 {
			src = src[:len(src)-1]
		}

		// decode
		expN, expErr := stdDec.Decode(expBuf, src)
		gotN, gotErr := pkgDec.Decode(gotBuf, src)

		if expErr != nil && gotErr == nil {
			t.Fatalf("\"%s\" expect error %q, got nil error", src, expErr)
		}
		if expErr == nil && gotErr != nil {
			t.Fatalf("for \"%s\" expect nil error, got %s", src, gotErr)
		}
		if expErr == nil && gotN != expN {
			t.Fatalf("expect %d bytes decoded, got %d", expN, gotN)
		}
		if expErr == nil && !bytes.Equal(expBuf[:expN], gotBuf[:gotN]) {
			t.Fatalf("for \"%s\" expect \"%s\", got \"%s\"", src, hex.EncodeToString(expBuf[:expN]), hex.EncodeToString(gotBuf[:gotN]))
		}
	}
}

func TestRawDecodeStrict(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)
	srcBuf := make([]byte, 16)

	stdEnc := base64.RawURLEncoding.Strict()

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%16]
		rand.Read(src)
		for j := range src {
			src[j] = URLAlphabet[src[j]&63]
		}

		// decode
		expN, expErr := stdEnc.Decode(expBuf, src)
		gotN, gotErr := RawURLEncoding.Decode(gotBuf, src)

		if (expErr != nil && gotErr == nil) || (expErr == nil && gotErr != nil) {
			if expErr == nil {
				t.Fatalf("for \"%s\" (%s) expect nil error, got %s", src, hex.EncodeToString(src), gotErr)
			}
			t.Fatalf("\"%s\" (%s) expect error %q, got nil error", src, hex.EncodeToString(src), expErr)
		} else if gotN != expN {
			t.Fatalf("expect %d bytes written, got %d", expN, gotN)
		} else if !bytes.Equal(expBuf[:expN], gotBuf[:gotN]) {
			t.Fatalf("for \"%s\" (%s) expect \"%s\", got \"%s\"", src, hex.EncodeToString(src), hex.EncodeToString(expBuf[:expN]), hex.EncodeToString(gotBuf[:gotN]))
		}
	}
}

func TestStdDecodeStrict(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)
	srcBuf := make([]byte, 16)

	stdEnc := base64.URLEncoding.Strict()

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:(l[0]%4)*4] // len(src) is 0, 4, 8 or 12
		rand.Read(src)
		for j := range src {
			src[j] = URLAlphabet[src[j]&63]
		}
		// add padding
		if len(src) > 0 {
			n := int(l[0]>>3) % 3 // 0, 1 or 2 paddings
			for i := len(src) - n; i < len(src); i++ {
				src[i] = '='
			}
		}

		// decode
		expN, expErr := stdEnc.Decode(expBuf, src)
		gotN, gotErr := URLEncoding.Decode(gotBuf, src)

		if (expErr != nil && gotErr == nil) || (expErr == nil && gotErr != nil) {
			if expErr == nil {
				t.Fatalf("for \"%s\" (%s) expect nil error, got %s", src, hex.EncodeToString(src), gotErr)
			}
			t.Fatalf("\"%s\" (%s) expect error %q, got nil error with 0x%s", src, hex.EncodeToString(src), expErr, hex.EncodeToString(expBuf[:expN]))
		} else if gotN != expN {
			t.Fatalf("for %s expect %d bytes written, got %d", src, expN, gotN)
		} else if !bytes.Equal(expBuf[:expN], gotBuf[:gotN]) {
			t.Fatalf("for \"%s\" (%s) expect \"%s\", got \"%s\"", src, hex.EncodeToString(src), hex.EncodeToString(expBuf[:expN]), hex.EncodeToString(gotBuf[:gotN]))
		}
	}
}

func TestRawEncodeLax(t *testing.T) {

	expBuf := make([]byte, 22)
	gotBuf := make([]byte, 22)
	srcBuf := make([]byte, 11)

	stdEnc := base64.RawURLEncoding
	pkgEnc := MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, NoPadding, Lax)

	for range 100000 {
		// generate random byte slice of 0 to 11 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%12]
		rand.Read(src)

		// encode
		expRes := expBuf[:stdEnc.EncodedLen(len(src))]
		stdEnc.Encode(expRes, src)

		gotRes := gotBuf[:pkgEnc.EncodedLen(len(src))]
		pkgEnc.Encode(gotRes, src)

		if len(expRes) != len(gotRes) {
			t.Fatalf("for 0x%s expect len %d got %d", hex.EncodeToString(src), len(expRes), len(gotRes))
		}
		if !bytes.Equal(expRes, gotRes) {
			t.Fatalf("for 0x%s expect %s got %s", hex.EncodeToString(src), string(expRes), string(gotRes))
		}
	}
}

func TestStdEncodeLax(t *testing.T) {

	expBuf := make([]byte, 22)
	gotBuf := make([]byte, 22)
	srcBuf := make([]byte, 11)

	stdEnc := base64.URLEncoding
	pkgEnc := MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, StdPadding, Lax)

	for range 100000 {
		// generate random byte slice of 0 to 11 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%12]
		rand.Read(src)

		// encode
		expRes := expBuf[:stdEnc.EncodedLen(len(src))]
		stdEnc.Encode(expRes, src)

		gotRes := gotBuf[:pkgEnc.EncodedLen(len(src))]
		pkgEnc.Encode(gotRes, src)

		if len(expRes) != len(gotRes) {
			t.Fatalf("for 0x%s expect len %d got %d", hex.EncodeToString(src), len(expRes), len(gotRes))
		}
		if !bytes.Equal(expRes, gotRes) {
			t.Fatalf("for 0x%s expect %s got %s", hex.EncodeToString(src), string(expRes), string(gotRes))
		}
	}
}

func TestRawDecodeLax(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)
	srcBuf := make([]byte, 16)

	stdEnc := base64.RawURLEncoding
	pkgEnc := MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, NoPadding, Lax)

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:l[0]%16]
		rand.Read(src)
		for j := range src {
			src[j] = URLAlphabet[src[j]&63]
		}

		// decode
		nExp, errExp := stdEnc.Decode(expBuf, src)
		nGot, errGot := pkgEnc.Decode(gotBuf, src)

		if (errExp != nil && errGot == nil) || (errExp == nil && errGot != nil) {
			if errExp == nil {
				t.Fatalf("for \"%s\" (%s) expect nil error, got %s", src, hex.EncodeToString(src), errGot)
			}
			t.Fatalf("\"%s\" (%s) expect error %q, got nil error", src, hex.EncodeToString(src), errExp)
		} else if nGot != nExp {
			t.Fatalf("expect %d bytes written, got %d", nExp, nGot)
		} else if !bytes.Equal(expBuf[:nExp], gotBuf[:nGot]) {
			t.Fatalf("for \"%s\" (%s) expect \"%s\", got \"%s\"", src, hex.EncodeToString(src), hex.EncodeToString(expBuf[:nExp]), hex.EncodeToString(gotBuf[:nGot]))
		}
	}
}

func TestStdDecodeLax(t *testing.T) {

	expBuf := make([]byte, 16)
	gotBuf := make([]byte, 16)
	srcBuf := make([]byte, 16)

	stdEnc := base64.URLEncoding
	pkgEnc := MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, StdPadding, Lax)

	for range 100000 {
		// generate random base64 encoded string of 0 to 15 bytes
		var l [1]byte
		rand.Read(l[:])
		src := srcBuf[:(l[0]%4)*4] // len(src) is 0, 4, 8 or 12
		rand.Read(src)
		for j := range src {
			src[j] = URLAlphabet[src[j]&63]
		}
		// add padding
		if len(src) > 0 {
			n := int(l[0]>>3) % 3 // 0, 1 or 2 paddings
			for i := len(src) - n; i < len(src); i++ {
				src[i] = '='
			}
		}

		// decode
		nExp, errExp := stdEnc.Decode(expBuf, src)
		nGot, errGot := pkgEnc.Decode(gotBuf, src)

		if (errExp != nil && errGot == nil) || (errExp == nil && errGot != nil) {
			if errExp == nil {
				t.Fatalf("for \"%s\" (%s) expect nil error, got %s", src, hex.EncodeToString(src), errGot)
			}
			t.Fatalf("\"%s\" (%s) expect error %q, got nil error", src, hex.EncodeToString(src), errExp)
		} else if nGot != nExp {
			t.Fatalf("expect %d bytes written, got %d", nExp, nGot)
		} else if !bytes.Equal(expBuf[:nExp], gotBuf[:nGot]) {
			t.Fatalf("for \"%s\" (%s) expect \"%s\", got \"%s\"", src, hex.EncodeToString(src), hex.EncodeToString(expBuf[:nExp]), hex.EncodeToString(gotBuf[:nGot]))
		}
	}
}

func TestDecode(t *testing.T) {
	breakpoint := 72
	type decType int

	const (
		rawStrict decType = iota
		stdStrict
		rawLax
		stdLax
	)
	str := [4]string{"rawStrict", "stdStrict", "rawLax", "stdLax"}

	var dec [4]*Encoding
	dec[rawStrict] = RawURLEncoding
	dec[stdStrict] = URLEncoding
	dec[rawLax] = MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, NoPadding, Lax)
	dec[stdLax] = MustNewEncoding(URLAlphabet, IgnoreNewlinesOnly, StdPadding, Lax)

	tests := []struct {
		t      decType
		i, o   string
		nw, nr int
		err    error
		ext    int
	}{
		// 0
		{t: rawLax, i: "", o: ""},
		{t: rawLax, i: "_", o: "", nr: 1, err: ErrBadLength},
		{t: rawLax, i: "__", o: "ff", nw: 1, nr: 2},
		{t: rawLax, i: "_w", o: "ff", nw: 1, nr: 2},
		{t: rawLax, i: "___", o: "ffff", nw: 2, nr: 3},
		{t: rawLax, i: "__8", o: "ffff", nw: 2, nr: 3},
		{t: rawLax, i: "____", o: "ffffff", nw: 3, nr: 4},
		{t: rawLax, i: "_____", o: "ffffff", nw: 3, nr: 5, err: ErrBadLength},
		{t: rawLax, i: "______", o: "ffffffff", nw: 4, nr: 6},
		{t: rawLax, i: "_____w", o: "ffffffff", nw: 4, nr: 6},
		// 10
		{t: rawLax, i: "_______", o: "ffffffffff", nw: 5, nr: 7},
		{t: rawLax, i: "______8", o: "ffffffffff", nw: 5, nr: 7},
		{t: rawLax, i: "________", o: "ffffffffffff", nw: 6, nr: 8},
		{t: rawLax, i: "_________", o: "ffffffffffff", nw: 6, nr: 9, err: ErrBadLength},
		{t: rawLax, i: "__________", o: "ffffffffffffff", nw: 7, nr: 10},
		{t: rawLax, i: "_________w", o: "ffffffffffffff", nw: 7, nr: 10},
		{t: rawLax, i: "___________", o: "ffffffffffffffff", nw: 8, nr: 11},
		{t: rawLax, i: "__________8", o: "ffffffffffffffff", nw: 8, nr: 11},
		{t: rawLax, i: "____________", o: "ffffffffffffffffff", nw: 9, nr: 12},
		{t: rawLax, i: "________________", o: "ffffffffffffffffffffffff", nw: 12, nr: 16},
		// 20
		{t: rawLax, i: "___\n_____________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "______\n__________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "___\r_____________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "__________\n______", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "_____________\n___", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "_______________\n_", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "________________\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawLax, i: "_______________\n_\n\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 19},
		{t: rawLax, i: "_______________\n_\n\n\n\n\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 22},
		{t: rawLax, i: "_____________\n_", o: "ffffffffffffffffffff", nw: 10, nr: 15},
		// 30
		{t: rawStrict, i: "", o: ""},
		{t: rawStrict, i: "_", o: "", nr: 1, err: ErrBadLength},
		{t: rawStrict, i: "__", o: "", nr: 1, err: ErrBadBitPadding},
		{t: rawStrict, i: "_w", o: "ff", nw: 1, nr: 2},
		{t: rawStrict, i: "___", o: "", nr: 2, err: ErrBadBitPadding},
		{t: rawStrict, i: "__8", o: "ffff", nw: 2, nr: 3},
		{t: rawStrict, i: "____", o: "ffffff", nw: 3, nr: 4},
		{t: rawStrict, i: "_____", o: "ffffff", nw: 3, nr: 5, err: ErrBadLength},
		{t: rawStrict, i: "______", o: "ffffff", nw: 3, nr: 5, err: ErrBadBitPadding},
		{t: rawStrict, i: "_____w", o: "ffffffff", nw: 4, nr: 6},
		// 40
		{t: rawStrict, i: "_______", o: "ffffff", nw: 3, nr: 6, err: ErrBadBitPadding},
		{t: rawStrict, i: "______8", o: "ffffffffff", nw: 5, nr: 7},
		{t: rawStrict, i: "________", o: "ffffffffffff", nw: 6, nr: 8},
		{t: rawStrict, i: "_________", o: "ffffffffffff", nw: 6, nr: 9, err: ErrBadLength},
		{t: rawStrict, i: "__________", o: "ffffffffffff", nw: 6, nr: 9, err: ErrBadBitPadding},
		{t: rawStrict, i: "_________w", o: "ffffffffffffff", nw: 7, nr: 10},
		{t: rawStrict, i: "___________", o: "ffffffffffff", nw: 6, nr: 10, err: ErrBadBitPadding},
		{t: rawStrict, i: "__________8", o: "ffffffffffffffff", nw: 8, nr: 11},
		{t: rawStrict, i: "____________", o: "ffffffffffffffffff", nw: 9, nr: 12},
		{t: rawStrict, i: "________________", o: "ffffffffffffffffffffffff", nw: 12, nr: 16},
		// 50
		{t: rawStrict, i: "___\n_____________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "______\n__________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "___\r_____________", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "__________\n______", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "_____________\n___", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "_______________\n_", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "________________\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 17},
		{t: rawStrict, i: "_______________\n_\n\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 19},
		{t: rawStrict, i: "_______________\n_\n\n\n\n\n", o: "ffffffffffffffffffffffff", nw: 12, nr: 22},
		{t: rawStrict, i: "_____________\nw", o: "ffffffffffffffffffff", nw: 10, nr: 15},
		// 60
		{t: stdLax, i: "", o: ""},
		{t: stdLax, i: "_", o: "", nr: 1, err: ErrBadPadding},
		{t: stdLax, i: "__", o: "", nr: 2, err: ErrBadPadding},
		{t: stdLax, i: "_w", o: "", nr: 2, err: ErrBadPadding},
		{t: stdLax, i: "___", o: "", nr: 3, err: ErrBadPadding},
		{t: stdLax, i: "__8", o: "", nr: 3, err: ErrBadPadding},
		{t: stdLax, i: "____", o: "ffffff", nw: 3, nr: 4},
		{t: stdLax, i: "====", o: "", nr: 4, err: ErrBadPadding},
		{t: stdLax, i: "_===", o: "", nr: 4, err: ErrBadPadding},
		{t: stdLax, i: "_w=", o: "", nr: 3, err: ErrBadPadding},
		// 70
		{t: stdLax, i: "_w==", o: "ff", nw: 1, nr: 4},
		{t: stdLax, i: "_w=x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdLax, i: "_w==x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdLax, i: "__==", o: "ff", nw: 1, nr: 4},
		{t: stdLax, i: "__8=", o: "ffff", nw: 2, nr: 4},
		{t: stdLax, i: "__8?", o: "", nw: 0, nr: 3, err: ErrBadCharacter},
		{t: stdLax, i: "__8=x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdLax, i: "___=", o: "ffff", nw: 2, nr: 4},
		{t: stdLax, i: "_____w==", o: "ffffffff", nw: 4, nr: 8},
		{t: stdLax, i: "______8=", o: "ffffffffff", nw: 5, nr: 8},
		// 80
		{t: stdStrict, i: "", o: ""},
		{t: stdStrict, i: "_", o: "", nr: 1, err: ErrBadPadding},
		{t: stdStrict, i: "__", o: "", nr: 2, err: ErrBadPadding},
		{t: stdStrict, i: "_w", o: "", nr: 2, err: ErrBadPadding},
		{t: stdStrict, i: "___", o: "", nr: 3, err: ErrBadPadding},
		{t: stdStrict, i: "__8", o: "", nr: 3, err: ErrBadPadding},
		{t: stdStrict, i: "____", o: "ffffff", nw: 3, nr: 4},
		{t: stdStrict, i: "====", o: "", nr: 4, err: ErrBadPadding},
		{t: stdStrict, i: "_===", o: "", nr: 4, err: ErrBadPadding},
		{t: stdStrict, i: "_w=", o: "", nr: 3, err: ErrBadPadding},
		// 90
		{t: stdStrict, i: "_w==", o: "ff", nw: 1, nr: 4},
		{t: stdStrict, i: "_w=x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdStrict, i: "_w==x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdStrict, i: "__==", o: "", nw: 0, nr: 1, err: ErrBadBitPadding},
		{t: stdStrict, i: "__8=", o: "ffff", nw: 2, nr: 4},
		{t: stdStrict, i: "__8?", o: "", nw: 0, nr: 3, err: ErrBadCharacter},
		{t: stdStrict, i: "__8=x", o: "", nw: 0, nr: 4, err: ErrBadPadding},
		{t: stdStrict, i: "___=", o: "", nw: 0, nr: 2, err: ErrBadBitPadding},
		{t: stdStrict, i: "_____w==", o: "ffffffff", nw: 4, nr: 8},
		{t: stdStrict, i: "______8=", o: "ffffffffff", nw: 5, nr: 8},
		// 100
		{t: stdStrict, i: "___+________", o: "", nw: 0, nr: 3, err: ErrBadCharacter},
		{t: stdStrict, i: "________", ext: 2, o: "ffffffffffff", nw: 6, nr: 8},
	}

	for i, test := range tests {
		var fail bool
		buf := make([]byte, dec[test.t].DecodedLen(len(test.i))+test.ext)
		print(i, " ")
		if i == len(tests)-1 {
			println()
		}
		if i == breakpoint {
			print("")
		}
		nw, err := dec[test.t].Decode(buf, []byte(test.i))
		if nw != test.nw {
			t.Errorf("expect nw %d, got %d", test.nw, nw)
			fail = true
		}
		if !errors.Is(err, test.err) {
			if test.err != nil && err != nil {
				t.Errorf("expect err %q, got %q", test.err, err)
				fail = true
			} else if test.err == nil {
				t.Errorf("expect nil error, got %q", err)
				fail = true
			} else {
				t.Errorf("expect error %q, got nil", test.err)
				fail = true
			}
			var errDecode ErrDecode
			if !errors.As(err, &errDecode) {
				t.Errorf("expect decode error ")
				fail = true
			} else {
				if test.nr != errDecode.Offset() {
					t.Errorf("expect offset %d, got %d", test.nr, errDecode.Offset())
				}
			}
		}
		if out := hex.EncodeToString(buf[:nw]); out != test.o {
			t.Errorf("expect 0x%s, got 0x%s", test.o, out)
			fail = true
		}
		if fail {
			if test.err == nil {
				t.Logf("%3d %s i:%q o:%q nw:%d nr:%d err: nil failed", i, str[test.t], test.i, test.o, test.nw, test.nr)
			} else {
				t.Logf("%3d %s i:%q o:%q nw:%d nr:%d err:%q failed", i, str[test.t], test.i, test.o, test.nw, test.nr, test.err)
			}
			t.Log("-----------------------------")
		}
	}
}

func TestDecodeMisc(t *testing.T) {
	buf := []byte{1, 2, 3}
	src := "AAEC"
	buf, err := RawURLEncoding.AppendDecode(buf, []byte(src))
	if err != nil {
		t.Fatal("expect nil error")
	}
	exp := []byte{1, 2, 3, 0, 1, 2}
	if !bytes.Equal(buf, exp) {
		t.Fatalf("for %q expect %q, got %q", src, hex.EncodeToString(exp), hex.EncodeToString(buf))
	}

	buf = []byte{1, 2, 3}
	src = "AAECDA=="
	buf, err = URLEncoding.AppendDecode(buf, []byte(src))
	if err != nil {
		t.Fatalf("expect nil error, got %q", err)
	}
	exp = []byte{1, 2, 3, 0, 1, 2, 12}
	if !bytes.Equal(buf, exp) {
		t.Fatalf("for %q expect %q, got %q", src, hex.EncodeToString(exp), hex.EncodeToString(buf))
	}
}

func BenchmarkRawDecodeNoSkip(b *testing.B) {

	data := make([]byte, 10240)
	rand.Read(data)
	data[len(data)-1] &= 0xF0
	buf := make([]byte, (len(data)*6)/8)
	for i := range data {
		data[i] = URLAlphabet[data[i]&63]
	}
	stddec := base64.RawURLEncoding.Strict()
	pkgdec := MustNewEncoding(URLAlphabet, IgnoreNone, NoPadding, Strict)

	// bench stdlib base64
	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			stddec.Decode(buf, data)
		}
	})

	// bench decode
	b.Run("decode", func(b *testing.B) {
		for b.Loop() {
			pkgdec.Decode(buf, data)
		}
	})
}

func BenchmarkDecodeSkip(b *testing.B) {
	k := 76 // insert newline every k characters
	data := make([]byte, 10240)
	rand.Read(data)
	data[len(data)-1] &= 0xF0
	buf := make([]byte, (len(data)*6)/8)
	for i := range data {
		data[i] = URLAlphabet[data[i]&63]
	}
	for i := 0; i <= len(data)-1; i += k {
		data[i] = '\n'
	}

	stddec := base64.RawURLEncoding.Strict()
	pkgdec := RawURLEncoding

	// bench stdlib base64
	b.Run("stdlib", func(b *testing.B) {
		for b.Loop() {
			stddec.Decode(buf, data)
		}
	})

	// bench decode
	b.Run("decode", func(b *testing.B) {
		for b.Loop() {
			pkgdec.Decode(buf, data)
		}
	})

}

func BenchmarkStdDecodeStrict(b *testing.B) {

	data := make([]byte, 100000)
	rand.Read(data)
	data[len(data)-1] &= 0xF0
	buf := make([]byte, len(data))
	for i := range data {
		data[i] = URLAlphabet[data[i]&63]
	}
	stddec := base64.URLEncoding.Strict()
	pkgdec := URLEncoding

	// bench stdlib base64
	b.Run("stdlib_", func(b *testing.B) {
		for b.Loop() {
			stddec.Decode(buf, data)
		}
	})

	// bench decode
	b.Run("decode_", func(b *testing.B) {
		for b.Loop() {
			pkgdec.Decode(buf, data)
		}
	})
}

func BenchmarkRawEncodeStrict(b *testing.B) {
	data := make([]byte, 10000)
	rand.Read(data)
	buf := make([]byte, len(data)*2)

	dec := base64.RawURLEncoding.Strict()

	// bench stdlib base64
	b.Run("stdlib__", func(b *testing.B) {
		for b.Loop() {
			dec.Encode(buf, data)
		}
	})

	// bench encode
	b.Run("encode", func(b *testing.B) {
		for b.Loop() {
			RawURLEncoding.Encode(buf, data)
		}
	})
}
