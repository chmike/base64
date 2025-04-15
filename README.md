# Fast base64 encoder/decoder

This base64 encoder/decoder is faster than stdlib base64 package.

Encoding is 70% faster on ARM64 (Mac book M2) and 36% on AMD64 (i5 11th Gen).

Decoding MIME encoded base64, which is base64 with a newline every 76 character,
is 32% faster on ARM64 and 5% faster on AMD64.

Decoding pure base64 without padding and characters to ignore is 7% faster on
ARM64 and 32% faster on AMD64.

## Testing and benchmarking

Testing covers 100% of the code.

A CLI program is provided to generate benchmarks of the three typical usages.

## API

Usage is similar to the standard library. The predefined `StdEncoding` and
`RawStandard` encoding is for base64 using the standard alphabet. The former
is with padding, and the later without padding. Decoding is strict by default
for security reason. The decoding methods will ignore \n and \r characters.

The `URLEncoding` and `RawURLEncoding` are using the URL compatible alphabet
defined in RFC4648. The former is for padded base64 encoding, and the later
without. Decoding is strict by default. The decoding methods will ignore \n
and \r characters.

The function `NewEncoding(alphabet, ignore, padding, bitPadding)` allows to
define an encoding with a user defined alphabet, any set of ASCII characters
to ignore, a user defined padding character or none, and `Strict` or `Lax`
bit padding checking which doesn't require the padding bits to be 0.

Two alphabets are predefined, `StdAlphabet` and `URLAlphabet`. The characters
to ignore may be nil, `IgnoreNone`, `IgnoreNewlineOnly`, `IgnoreAll`.  The
user may provide a custom ignore map which is a slice of 256 bytes with the
values `Invalid` or `Ignore`. The function `MakeIgnore` is a handy function
to create such ignore map.

The padding argument is a rune whose value is used as padding character
unless it has the value `NoPadding`.

The bitPadding argument may be `Strict` to enforce 0 bit padding check, or
`Lax` to not check the padding bits.

## Final word

There is room for enhancement by using SIMD instructions. We didn't explore
this option.