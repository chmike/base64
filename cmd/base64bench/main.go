package main

import (
	"crypto/rand"
	stdbase64 "encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	pkgbase64 "github.com/chmike/base64"
)

func benchRawEncode(w io.Writer, data []byte) (std, pkg, pct []float64) {
	rand.Read(data)

	points := 20
	std = make([]float64, points)
	pkg = make([]float64, points)
	pct = make([]float64, points)

	libEnc := stdbase64.RawURLEncoding
	pkgEnc := pkgbase64.RawURLEncoding
	buf := make([]byte, pkgEnc.EncodedLen(len(data)))

	for i := range points {
		size := (i + 1) * len(data) / points
		src := data[:size]
		dst := buf[:pkgEnc.EncodedLen(len(data))]
		stdResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				libEnc.Encode(dst, src)
			}
		})
		pkgResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				pkgEnc.Encode(dst, src)
			}
		})
		std[i] = float64(stdResult.T.Nanoseconds()) / float64(stdResult.N)
		pkg[i] = float64(pkgResult.T.Nanoseconds()) / float64(pkgResult.N)
		pct[i] = (std[i]/pkg[i] - 1) * 100

		fmt.Fprintf(w, "encode: %3d%% %5d %7.1fns %7.1fns %5.2f%%\n", ((i+1)*100)/points, size, std[i], pkg[i], pct[i])
	}
	return std, pkg, pct
}

func benchRawDecodeIgnore(w io.Writer, data []byte) (std, pkg, pct []float64) {
	rand.Read(data)
	for i := range data {
		data[i] = pkgbase64.URLAlphabet[data[i]&0x3F]
	}
	// add \n every 76 character as with std MIME
	for i := 0; i < len(data); i += 76 {
		data[i] = '\n'
	}
	points := 20
	std = make([]float64, points)
	pkg = make([]float64, points)
	pct = make([]float64, points)

	libEnc := stdbase64.RawURLEncoding
	pkgEnc := pkgbase64.RawURLEncoding
	buf := make([]byte, pkgEnc.DecodedLen(len(data)))

	for i := range points {
		size := (i + 1) * len(data) / points
		if size&1 != 0 {
			size--
		}
		src := data[:size]
		dst := buf[:pkgEnc.DecodedLen(len(data))]
		stdResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				libEnc.Decode(dst, src)
			}
		})
		pkgResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				pkgEnc.Decode(dst, src)
			}
		})
		std[i] = float64(stdResult.T.Nanoseconds()) / float64(stdResult.N)
		pkg[i] = float64(pkgResult.T.Nanoseconds()) / float64(pkgResult.N)
		pct[i] = (std[i]/pkg[i] - 1) * 100

		fmt.Fprintf(w, "decode ignore %3d%% %5d %7.1fns %7.1fns %5.2f%%\n", ((i+1)*100)/points, size, std[i], pkg[i], pct[i])
	}
	return std, pkg, pct
}

func benchRawDecode(w io.Writer, data []byte) (std, pkg, pct []float64) {
	rand.Read(data)
	for i := range data {
		data[i] = pkgbase64.URLAlphabet[data[i]&0x3F]
	}
	points := 20
	std = make([]float64, points)
	pkg = make([]float64, points)
	pct = make([]float64, points)

	libEnc := stdbase64.RawURLEncoding
	pkgEnc := pkgbase64.MustNewEncoding(pkgbase64.URLAlphabet, nil, pkgbase64.NoPadding, pkgbase64.Strict)
	buf := make([]byte, pkgEnc.EncodedLen(len(data)))

	for i := range points {
		size := (i + 1) * len(data) / points
		if size&1 != 0 {
			size--
		}
		src := data[:size]
		dst := buf[:pkgEnc.DecodedLen(len(data))]
		stdResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				libEnc.Decode(dst, src)
			}
		})
		pkgResult := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				pkgEnc.Decode(dst, src)
			}
		})
		std[i] = float64(stdResult.T.Nanoseconds()) / float64(stdResult.N)
		pkg[i] = float64(pkgResult.T.Nanoseconds()) / float64(pkgResult.N)
		pct[i] = (std[i]/pkg[i] - 1) * 100

		fmt.Fprintf(w, "decode %3d%% %5d %7.1fns %7.1fns %5.2f%%\n", ((i+1)*100)/points, size, std[i], pkg[i], pct[i])
	}
	return std, pkg, pct
}

func average(pcts []float64) float64 {
	var ave float64
	for _, v := range pcts {
		ave += v
	}
	ave /= float64(len(pcts))
	return ave
}

func main() {

	sys := runtime.GOOS
	arch := runtime.GOARCH

	buildInfo, ok := debug.ReadBuildInfo()
	goVersion := "go0.0.0" // unknown version
	if ok {
		goVersion = buildInfo.GoVersion
	}

	fileName := fmt.Sprintf("bench_%s_%s_%s.txt", sys, arch, goVersion)
	fileName = strings.ReplaceAll(fileName, " ", "_")
	fmt.Println("saving stats in", fileName)

	f, err := os.Create(fileName)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}

	infoString := fmt.Sprintf("OS: %s, Arch: %s, %s", sys, arch, goVersion)
	fmt.Println(infoString)
	fmt.Fprintln(f, infoString)

	data := make([]byte, 5000)
	_, _, pct := benchRawEncode(f, data)
	fmt.Printf("encode enhancement: %5.2f%%\n", average(pct))
	fmt.Fprintf(f, "encode enhancement: %5.2f%%\n", average(pct))

	_, _, pct = benchRawDecodeIgnore(f, data)
	fmt.Printf("decode MIME enhancement: %5.2f%%\n", average(pct))
	fmt.Fprintf(f, "decode MIME enhancement: %5.2f%%\n", average(pct))

	_, _, pct = benchRawDecode(f, data)
	fmt.Printf("decode enhancement: %5.2f%%\n", average(pct))
	fmt.Fprintf(f, "decode enhancement: %5.2f%%\n", average(pct))
	f.Close()
}
