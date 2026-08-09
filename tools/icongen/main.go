// Command icongen turns the Boobook logo into the two Windows resources the
// executable needs: a multi-size .ico, and a COFF object file the Go linker
// folds into the binary so Explorer, the taskbar and the file properties
// dialog show the owl rather than a blank sheet.
//
// It is a build-time utility, not part of the tool. It is committed because
// the .syso it produces is an opaque binary blob sitting in the command
// directory, and a blob nobody can regenerate is one nobody can trust or
// change. Run it when the logo changes:
//
//	go run ./tools/icongen
//
// No third-party dependency does this here on purpose. The alternatives
// (rsrc, go-winres) are fine tools, but this writes one object file to a
// format that has not changed since the 1990s, and the project would rather
// carry sixty lines of COFF than another module in the licence audit.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
)

// iconSizes are the square sizes Windows actually asks for: 16 in the title
// bar and tree views, 32 on the desktop and in the Alt-Tab switcher, 48 in
// the default Explorer view, 256 for the extra-large view and the Start
// menu. 64 and 128 are the intermediate steps the shell scales between, and
// including them beats letting it resample 256 down to 40-odd pixels.
var iconSizes = []int{16, 32, 48, 64, 128, 256}

// pngThreshold is the size at and above which the image is stored as PNG
// rather than an uncompressed DIB. This is the convention every icon
// toolchain follows: a 256x256 BGRA bitmap is 256 KB, and six of those would
// dominate the resource section, while Windows has read PNG-compressed icon
// entries since Vista. Below 256 the classic form is kept, because a handful
// of old shell code paths still reach for the DIB directly.
const pngThreshold = 256

func main() {
	in := flag.String("in", "logo/logo.png", "source PNG, square and at least 256x256")
	ico := flag.String("ico", "logo/boobook.ico", "multi-size icon to write")
	syso := flag.String("syso", "cmd/boobook/rsrc_windows_amd64.syso", "COFF resource object to write")
	flag.Parse()

	if err := run(*in, *ico, *syso); err != nil {
		fmt.Fprintf(os.Stderr, "icongen: %v\n", err)
		os.Exit(1)
	}
}

func run(in, icoPath, sysoPath string) error {
	src, err := loadPNG(in)
	if err != nil {
		return err
	}
	b := src.Bounds()
	if b.Dx() != b.Dy() {
		return fmt.Errorf("%s is %dx%d: the source must be square, or every size it is scaled to will be distorted", in, b.Dx(), b.Dy())
	}
	if b.Dx() < iconSizes[len(iconSizes)-1] {
		return fmt.Errorf("%s is %dx%d: the source must be at least %d wide, or the largest icon is an upscale", in, b.Dx(), b.Dy(), pngThreshold)
	}

	// Reported rather than refused. A logo drawn on a white square still
	// makes a working icon; it just wears a white box on a dark taskbar,
	// and that is a surprise worth having before the binary is published
	// rather than after.
	if opaque(src) {
		fmt.Fprintf(os.Stderr, "icongen: note: %s has no transparency, so the icon will show as a filled square\n", in)
	}

	images := make([]iconImage, 0, len(iconSizes))
	for _, size := range iconSizes {
		scaled := resample(src, size)
		var data []byte
		var err error
		if size >= pngThreshold {
			data, err = encodePNG(scaled)
		} else {
			data = encodeDIB(scaled)
		}
		if err != nil {
			return err
		}
		images = append(images, iconImage{size: size, data: data})
	}

	if err := writeFile(icoPath, buildICO(images)); err != nil {
		return err
	}
	object, err := buildCOFF(images)
	if err != nil {
		return err
	}
	if err := writeFile(sysoPath, object); err != nil {
		return err
	}

	fmt.Printf("wrote %s and %s from %s (%d sizes: %v)\n", icoPath, sysoPath, in, len(images), iconSizes)
	return nil
}

// iconImage is one size, already encoded in the form it will be stored in.
type iconImage struct {
	size int
	data []byte
}

func loadPNG(path string) (*image.NRGBA, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoded, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	// Normalised to non-premultiplied RGBA once, so the resampler below has
	// exactly one pixel layout to reason about whatever the source was.
	out := image.NewNRGBA(decoded.Bounds())
	draw.Draw(out, out.Bounds(), decoded, decoded.Bounds().Min, draw.Src)
	return out, nil
}

func opaque(img *image.NRGBA) bool {
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if img.NRGBAAt(x, y).A != 0xFF {
				return false
			}
		}
	}
	return true
}

// resample box-averages the source down to n by n.
//
// The averaging is done on premultiplied values and then un-premultiplied,
// which matters at the edges: averaging the colour of a transparent pixel in
// with its neighbours drags whatever happens to be stored behind the alpha
// into the result, and on a logo cut out of a white background that shows up
// as a pale halo at 16x16. A box filter is enough because every size here is
// a reduction, never an enlargement.
func resample(src *image.NRGBA, n int) *image.NRGBA {
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	dst := image.NewNRGBA(image.Rect(0, 0, n, n))

	for dy := 0; dy < n; dy++ {
		y0, y1 := b.Min.Y+dy*h/n, b.Min.Y+(dy+1)*h/n
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for dx := 0; dx < n; dx++ {
			x0, x1 := b.Min.X+dx*w/n, b.Min.X+(dx+1)*w/n
			if x1 <= x0 {
				x1 = x0 + 1
			}

			var sumR, sumG, sumB, sumA float64
			count := 0.0
			for y := y0; y < y1; y++ {
				for x := x0; x < x1; x++ {
					c := src.NRGBAAt(x, y)
					a := float64(c.A) / 255
					sumR += float64(c.R) * a
					sumG += float64(c.G) * a
					sumB += float64(c.B) * a
					sumA += a
					count++
				}
			}

			out := color.NRGBA{}
			if sumA > 0 {
				out.R = round(sumR / sumA)
				out.G = round(sumG / sumA)
				out.B = round(sumB / sumA)
				out.A = round(sumA / count * 255)
			}
			dst.SetNRGBA(dx, dy, out)
		}
	}
	return dst
}

func round(v float64) uint8 {
	switch {
	case v <= 0:
		return 0
	case v >= 255:
		return 255
	}
	return uint8(v + 0.5)
}

func encodePNG(img *image.NRGBA) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeDIB writes the classic icon image: a BITMAPINFOHEADER whose height is
// doubled, then the colour rows bottom-up, then a 1bpp mask.
//
// The doubled height is the format saying the two bitmaps are stacked. The
// mask is written all-zero — fully opaque — because at 32 bits per pixel
// Windows takes transparency from the alpha channel and ignores the mask.
// It cannot be omitted: the size is computed from the header, and a reader
// that walks off the end of the buffer gets a corrupt icon.
func encodeDIB(img *image.NRGBA) []byte {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()

	maskRow := ((w + 31) / 32) * 4
	var buf bytes.Buffer

	write(&buf, uint32(40), uint32(w), uint32(2*h), uint16(1), uint16(32), uint32(0))
	write(&buf, uint32(w*h*4+maskRow*h), uint32(0), uint32(0), uint32(0), uint32(0))

	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(b.Min.X+x, b.Min.Y+y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	buf.Write(make([]byte, maskRow*h))

	return buf.Bytes()
}

// buildICO assembles the .ico file: a directory of fixed-size entries
// followed by the images they point at.
func buildICO(images []iconImage) []byte {
	var buf bytes.Buffer
	write(&buf, uint16(0), uint16(1), uint16(len(images)))

	offset := 6 + 16*len(images)
	for _, img := range images {
		write(&buf, dimension(img.size), dimension(img.size), uint8(0), uint8(0))
		write(&buf, uint16(1), uint16(32), uint32(len(img.data)), uint32(offset))
		offset += len(img.data)
	}
	for _, img := range images {
		buf.Write(img.data)
	}
	return buf.Bytes()
}

// buildGroupIcon assembles the RT_GROUP_ICON resource, which is the .ico
// directory again with each image's byte offset replaced by the resource id
// the image was stored under. This is the structure Windows reads to decide
// which size to load, so it is the one that must list every size.
func buildGroupIcon(images []iconImage) []byte {
	var buf bytes.Buffer
	write(&buf, uint16(0), uint16(1), uint16(len(images)))
	for i, img := range images {
		write(&buf, dimension(img.size), dimension(img.size), uint8(0), uint8(0))
		write(&buf, uint16(1), uint16(32), uint32(len(img.data)), uint16(i+1))
	}
	return buf.Bytes()
}

// dimension encodes an icon edge in the single byte the directory allows.
// 256 does not fit, and the format's answer is that zero means 256.
func dimension(size int) uint8 {
	if size >= 256 {
		return 0
	}
	return uint8(size)
}

func write(buf *bytes.Buffer, values ...any) {
	for _, v := range values {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err) // Only a bad type reaches this, and that is a bug here, not input.
		}
	}
}

func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o644)
}
