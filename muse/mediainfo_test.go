package muse

import (
	"encoding/binary"
	"os"
	"testing"
)

func box(typ string, body ...[]byte) []byte {
	n := 8
	for _, b := range body {
		n += len(b)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(n))
	out = append(out, typ...)
	for _, b := range body {
		out = append(out, b...)
	}
	return out
}

func TestProbeMP4(t *testing.T) {
	mvhd := make([]byte, 100) // version 0: timescale@12, duration@16
	binary.BigEndian.PutUint32(mvhd[12:], 1000)
	binary.BigEndian.PutUint32(mvhd[16:], 5040)
	tkhd := make([]byte, 84)
	binary.BigEndian.PutUint32(tkhd[76:], 1280<<16)
	binary.BigEndian.PutUint32(tkhd[80:], 720<<16)
	data := append(box("ftyp", []byte("isom")), box("moov", box("mvhd", mvhd), box("trak", box("tkhd", tkhd)))...)
	if w, h, s := probeMedia(data); w != 1280 || h != 720 || s != 5.04 {
		t.Fatalf("got %dx%d %.2fs", w, h, s)
	}
}

func TestProbeWebPVP8X(t *testing.T) {
	b := make([]byte, 30)
	copy(b, "RIFF")
	copy(b[8:], "WEBPVP8X")
	b[24], b[25] = 0xFF, 0x07 // 2047 → 2048
	b[27], b[28] = 0x7F, 0x04 // 1151 → 1152
	if w, h, _ := probeMedia(b); w != 2048 || h != 1152 {
		t.Fatalf("got %dx%d", w, h)
	}
}

// MUSE2API_PROBE=<file> checks a real file by hand.
func TestProbeFile(t *testing.T) {
	f := os.Getenv("MUSE2API_PROBE")
	if f == "" {
		t.Skip()
	}
	b, _ := os.ReadFile(f)
	w, h, s := probeMedia(b)
	t.Logf("%s: %dx%d %.2fs", f, w, h, s)
}

func TestProbeMP4MoovAtEnd(t *testing.T) {
	mvhd := make([]byte, 100)
	binary.BigEndian.PutUint32(mvhd[12:], 1000)
	binary.BigEndian.PutUint32(mvhd[16:], 2500)
	tkhd := make([]byte, 84)
	binary.BigEndian.PutUint32(tkhd[76:], 640<<16)
	binary.BigEndian.PutUint32(tkhd[80:], 360<<16)
	data := append(box("ftyp", []byte("isom")), box("mdat", make([]byte, 1<<20))...)
	data = append(data, box("moov", box("mvhd", mvhd), box("trak", box("tkhd", tkhd)))...)
	if w, h, s := probeMedia(data); w != 640 || h != 360 || s != 2.5 {
		t.Fatalf("got %dx%d %.2fs", w, h, s)
	}
}
