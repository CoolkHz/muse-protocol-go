package muse

import (
	"bytes"
	"encoding/binary"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
)

// probeMedia reads dimensions (and duration for MP4) from file headers.
func probeMedia(data []byte) (w, h int, seconds float64) {
	return probeMediaFile(bytes.NewReader(data), int64(len(data)))
}

// probeMediaFile is probeMedia without loading the file: images are read
// from the start as needed and only the MP4 moov box is loaded, wherever it is.
func probeMediaFile(r io.ReaderAt, size int64) (w, h int, seconds float64) {
	if cfg, _, err := image.DecodeConfig(io.NewSectionReader(r, 0, size)); err == nil {
		return cfg.Width, cfg.Height, 0
	}
	head := make([]byte, min(size, 32))
	n, _ := r.ReadAt(head, 0)
	if w, h, ok := webpSize(head[:n]); ok {
		return w, h, 0
	}
	var hdr [16]byte
	for off := int64(0); off+8 <= size; {
		if _, err := r.ReadAt(hdr[:8], off); err != nil {
			return 0, 0, 0
		}
		boxSize, hdrLen := int64(binary.BigEndian.Uint32(hdr[:4])), int64(8)
		if boxSize == 1 {
			if _, err := r.ReadAt(hdr[8:16], off+8); err != nil {
				return 0, 0, 0
			}
			boxSize, hdrLen = int64(binary.BigEndian.Uint64(hdr[8:16])), 16
		} else if boxSize == 0 {
			boxSize = size - off
		}
		if boxSize < hdrLen || boxSize > size-off {
			return 0, 0, 0
		}
		if string(hdr[4:8]) == "moov" {
			if boxSize > 64<<20 {
				return 0, 0, 0
			}
			box := make([]byte, boxSize)
			if _, err := r.ReadAt(box, off); err != nil {
				return 0, 0, 0
			}
			return mp4Info(box)
		}
		off += boxSize
	}
	return 0, 0, 0
}

func webpSize(b []byte) (int, int, bool) {
	if len(b) < 30 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
		return 0, 0, false
	}
	u24 := func(p []byte) int { return int(p[0]) | int(p[1])<<8 | int(p[2])<<16 }
	switch string(b[12:16]) {
	case "VP8X":
		return u24(b[24:27]) + 1, u24(b[27:30]) + 1, true
	case "VP8 ":
		return int(binary.LittleEndian.Uint16(b[26:28]) & 0x3fff), int(binary.LittleEndian.Uint16(b[28:30]) & 0x3fff), true
	case "VP8L":
		v := binary.LittleEndian.Uint32(b[21:25])
		return int(v&0x3fff) + 1, int(v>>14&0x3fff) + 1, true
	}
	return 0, 0, false
}

// mp4Info walks moov → mvhd (duration) and trak → tkhd (video size).
func mp4Info(b []byte) (w, h int, seconds float64) {
	var walk func(b []byte)
	walk = func(b []byte) {
		for len(b) >= 8 {
			size := int(binary.BigEndian.Uint32(b))
			typ := string(b[4:8])
			hdr := 8
			if size == 1 && len(b) >= 16 {
				size, hdr = int(binary.BigEndian.Uint64(b[8:16])), 16
			} else if size == 0 {
				size = len(b)
			}
			if size < hdr || size > len(b) {
				return
			}
			body := b[hdr:size]
			switch typ {
			case "moov", "trak":
				walk(body)
			case "mvhd":
				if len(body) >= 32 && body[0] == 1 {
					ts := binary.BigEndian.Uint32(body[20:24])
					if ts > 0 {
						seconds = float64(binary.BigEndian.Uint64(body[24:32])) / float64(ts)
					}
				} else if len(body) >= 20 {
					ts := binary.BigEndian.Uint32(body[12:16])
					if ts > 0 {
						seconds = float64(binary.BigEndian.Uint32(body[16:20])) / float64(ts)
					}
				}
			case "tkhd":
				// Width and height are the last two 16.16 fixed-point fields.
				if len(body) >= 8 && w == 0 {
					tw := int(binary.BigEndian.Uint32(body[len(body)-8:]) >> 16)
					th := int(binary.BigEndian.Uint32(body[len(body)-4:]) >> 16)
					if tw > 0 && th > 0 {
						w, h = tw, th
					}
				}
			}
			b = b[size:]
		}
	}
	walk(b)
	return w, h, seconds
}
