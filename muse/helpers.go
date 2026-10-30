package muse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"
)

func kindName(k string) string {
	if k == "video" {
		return "视频"
	}
	return "图片"
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func pickExt(mime, src, expect string) string {
	m := strings.ToLower(mime)
	for _, kv := range [][2]string{{"mp4", ".mp4"}, {"webm", ".webm"}, {"quicktime", ".mov"}, {"png", ".png"},
		{"jpeg", ".jpg"}, {"jpg", ".jpg"}, {"webp", ".webp"}, {"gif", ".gif"}} {
		if strings.Contains(m, kv[0]) {
			return kv[1]
		}
	}
	s := strings.ToLower(strings.SplitN(src, "?", 2)[0])
	for _, ext := range []string{".mp4", ".webm", ".mov", ".png", ".jpg", ".jpeg", ".webp", ".gif"} {
		if strings.HasSuffix(s, ext) {
			if ext == ".jpeg" {
				return ".jpg"
			}
			return ext
		}
	}
	if expect == "video" {
		return ".mp4"
	}
	return ".png"
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
func cookieFingerprint(acc *Account) string {
	return acc.Cookies["hatch_sess"] + "|" + acc.Proxy
}

func sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func isVideoURL(s string) bool {
	s = strings.ToLower(strings.SplitN(s, "?", 2)[0])
	return strings.HasSuffix(s, ".mp4") || strings.HasSuffix(s, ".webm") || strings.HasSuffix(s, ".mov")
}
