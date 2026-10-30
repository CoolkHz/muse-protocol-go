// Package fakemuse serves a minimal imitation of muse.ai for tests.
package fakemuse

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// PNG is the 8x6 image the fake site returns as a generation result.
func PNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 8, 6))
	for x := 0; x < 8; x++ {
		img.Set(x, 1, color.RGBA{255, 0, 0, 255})
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

// New starts the fake site. hatch_sess=s1 is the only valid session.
func New() *httptest.Server {
	srv, _ := NewWithGateway()
	return srv
}

// NewWithGateway also serves the fake Hatch gateway at /v1/noise.
func NewWithGateway() (*httptest.Server, *Gateway) {
	result := PNG()
	gw := NewGateway()
	mux := http.NewServeMux()
	mux.Handle("/v1/noise", gw)
	authed := func(r *http.Request) bool { return strings.Contains(r.Header.Get("Cookie"), "hatch_sess=s1") }
	mux.HandleFunc("/api/hatch/token", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, `{"token":"tok"}`)
	})
	mux.HandleFunc("/api/hatch/noise-notary-token", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"notaryToken":"notary"}`)
	})
	mux.HandleFunc("/api/session", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Cookie"), "hatch_sess=s1") {
			w.WriteHeader(401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "hatch_vml", Value: "rotated", MaxAge: 3600})
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"assigned","vm_id":"vm1","vm_state":"RUNNING","endpoint_url":"192.0.2.1:8443"}`)
	})
	mux.HandleFunc("/result.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(result)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html></html>")
	})
	return httptest.NewServer(mux), gw
}
