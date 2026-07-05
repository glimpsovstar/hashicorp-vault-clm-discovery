// Command gen-certs mints the UAT self-signed certificate matrix with exact
// notBefore/notAfter (+12h buffer) into <outdir>/<id>.crt and <id>.key.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type spec struct {
	id     string
	nbDays int // days from now for NotBefore
	naDays int // days from now for NotAfter (12h buffer added, except when 0)
}

func main() {
	outdir := "certs"
	if len(os.Args) > 1 {
		outdir = os.Args[1]
	}
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		log.Fatal(err)
	}
	now := time.Now().UTC()
	buf := 12 * time.Hour
	at := func(days int) time.Time {
		if days == 0 {
			return now
		}
		return now.Add(time.Duration(days)*24*time.Hour + buf)
	}
	specs := []spec{
		{"expired", -30, 0}, // na handled below (expired => now-1d)
		{"exp-7", 0, 7},
		{"exp-14", 0, 14},
		{"exp-15", 0, 15},
		{"exp-30", 0, 30},
		{"exp-45", 0, 45},
		{"exp-60", 0, 60},
		{"exp-61", 0, 61},
		{"valid-99", 0, 99},
		{"valid-400", 0, 400},
	}
	for _, s := range specs {
		nb := at(s.nbDays)
		na := at(s.naDays)
		if s.id == "expired" {
			nb = now.Add(-30 * 24 * time.Hour)
			na = now.Add(-1 * 24 * time.Hour)
		}
		writePair(outdir, s.id, nb, na)
	}
	log.Printf("wrote %d cert pairs to %s", len(specs), outdir)
}

func writePair(outdir, id string, nb, na time.Time) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id + ".uat.test"},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{id + ".uat.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	crt, err := os.Create(filepath.Join(outdir, id+".crt"))
	if err != nil {
		log.Fatal(err)
	}
	defer crt.Close()
	if err := pem.Encode(crt, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		log.Fatal(err)
	}
	kf, err := os.Create(filepath.Join(outdir, id+".key"))
	if err != nil {
		log.Fatal(err)
	}
	defer kf.Close()
	if err := pem.Encode(kf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		log.Fatal(err)
	}
}
