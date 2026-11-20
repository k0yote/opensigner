package main

// Prototype test for commit-reveal (verification branch, not for merge).
// It verifies proofs that real browsers produced (experiment V5-E11).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// browserRow is one line of the browser page's output.
type browserRow struct {
	Exp         string `json:"exp"`
	UA          string `json:"ua"`
	Alg         string `json:"alg"`
	OK          bool   `json:"ok"`
	PublicKey   string `json:"publicKey"`
	Signature   string `json:"signature"`
	Extractable *bool  `json:"extractable"` // pointer: a missing field must not read as false
	ErrorName   string `json:"errorName"`
}

// getDeviceFields are the fields of the "get-device" vector in
// TestSigningInputVectors. The browser page signs exactly this input.
func getDeviceFields() proofFields {
	return proofFields{
		Method:     "GET",
		Path:       "/v1/devices/dev_123",
		DeviceID:   "dev_123",
		BodySHA256: sha256.Sum256(nil),
		Counter:    1,
		SessionID:  "0b9f7c1e-5a52-4f0e-9d53-2f6f1c1d7a11",
	}
}

// decodeStrictB64 applies the commit handler's rule: unpadded base64url that
// re-encodes to the same string.
func decodeStrictB64(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, fmt.Errorf("not canonical unpadded base64url")
	}
	return b, nil
}

// checkBrowserRow verifies one ok:true row against msg. Errors never contain
// key or signature bytes.
func checkBrowserRow(row browserRow, msg []byte) error {
	if row.Extractable == nil {
		return fmt.Errorf("extractable field is missing")
	}
	if *row.Extractable {
		return fmt.Errorf("private key was reported extractable")
	}
	key, err := decodeStrictB64(row.PublicKey)
	if err != nil {
		return fmt.Errorf("publicKey: %w", err)
	}
	if err := checkPublicKey(row.Alg, key); err != nil {
		return fmt.Errorf("publicKey rejected by checkPublicKey (%d bytes): %w", len(key), err)
	}
	sig, err := decodeStrictB64(row.Signature)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if len(sig) != 64 {
		return fmt.Errorf("signature is %d bytes, want 64", len(sig))
	}
	if !verifyProof(row.Alg, key, msg, sig) {
		return fmt.Errorf("signature does not verify over the get-device signing input")
	}
	return nil
}

var uaTokenRe = regexp.MustCompile(`(Firefox|Edg|Chrome|Version)/(\d+)`)

// browserLabel gives a short stable label: browser token and major version,
// plus the row index so labels stay unique.
func browserLabel(ua string, idx int) string {
	name := "ua"
	for _, m := range uaTokenRe.FindAllStringSubmatch(ua, -1) {
		name = m[1] + m[2]
		if m[1] != "Version" { // Chrome/Edg/Firefox win over Safari's Version
			break
		}
	}
	if name == "Version" || strings.HasPrefix(name, "Version") {
		name = "Safari" + strings.TrimPrefix(name, "Version")
	}
	return fmt.Sprintf("%s-%d", name, idx)
}

const getDeviceVectorHex = "0000001b6f70656e7369676e65722f636f6d6d69742d72657665616c2f763100000003474554000000132f76312f646576696365732f6465765f313233000000076465765f31323300000020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550000000800000000000000010000002430623966376331652d356135322d346630652d396435332d326636663163316437613131"

// checkGetDeviceVector ties getDeviceFields to the get-device vector.
func checkGetDeviceVector(msg []byte) error {
	if fmt.Sprintf("%x", msg) != getDeviceVectorHex {
		return fmt.Errorf("get-device signing input drifted from the vector")
	}
	return nil
}

// requireVerified fails when no ok:true row was verified, so a file of
// only failed rows cannot read as a pass.
func requireVerified(counts map[string]int) error {
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return fmt.Errorf("nothing verified: no ok:true row passed verification")
	}
	return nil
}

func loadBrowserRows(path string) ([]browserRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var all []browserRow
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, fmt.Errorf("not a JSON array of rows")
	}
	var rows []browserRow
	for _, r := range all {
		if r.Exp == "V5-E11" {
			rows = append(rows, r)
		}
	}
	return rows, nil
}

func TestVerifyBrowserSignatures(t *testing.T) {
	path := os.Getenv("LAB_BROWSER_SIGS")
	if path == "" {
		t.Skip("LAB_BROWSER_SIGS is not set")
	}
	rows, err := loadBrowserRows(path)
	if err != nil {
		t.Fatalf("reading LAB_BROWSER_SIGS: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no V5-E11 rows in the file")
	}
	msg := signingInput(getDeviceFields())
	if err := checkGetDeviceVector(msg); err != nil {
		t.Fatal(err)
	}
	verified := map[string]int{}
	for i, row := range rows {
		row := row
		t.Run(row.Alg+"/"+browserLabel(row.UA, i), func(t *testing.T) {
			if !row.OK {
				t.Skipf("browser could not sign: %s", row.ErrorName)
			}
			if err := checkBrowserRow(row, msg); err != nil {
				t.Error(err)
				return
			}
			verified[row.Alg]++
		})
	}
	for alg, n := range verified {
		t.Logf("verified %s rows: %d", alg, n)
	}
	if err := requireVerified(verified); err != nil {
		t.Error(err)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// goRow builds a row the way the browser page does, with Go keys.
func goRow(t *testing.T, alg string, msg []byte) browserRow {
	t.Helper()
	notExtractable := false
	row := browserRow{Exp: "V5-E11", UA: "Go/test", Alg: alg, OK: true, Extractable: &notExtractable}
	switch alg {
	case algEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		row.PublicKey = b64(pub)
		row.Signature = b64(ed25519.Sign(priv, msg))
	case algES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := priv.PublicKey.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		row.PublicKey = b64(pub)
		row.Signature = b64(sig)
	}
	return row
}

func TestBrowserSignatureVerifier(t *testing.T) {
	msg := signingInput(getDeviceFields())
	other := getDeviceFields()
	other.Counter = 2
	otherMsg := signingInput(other)

	good := []browserRow{goRow(t, algEd25519, msg), goRow(t, algES256, msg)}
	// Round-trip through a file, as the real input arrives.
	file := filepath.Join(t.TempDir(), "sigs.json")
	data, err := json.Marshal(append(good, browserRow{Exp: "other", Alg: algEd25519}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rows, err := loadBrowserRows(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (rows of another exp are ignored)", len(rows))
	}
	for _, row := range rows {
		if err := checkBrowserRow(row, msg); err != nil {
			t.Errorf("%s: good row rejected: %v", row.Alg, err)
		}
	}

	for _, alg := range []string{algEd25519, algES256} {
		t.Run(alg, func(t *testing.T) {
			// (i) signed over a different signing input
			wrongInput := goRow(t, alg, otherMsg)
			if err := checkBrowserRow(wrongInput, msg); err == nil || !strings.Contains(err.Error(), "does not verify") {
				t.Errorf("wrong signing input: got %v", err)
			}
			// (ii) extractable key
			ext := goRow(t, alg, msg)
			yes := true
			ext.Extractable = &yes
			if err := checkBrowserRow(ext, msg); err == nil || !strings.Contains(err.Error(), "extractable") {
				t.Errorf("extractable: got %v", err)
			}
			// (iii) public key of the wrong length
			short := goRow(t, alg, msg)
			raw, _ := decodeStrictB64(short.PublicKey)
			short.PublicKey = b64(raw[:len(raw)-1])
			if err := checkBrowserRow(short, msg); err == nil || !strings.Contains(err.Error(), "checkPublicKey") {
				t.Errorf("short key: got %v", err)
			}
			// padded base64 is refused by the strict rule
			padded := goRow(t, alg, msg)
			padded.Signature += "="
			if err := checkBrowserRow(padded, msg); err == nil || !strings.HasPrefix(err.Error(), "signature:") {
				t.Errorf("padded signature: got %v", err)
			}
		})
	}

	// The fields really are the get-device vector.
	if err := checkGetDeviceVector(msg); err != nil {
		t.Error(err)
	}
	if err := requireVerified(map[string]int{}); err == nil || !strings.Contains(err.Error(), "nothing verified") {
		t.Errorf("empty counts: got %v", err)
	}
	if err := requireVerified(map[string]int{algES256: 1}); err != nil {
		t.Errorf("one verified row: got %v", err)
	}
	// A file of only ok:false rows verifies nothing.
	failedFile := filepath.Join(t.TempDir(), "failed.json")
	failedData := `[{"exp":"V5-E11","ua":"x","alg":"Ed25519","ok":false,"errorName":"NotSupportedError"}]`
	if err := os.WriteFile(failedFile, []byte(failedData), 0o600); err != nil {
		t.Fatal(err)
	}
	failedRows, err := loadBrowserRows(failedFile)
	if err != nil || len(failedRows) != 1 || failedRows[0].OK {
		t.Fatalf("failed-row file not loaded as expected: %v", err)
	}
	if err := requireVerified(map[string]int{}); err == nil {
		t.Error("only ok:false rows must read as nothing verified")
	}
	// A row without the extractable field is refused, not read as false.
	missing := goRow(t, algEd25519, msg)
	missing.Extractable = nil
	if err := checkBrowserRow(missing, msg); err == nil || !strings.Contains(err.Error(), "extractable field is missing") {
		t.Errorf("missing extractable: got %v", err)
	}
	var fromJSON browserRow
	if err := json.Unmarshal([]byte(`{"ok":true,"alg":"Ed25519"}`), &fromJSON); err != nil || fromJSON.Extractable != nil {
		t.Error("absent extractable must decode to nil")
	}
	if label := browserLabel("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15", 3); label != "Safari18-3" {
		t.Errorf("Safari label: %s", label)
	}
	if label := browserLabel("Mozilla/5.0 Chrome/131.0.0.0 Safari/537.36", 0); label != "Chrome131-0" {
		t.Errorf("Chrome label: %s", label)
	}
}
