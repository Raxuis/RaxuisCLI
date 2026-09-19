package spray

import (
	"crypto/hmac"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// NT hash known-answer vector: NT("password") is a widely published value.
func TestNTHashKnownVector(t *testing.T) {
	got := hex.EncodeToString(ntHash("password"))
	const want = "8846f7eaee8fb117ad06bdd830b7586c"
	if got != want {
		t.Errorf("ntHash(\"password\") = %s, want %s", got, want)
	}
}

// rc4HMACDecrypt reverses rc4HMACEncrypt and verifies the integrity checksum.
func rc4HMACDecrypt(key []byte, usage int, data []byte) ([]byte, bool) {
	if len(data) < 16 {
		return nil, false
	}
	checksum, enc := data[:16], data[16:]
	tb := make([]byte, 4)
	binary.LittleEndian.PutUint32(tb, uint32(rc4Usage(usage)))
	k1 := hmacMD5(key, tb)
	k3 := hmacMD5(k1, checksum)
	c, _ := rc4.NewCipher(k3)
	plain := make([]byte, len(enc))
	c.XORKeyStream(plain, enc)
	if !hmac.Equal(hmacMD5(k1, plain), checksum) {
		return nil, false
	}
	return plain[8:], true // strip the 8-byte confounder
}

func TestRC4HMACRoundTrip(t *testing.T) {
	key := ntHash("Winter2025!")
	plaintext := []byte("the quick brown fox")
	confounder := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	ct := rc4HMACEncrypt(key, 1, plaintext, confounder)
	if len(ct) != 16+8+len(plaintext) {
		t.Fatalf("ciphertext length = %d, want %d", len(ct), 16+8+len(plaintext))
	}
	got, ok := rc4HMACDecrypt(key, 1, ct)
	if !ok {
		t.Fatal("checksum verification failed on round-trip")
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip = %q, want %q", got, plaintext)
	}
}

func TestRC4HMACDetectsTampering(t *testing.T) {
	key := ntHash("pw")
	ct := rc4HMACEncrypt(key, 1, []byte("data"), []byte("confound"))
	ct[len(ct)-1] ^= 0xff // flip a ciphertext bit
	if _, ok := rc4HMACDecrypt(key, 1, ct); ok {
		t.Error("tampered ciphertext should fail checksum verification")
	}
}

// walkField returns the content of the first [context tag] element in a SEQUENCE body.
func walkField(seq []byte, tag byte) ([]byte, bool) {
	for len(seq) > 0 {
		tg, c, rest, ok := readTLV(seq)
		if !ok {
			return nil, false
		}
		if tg == tag {
			return c, true
		}
		seq = rest
	}
	return nil, false
}

func TestBuildASREQStructure(t *testing.T) {
	req, err := buildASREQ("alice", "Winter2025!", "CORP.LOCAL")
	if err != nil {
		t.Fatalf("buildASREQ: %v", err)
	}
	if req[0] != 0x6a { // [APPLICATION 10] AS-REQ
		t.Fatalf("AS-REQ should start with 0x6a, got 0x%02x", req[0])
	}

	_, kdcReq, _, ok := readTLV(req) // unwrap APPLICATION 10
	if !ok {
		t.Fatal("cannot unwrap AS-REQ application tag")
	}
	_, body, _, ok := readTLV(kdcReq) // unwrap SEQUENCE
	if !ok {
		t.Fatal("cannot unwrap KDC-REQ sequence")
	}

	pvno, ok := walkField(body, 0xA1) // [1] pvno
	if !ok {
		t.Fatal("pvno field missing")
	}
	if _, v, _, _ := readTLV(pvno); beInt(v) != 5 {
		t.Errorf("pvno = %d, want 5", beInt(v))
	}
	msgType, ok := walkField(body, 0xA2) // [2] msg-type
	if !ok {
		t.Fatal("msg-type field missing")
	}
	if _, v, _, _ := readTLV(msgType); beInt(v) != 10 {
		t.Errorf("msg-type = %d, want 10 (AS-REQ)", beInt(v))
	}
	if _, ok := walkField(body, 0xA3); !ok { // [3] padata present
		t.Error("padata (PA-ENC-TIMESTAMP) field missing")
	}
}

func TestParseKerberosResponse(t *testing.T) {
	asRep := appTag(11, derSeq(ctxTag(0, derInt(5)))) // [APPLICATION 11]
	if out := parseKerberosResponse(asRep); !out.Valid || !out.Definitive {
		t.Errorf("AS-REP should be a valid+definitive hit, got %+v", out)
	}

	krbErr := func(code int) []byte {
		return appTag(30, derSeq(
			ctxTag(0, derInt(5)),
			ctxTag(1, derInt(30)),
			ctxTag(6, derInt(code)),
		))
	}

	tests := []struct {
		code       int
		valid      bool
		definitive bool
	}{
		{krbErrPreauthFailed, false, true},    // wrong password
		{krbErrPrincipalUnknown, false, true}, // user unknown
		{krbErrClientRevoked, false, true},    // locked/disabled
		{krbErrKeyExpired, true, true},        // valid but expired
		{krbErrEtypeNoSupp, false, false},     // RC4 refused -> non-definitive
	}
	for _, tt := range tests {
		out := parseKerberosResponse(krbErr(tt.code))
		if out.Valid != tt.valid || out.Definitive != tt.definitive {
			t.Errorf("krb-error %d -> %+v, want valid=%v definitive=%v", tt.code, out, tt.valid, tt.definitive)
		}
	}
}

func TestParseKerberosResponseGarbage(t *testing.T) {
	if out := parseKerberosResponse([]byte{0x00}); out.Definitive {
		t.Error("garbage response should be non-definitive")
	}
}
