package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBuildSMB2Header(t *testing.T) {
	for _, command := range []uint16{0, 3, 5} {
		t.Run(fmt.Sprint(command), func(t *testing.T) {
			header := BuildSMB2Header(command, 0x123456789abcdef0)
			if len(header) != 64 || !bytes.Equal(header[:4], []byte{0xfe, 'S', 'M', 'B'}) {
				t.Fatalf("invalid SMB2 header: %x", header)
			}
			if binary.LittleEndian.Uint16(header[4:6]) != 64 || binary.LittleEndian.Uint16(header[12:14]) != command || binary.LittleEndian.Uint64(header[24:32]) != 0x123456789abcdef0 {
				t.Fatalf("header lost size, command or message ID: %x", header)
			}
		})
	}
}

// This is a negotiate-response fixture, not a complete SMB server. Offsets are
// relative to the SMB2 header (after the four-byte NetBIOS framing header).
func negotiateResponse(securityMode uint16) []byte {
	packet := make([]byte, 4+64+64)
	packet[3] = 128
	copy(packet[4:], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(packet[8:10], 64)
	binary.LittleEndian.PutUint32(packet[20:24], 1) // server response
	binary.LittleEndian.PutUint16(packet[68:70], 65)
	binary.LittleEndian.PutUint16(packet[70:72], securityMode)
	binary.LittleEndian.PutUint16(packet[72:74], 0x0210)
	return packet
}

func smbFixture(t *testing.T, response []byte, fragmented ...bool) (SMBOptions, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		header := make([]byte, 4)
		if _, err = io.ReadFull(conn, header); err != nil {
			done <- err
			return
		}
		length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
		if header[0] != 0 || length < 35 || length > 4096 {
			done <- fmt.Errorf("invalid NetBIOS request: %x", header)
			return
		}
		request := make([]byte, length)
		if _, err = io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(request[:5], []byte{0xff, 'S', 'M', 'B', 0x72}) || !bytes.Contains(request[35:], []byte("SMB 2.002\x00")) {
			done <- fmt.Errorf("expected SMB negotiate request, got %x", request)
			return
		}
		if len(fragmented) > 0 && fragmented[0] {
			for _, value := range response {
				if _, err = conn.Write([]byte{value}); err != nil {
					done <- err
					return
				}
				time.Sleep(time.Millisecond)
			}
		} else {
			_, err = conn.Write(response)
		}
		done <- err
	}()
	return SMBOptions{Host: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port, Timeout: 2}, done
}

func awaitSMBFixture(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SMB fixture: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("SMB fixture did not finish")
	}
}

func TestConnectLocalFixture(t *testing.T) {
	for _, tt := range []struct {
		name              string
		mode              uint16
		signing, required bool
	}{
		{"disabled", 0, false, false},
		{"enabled", 1, true, false},
		{"required", 3, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts, done := smbFixture(t, negotiateResponse(tt.mode))
			result, err := Connect(opts)
			awaitSMBFixture(t, done)
			if err != nil {
				t.Fatal(err)
			}
			if result.SMBVersion != "SMB2/3" || result.Signing != tt.signing || result.SignRequired != tt.required {
				t.Fatalf("negotiate result = %+v; want SMB2/3 signing=%v required=%v", result, tt.signing, tt.required)
			}
		})
	}
}

func TestConnectRejectsMalformedLocalFixture(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response []byte
	}{
		{"unknown protocol", []byte("HTTP/1.1 200 OK\r\n\r\n")},
		{"truncated negotiate", negotiateResponse(3)[:12]},
		{"empty response", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts, done := smbFixture(t, tt.response)
			result, err := Connect(opts)
			awaitSMBFixture(t, done)
			if err == nil || result.Error == nil {
				t.Fatalf("malformed negotiation accepted: %+v, %v", result, err)
			}
		})
	}
}

func TestEnumerateSharesDoesNotInventResults(t *testing.T) {
	shares, err := EnumerateShares(SMBOptions{Host: "127.0.0.1", Port: 0, Timeout: 1})
	if err == nil || len(shares) != 0 || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unsupported enumeration returned invented shares: %+v, %v", shares, err)
	}
}

func TestCheckNullSessionDoesNotClaimAuthentication(t *testing.T) {
	// A negotiate response contains no session-setup authentication evidence.
	// Until session setup is implemented, this operation must fail explicitly.
	allowed, err := CheckNullSession("127.0.0.1", 0, 1)
	if allowed || err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("unsupported null session check = %v, %v", allowed, err)
	}
}

func TestConnectReadsFragmentedLocalFixture(t *testing.T) {
	opts, done := smbFixture(t, negotiateResponse(3), true)
	result, err := Connect(opts)
	awaitSMBFixture(t, done)
	if err != nil || !result.Signing || !result.SignRequired {
		t.Fatalf("fragmented negotiation = %+v, %v", result, err)
	}
}

func TestConnectRejectsFailedNegotiation(t *testing.T) {
	response := negotiateResponse(3)
	binary.LittleEndian.PutUint32(response[12:16], 0xc0000022) // STATUS_ACCESS_DENIED
	opts, done := smbFixture(t, response)
	result, err := Connect(opts)
	awaitSMBFixture(t, done)
	if err == nil || result.Error == nil {
		t.Fatalf("access denied treated as successful negotiation: %+v, %v", result, err)
	}
}
