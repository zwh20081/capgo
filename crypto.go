// Package capgo is a Go server-side SDK for Cap (https://capjs.js.org), the
// proof-of-work CAPTCHA alternative.
//
// It implements every server-side protocol understood by the official
// @cap.js/widget:
//
//   - format 1, stateful challenges (wire-compatible with @cap.js/server);
//   - format 1, stateless signed challenges (wire-compatible with capjs-core),
//     with optional instrumentation;
//   - format 2 challenges (capjs-core) carrying any combination of the
//     "sha256-pow", "rsw" (repeated-squaring time-lock) and "instrumentation"
//     protocols;
//   - action scopes, replay protection (nonce consumption) and single-use
//     verification tokens.
//
// State lives behind the Store interface. MemoryStore is the single-process
// default; package capredis provides a Redis implementation for multi-replica
// deployments. Package caphttp mounts everything on net/http.
package capgo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"
)

const jwtHeaderJSON = `{"alg":"HS256","typ":"JWT"}`

var jwtHeaderB64 = base64.RawURLEncoding.EncodeToString([]byte(jwtHeaderJSON))

func randomHex(random io.Reader, byteCount int) (string, error) {
	raw := make([]byte, byteCount)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func sha256Sum(input string) [32]byte { return sha256.Sum256([]byte(input)) }

func sha256Hex(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// jwtSign produces a compact HS256 JWT over an already-serialized payload.
func jwtSign(payloadJSON []byte, secret []byte) string {
	signingInput := jwtHeaderB64 + "." + base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := hmacSHA256(secret, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwtVerify checks the HS256 signature and returns the raw payload JSON plus
// the hex-encoded signature (used as the replay nonce key).
func jwtVerify(token string, secret []byte) (payload []byte, signatureHex string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != sha256.Size {
		return nil, "", false
	}
	expected := hmacSHA256(secret, []byte(parts[0]+"."+parts[1]))
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, "", false
	}
	payload, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", false
	}
	return payload, hex.EncodeToString(sig), true
}

// jwtSignatureHex returns the hex of the signature segment without verifying.
func jwtSignatureHex(token string) (string, bool) {
	last := strings.LastIndexByte(token, '.')
	if last < 0 {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[last+1:])
	if err != nil {
		return "", false
	}
	return hex.EncodeToString(sig), true
}

func deriveGCMKey(secret []byte, info string) []byte {
	return hmacSHA256(secret, []byte(info))
}

// encryptGCM mirrors capjs-core encryptGcm: base64url(iv || tag || ciphertext)
// with AES-256-GCM under HMAC(secret, info).
func encryptGCM(secret []byte, info string, plaintext []byte, random io.Reader) (string, error) {
	block, err := aes.NewCipher(deriveGCMKey(secret, info))
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tagStart := len(sealed) - gcm.Overhead()
	packed := make([]byte, 0, len(iv)+len(sealed))
	packed = append(packed, iv...)
	packed = append(packed, sealed[tagStart:]...)
	packed = append(packed, sealed[:tagStart]...)
	return base64.RawURLEncoding.EncodeToString(packed), nil
}

func decryptGCM(secret []byte, info, blob string) ([]byte, bool) {
	packed, err := decodeBase64URL(blob)
	if err != nil || len(packed) < 28 {
		return nil, false
	}
	block, err := aes.NewCipher(deriveGCMKey(secret, info))
	if err != nil {
		return nil, false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false
	}
	iv, tag, ciphertext := packed[:12], packed[12:28], packed[28:]
	sealed := make([]byte, 0, len(ciphertext)+len(tag))
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)
	plaintext, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}

// decodeBase64URL accepts both padded and unpadded base64url, like Node's
// Buffer.from(str, "base64url").
func decodeBase64URL(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	return base64.RawURLEncoding.DecodeString(value)
}

// hashHasHexPrefix reports whether the hex encoding of hash starts with the
// (lowercase or uppercase) hex prefix target. Equivalent to capjs-core's
// powMatchesPrefix, including odd-length (nibble) targets.
func hashHasHexPrefix(hash []byte, target string) bool {
	return strings.HasPrefix(hex.EncodeToString(hash), strings.ToLower(target))
}
