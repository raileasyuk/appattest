package authenticator

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Could not decode hex: %v", err)
	}
	return b
}

func TestAttestationAuthenticatorData(t *testing.T) {
	tests := []struct {
		name          string
		appID         string
		authData      string
		credentialID  string
		hasExtensions bool
	}{
		{
			name:          "with Apple extensions",
			appID:         "KN65PKJXMB.com.trainsplit.app.dev",
			authData:      attestationAuthDataWithExtensions,
			credentialID:  "64effade2841534077996d1466d4474ceecf1c6d35977612b7e197f629d8b766",
			hasExtensions: true,
		},
		{
			name:         "without extensions",
			appID:        "KN65PKJXMB.com.trainsplit.app",
			authData:     attestationAuthDataWithoutExtensions,
			credentialID: "5bf793b057cd89f34dbf05b364577d886f014c5db83645663c81b2c5783cfd95",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a AuthenticatorData
			if err := a.Unmarshal(mustDecodeHex(t, tt.authData)); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			if got := a.Flags.HasExtensions(); got != tt.hasExtensions {
				t.Fatalf("HasExtensions() = %v, want %v", got, tt.hasExtensions)
			}

			appIDHash := sha256.Sum256([]byte(tt.appID))
			if err := a.Verify(appIDHash[:], mustDecodeHex(t, tt.credentialID), true); err != nil {
				t.Fatalf("Verify failed: %v", err)
			}
		})
	}
}

func TestAssertionAuthenticatorData(t *testing.T) {
	raw := mustDecodeHex(t, assertionAuthData)
	original := append([]byte(nil), raw...)

	var strict AuthenticatorData
	if err := strict.Unmarshal(raw); err == nil {
		t.Fatal("Unmarshal accepted an assertion with the attested credential data flag set; the workaround might no longer be needed")
	}

	var a AuthenticatorData
	if err := a.UnmarshalAssertion(raw); err != nil {
		t.Fatalf("UnmarshalAssertion failed: %v", err)
	}

	if a.Counter != 3 {
		t.Fatalf("Counter = %d, want 3", a.Counter)
	}

	if hex.EncodeToString(raw) != hex.EncodeToString(original) {
		t.Fatal("UnmarshalAssertion modified the raw authenticator data")
	}
}

const attestationAuthDataWithExtensions = "340286f1914261e4c7d5c7d342f5e947b5d635aaf45ef7f8a12529c7a8fbc01ec00000000061707061747465737400000000000000002064effade2841534077996d1466d4474ceecf1c6d35977612b7e197f629d8b766a501020326200121582065d1b551327a117f7b4af230130b686175145c72871e6d87f7a28c7c4deb22a8225820b32f25b5568152506ebbe7c5075c33d9817095b968ef5ea1ae13f0bce6fa5549a2776170706c655f62756e646c655f76657273696f6e5f3031623435781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314402000000"

const attestationAuthDataWithoutExtensions = "15ae2a8670f3d5150a95b6fd2fabfc92c5845c26a4b382ca3c51bb0cff9d4a1840000000006170706174746573740000000000000000205bf793b057cd89f34dbf05b364577d886f014c5db83645663c81b2c5783cfd95a5010203262001215820f6c0039c439b2137f14b8d85197c8c4236f8a14885ca454de2551cb33b2a067e22582071ec2b3a6e257f46738248274b3da1b3b302dc00e9f8a255091f6c0d56ffcf96"

const assertionAuthData = "7cef2b55da724108ba912796f675ff00be71d52dae268fa688d34ca6d27f70744000000003"
