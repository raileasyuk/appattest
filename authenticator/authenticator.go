package authenticator

import (
	"bytes"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/raileasyuk/appattest/utils"
)

// flagsOffset is the offset of the flags byte in the authenticator data.
const flagsOffset = 32

// AuthenticatorData is the authenticator data of an App Attest attestation or assertion.
//
// This wraps the upstream library type so we can add App Attest specific methods to it.
type AuthenticatorData struct {
	protocol.AuthenticatorData
}

// UnmarshalAssertion parses the authenticator data of an App Attest assertion.
func (a *AuthenticatorData) UnmarshalAssertion(rawAuthData []byte) error {
	authData := bytes.Clone(rawAuthData)

	// Apple sets the attested credential data flag on assertions even though assertions never contain attested
	// credential data, which means our parser will reject the payload. The flag is cleared on a copy of the payload so
	// that the signature still matches, but so we can parse the data successfully.
	if len(authData) > flagsOffset {
		authData[flagsOffset] &^= byte(protocol.FlagAttestedCredentialData)
	}

	return a.Unmarshal(authData)
}

func (a *AuthenticatorData) Verify(appIDHash []byte, credentialId []byte, production bool) error {
	// 6. Compute the SHA256 hash of your app’s App ID, and verify that this is the same as the authenticator data’s RP ID hash.
	if !bytes.Equal(a.RPIDHash[:], appIDHash) {
		return utils.ErrVerification.WithDetails(fmt.Sprintf("RP Hash mismatch. Expected %s and Received %s\n", a.RPIDHash, appIDHash))
	}

	// 7. Verify that the authenticator data’s counter field equals 0.
	if a.Counter != 0 {
		return utils.ErrVerification.WithDetails(fmt.Sprintf("Counter was not 0, but %d\n", a.Counter))
	}

	// 8. Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development environment,
	// or appattest followed by seven 0x00 bytes if operating in the production environment.
	aaguid := make([]byte, 16)
	if production {
		copy(aaguid, "appattest")
	} else {
		copy(aaguid, "appattestdevelop")
	}
	if !bytes.Equal(a.AttData.AAGUID, aaguid) {
		return utils.ErrVerification.WithDetails("AAGUID was not appattestdevelop\n")
	}

	// 9. Verify that the authenticator data’s credentialId field is the same as the key identifier.
	if !bytes.Equal(a.AttData.CredentialID, credentialId) {
		return utils.ErrVerification.WithDetails("Credential ID did not equal the provided key identifier\n")
	}

	return nil
}
