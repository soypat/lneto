package tls

// StringConst methods name values as String does but always return a
// compile-time constant, unlike String which formats an unrecognized value with
// strconv. Wire values are attacker controlled, so decoders and logs on
// embedded targets use StringConst and print the number alongside it.

const (
	// nameGREASE names the reserved values of RFC 8701, which carry no meaning.
	nameGREASE = "GREASE"
	// nameUnknown names a value this package does not recognize. Other RFCs may
	// well define it: this is TLS 1.3 only.
	nameUnknown = "unknown"
)

// StringConst returns the content type's name, or "unknown".
func (v ContentType) StringConst() string {
	switch v {
	case ContentTypeInvalid, ContentTypeChangeCipherSpec, ContentTypeAlert,
		ContentTypeHandshake, ContentTypeApplicationData:
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the handshake message type's name, or "unknown".
func (v HandshakeType) StringConst() string {
	switch v {
	case HandshakeTypeClientHello, HandshakeTypeServerHello, HandshakeTypeNewSessionTicket,
		HandshakeTypeEndOfEarlyData, HandshakeTypeEncryptedExtensions, HandshakeTypeCertificate,
		HandshakeTypeCertificateRequest, HandshakeTypeCertificateVerify, HandshakeTypeFinished,
		HandshakeTypeKeyUpdate, HandshakeTypeMessageHash:
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the extension type's name, "GREASE" or "unknown".
func (v ExtensionType) StringConst() string {
	switch v {
	case ExtServerName, ExtMaxFragmentLength, ExtStatusRequest, ExtSupportedGroups,
		ExtECPointFormats, ExtSignatureAlgorithms, ExtALPN, ExtSignedCertificateTimestamp,
		ExtPadding, ExtExtendedMasterSecret, ExtCompressCertificate, ExtRecordSizeLimit,
		ExtSessionTicket, ExtPreSharedKey, ExtEarlyData, ExtSupportedVersions, ExtCookie,
		ExtPSKKeyExchangeModes, ExtCertificateAuthorities, ExtSignatureAlgorithmsCert,
		ExtKeyShare, ExtApplicationSettings, ExtEncryptedClientHello, ExtRenegotiationInfo:
		return v.String()
	}
	if IsGREASE(uint16(v)) {
		return nameGREASE
	}
	return nameUnknown
}

// StringConst returns the alert level's name, or "unknown".
func (v AlertLevel) StringConst() string {
	switch v {
	case AlertLevelWarning, AlertLevelFatal:
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the alert description's name, or "unknown".
func (v AlertDescription) StringConst() string {
	switch v {
	case AlertCloseNotify, AlertUnexpectedMessage, AlertBadRecordMAC, AlertRecordOverflow,
		AlertHandshakeFailure, AlertBadCertificate, AlertUnsupportedCertificate,
		AlertCertificateRevoked, AlertCertificateExpired, AlertCertificateUnknown,
		AlertIllegalParameter, AlertUnknownCA, AlertAccessDenied, AlertDecodeError,
		AlertDecryptError, AlertProtocolVersion, AlertInsufficientSecurity,
		AlertInternalError, AlertInappropriateFallback, AlertUserCanceled,
		AlertMissingExtension, AlertUnsupportedExtension, AlertUnrecognizedName,
		AlertBadCertificateStatusResponse, AlertUnknownPSKIdentity,
		AlertCertificateRequired, AlertNoApplicationProtocol:
		return v.String()
	}
	return nameUnknown
}

// StringConst returns the named group's name, "GREASE" or "unknown".
func (v NamedGroup) StringConst() string {
	switch v {
	case GroupSECP256R1, GroupSECP384R1, GroupSECP521R1,
		GroupX25519, GroupX448, GroupX25519MLKEM768:
		return v.String()
	}
	if IsGREASE(uint16(v)) {
		return nameGREASE
	}
	return nameUnknown
}

// StringConst returns the signature scheme's name, "GREASE" or "unknown".
func (v SignatureScheme) StringConst() string {
	switch v {
	case SigRSAPKCS1SHA256, SigRSAPKCS1SHA384, SigRSAPKCS1SHA512,
		SigECDSAP256SHA256, SigECDSAP384SHA384, SigECDSAP521SHA512,
		SigRSAPSSRSAESHA256, SigRSAPSSRSAESHA384, SigRSAPSSRSAESHA512,
		SigEd25519, SigRSAPSSPSSSHA256:
		return v.String()
	}
	if IsGREASE(uint16(v)) {
		return nameGREASE
	}
	return nameUnknown
}

// StringConst returns the cipher suite's name, "GREASE" or "unknown".
// Every TLS 1.2 suite a browser still offers is undefined here: this package
// implements TLS 1.3 only.
func (v CipherSuite) StringConst() string {
	switch v {
	case SuiteAES128GCMSHA256, SuiteAES256GCMSHA384, SuiteChaCha20Poly1305SHA256,
		SuiteAES128CCMSHA256, SuiteAES128CCM8SHA256:
		return v.String()
	}
	if IsGREASE(uint16(v)) {
		return nameGREASE
	}
	return nameUnknown
}
