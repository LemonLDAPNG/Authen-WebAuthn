# Authen::WebAuthn

A library to add [Web Authentication](https://www.w3.org/TR/webauthn/) support to server applications

# Status

* Authentication works
* Builds the options for registration and authentication requests
* Takes the credential as the browser serializes it (`PublicKeyCredential.toJSON()`)
* Sign-in without a username (user handle checks)
* Extension outputs checked (credProps, prf, largeBlob, appid, credProtect...)
* ECDSA (P-256, P-384, P-521), Ed25519 and RSA keys supported, including the
  fully-specified algorithm identifiers of RFC 9864
* Supported attestation formats: none, packed, fido-u2f, apple, android-key,
  tpm
* Mandatory attestation trust chain validation

# TODO

* Support FIDO Metadata Service

# Documentation

https://metacpan.org/pod/Authen::WebAuthn
