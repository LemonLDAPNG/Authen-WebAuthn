# Authen::WebAuthn

A library to add [Web Authentication](https://www.w3.org/TR/webauthn/) support to server applications

# Status

* Implements the Relying Party steps of [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
  (sections 7.1 and 7.2)
* Authentication works
* Builds the options for registration and authentication requests
* Takes the credential as the browser serializes it (`PublicKeyCredential.toJSON()`)
* Sign-in without a username (user handle checks)
* Extension outputs checked (credProps, prf, largeBlob, appid, credProtect...)
* ECDSA (P-256, P-384, P-521), Ed25519, Ed448 and RSA keys supported,
  including the fully-specified algorithm identifiers of RFC 9864
* Supported attestation formats: none, packed, fido-u2f, apple, android-key,
  tpm, compound
* Mandatory attestation trust chain validation
* FIDO Metadata Service (MDS3): attestation roots and authenticator status
  from FIDO's signed metadata, read offline, with CRL-checked downloads

# Documentation

https://metacpan.org/pod/Authen::WebAuthn
