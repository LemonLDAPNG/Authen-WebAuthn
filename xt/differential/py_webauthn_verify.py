"""Verifies WebAuthn responses with py_webauthn, for xt/differential.t.

Reads a JSON array of cases on standard input and writes a JSON array of
results, one per case: {"ok": true} or {"ok": false, "error": "..."}.
"""

import base64
import json
import sys

from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import AttestationFormat

# The algorithms Authen::WebAuthn supports, of those py_webauthn knows (it has
# no ES384)
SUPPORTED = {alg.value for alg in COSEAlgorithmIdentifier}
ALGORITHMS = [
    COSEAlgorithmIdentifier(alg)
    for alg in (-7, -35, -36, -8, -257, -37)
    if alg in SUPPORTED
]


def b64decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def verify(case):
    common = {
        "credential": case["credential"],
        "expected_challenge": b64decode(case["challenge_b64"]),
        "expected_rp_id": case["rp_id"],
        "expected_origin": case["origin"],
    }
    if case["ceremony"] == "registration":
        roots = [pem.encode() for pem in case.get("root_pems", [])]
        verify_registration_response(
            **common,
            supported_pub_key_algs=ALGORITHMS,
            pem_root_certs_bytes_by_fmt={
                AttestationFormat.PACKED: roots,
                AttestationFormat.FIDO_U2F: roots,
            },
        )
    else:
        verify_authentication_response(
            **common,
            credential_public_key=b64decode(case["public_key_b64"]),
            credential_current_sign_count=case["sign_count"],
        )


results = []
for case in json.load(sys.stdin):
    try:
        verify(case)
        results.append({"ok": True})
    except Exception as error:  # every refusal is reported, whatever its type
        results.append({"ok": False, "error": f"{type(error).__name__}: {error}"})
json.dump(results, sys.stdout)
