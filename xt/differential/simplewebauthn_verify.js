// Verifies WebAuthn responses with SimpleWebAuthn, for xt/differential.t.
//
// Reads a JSON array of cases on standard input and writes a JSON array of
// results, one per case: {"ok": true} or {"ok": false, "error": "..."}.

const {
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  SettingsService,
} = require("@simplewebauthn/server");

// The algorithms Authen::WebAuthn supports
const ALGORITHMS = [-7, -35, -36, -8, -257, -37];

function b64decode(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

async function verify(testCase) {
  const common = {
    response: testCase.credential,
    expectedChallenge: testCase.challenge_b64,
    expectedOrigin: testCase.origin,
    expectedRPID: testCase.rp_id,
    requireUserVerification: false,
  };
  let result;
  if (testCase.ceremony === "registration") {
    const roots = testCase.root_pems || [];
    for (const identifier of ["packed", "fido-u2f"]) {
      SettingsService.setRootCertificates({ identifier, certificates: roots });
    }
    result = await verifyRegistrationResponse({
      ...common,
      supportedAlgorithmIDs: ALGORITHMS,
    });
  } else {
    result = await verifyAuthenticationResponse({
      ...common,
      credential: {
        id: testCase.credential.id,
        publicKey: b64decode(testCase.public_key_b64),
        counter: testCase.sign_count,
      },
    });
  }
  // A refusal can also be a result that says it did not verify
  if (!result.verified) throw new Error("not verified");
}

async function main() {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const results = [];
  for (const testCase of JSON.parse(input)) {
    try {
      await verify(testCase);
      results.push({ ok: true });
    } catch (error) {
      results.push({ ok: false, error: `${error.name}: ${error.message}` });
    }
  }
  process.stdout.write(JSON.stringify(results));
}

main();
