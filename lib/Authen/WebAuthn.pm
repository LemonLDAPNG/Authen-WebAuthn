package Authen::WebAuthn;

use strict;
use warnings;
use Mouse;
use MIME::Base64 qw(encode_base64url decode_base64url);
use JSON qw(decode_json from_json to_json);
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::PK::Ed25519;
use Crypt::PRNG;
use Crypt::OpenSSL::X509 1.808;
use CBOR::XS 1.6 ();
use URI;
use Carp;
use Authen::WebAuthn::SSLeayChainVerifier;

has rp_id  => ( is => 'rw', required => 1 );
has origin => ( is => 'rw', required => 1 );

# 1 to accept any cross-origin iframe, or an arrayref of allowed top origins
has allow_cross_origin => ( is => 'rw', default => 0 );

my $ATTESTATION_FUNCTIONS = {
    none       => \&attest_none,
    packed     => \&attest_packed,
    "fido-u2f" => \&attest_u2f,
};

my $KEY_TYPES = {
    ECC => {
        parse_pem     => \&parse_ecc_pem,
        parse_cose    => \&parse_ecc_cose,
        make_verifier => \&make_cryptx_verifier,
    },
    RSA => {
        parse_pem     => \&parse_rsa_pem,
        parse_cose    => \&parse_rsa_cose,
        make_verifier => \&make_cryptx_verifier,
    },
    OKP => {
        parse_pem     => \&parse_okp_pem,
        parse_cose    => \&parse_okp_cose,
        make_verifier => \&make_cryptx_verifier,
    }
};

my $COSE_ALG = {

    # curve is the COSE elliptic curve identifier the key must use
    # https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier
    -7 => {
        name              => "ES256",
        key_type          => "ECC",
        curve             => 1,
        signature_options => ["SHA256"]
    },
    -35 => {
        name              => "ES384",
        key_type          => "ECC",
        curve             => 2,
        signature_options => ["SHA384"]
    },
    -36 => {
        name              => "ES512",
        key_type          => "ECC",
        curve             => 3,
        signature_options => ["SHA512"]
    },
    -8 => {
        name              => "EdDSA",
        key_type          => "OKP",
        curve             => 6,
        signature_options => []
    },
    -257 => {
        name              => "RS256",
        key_type          => "RSA",
        signature_options => [ "SHA256", "v1.5" ]
    },
    -37 => {
        name              => "PS256",
        key_type          => "RSA",
        signature_options => [ "SHA256", "pss", 32 ]
    },
    -65535 => {
        name              => "RS1",
        key_type          => "RSA",
        signature_options => [ "SHA1", "v1.5" ]
    }
};

# ES256 and RS256: what every platform authenticator and security key can do
my $DEFAULT_ALGS = [ -7, -257 ];

sub generate_registration_options {
    my ( $self, %params ) = @_;

    for my $required (qw(rp_name user_id user_name)) {
        unless ( defined $params{$required} and length $params{$required} ) {
            croak("Missing $required");
        }
    }

    my $algs = $params{allowed_algs};
    $algs = $DEFAULT_ALGS unless ref($algs) eq "ARRAY" and @$algs;
    for my $alg (@$algs) {
        croak("Unsupported algorithm $alg") unless $COSE_ALG->{$alg};
    }

    my $options = {
        rp   => { id => $self->rp_id, name => $params{rp_name} },
        user => {
            id          => encode_base64url( $params{user_id} ),
            name        => $params{user_name},
            displayName => $params{user_display_name} // $params{user_name},
        },
        challenge        => $params{challenge_b64} // _generate_challenge(),
        pubKeyCredParams =>
          [ map { { type => "public-key", alg => $_ + 0 } } @$algs ],
        attestation        => $params{attestation} // "none",
        excludeCredentials =>
          _credential_descriptors( $params{exclude_credentials} ),
        authenticatorSelection => {
            userVerification => $params{requested_uv} // "preferred",
            (
                $params{resident_key} ? ( residentKey => $params{resident_key} )
                : ()
            ),
            (
                $params{authenticator_attachment}
                ? ( authenticatorAttachment =>
                      $params{authenticator_attachment} )
                : ()
            ),
        },
    };
    $options->{timeout} = $params{timeout} + 0 if $params{timeout};

    return $options;
}

sub generate_assertion_options {
    my ( $self, %params ) = @_;

    my $options = {
        rpId             => $self->rp_id,
        challenge        => $params{challenge_b64} // _generate_challenge(),
        userVerification => $params{requested_uv}  // "preferred",
        allowCredentials =>
          _credential_descriptors( $params{allow_credentials} ),
    };
    $options->{timeout} = $params{timeout} + 0 if $params{timeout};

    return $options;
}

sub _generate_challenge {
    return encode_base64url( Crypt::PRNG::random_bytes(32) );
}

# Accepts base64url credential IDs, or hashrefs with an id and transports
sub _credential_descriptors {
    my ($credentials) = @_;

    return [] unless ref($credentials) eq "ARRAY";
    return [
        map {
            my $credential = ref($_) eq "HASH" ? $_ : { id => $_ };
            croak("Missing credential id") unless $credential->{id};
            {
                type => "public-key",
                id   => $credential->{id},
                (
                    ref( $credential->{transports} ) eq "ARRAY"
                      && @{ $credential->{transports} }
                    ? ( transports => $credential->{transports} )
                    : ()
                ),
            }
        } @$credentials
    ];
}

sub validate_registration {
    my ( $self, %params ) = @_;

    my (
        $challenge_b64,               $requested_uv,
        $client_data_json_b64,        $attestation_object_b64,
        $trust_anchors,               $allowed_attestation_types,
        $allow_untrusted_attestation, $allow_unknown_attestation_format,
        $allowed_algs,
      )
      = @params{ qw(
          challenge_b64        requested_uv
          client_data_json_b64 attestation_object_b64
          trust_anchors
          allowed_attestation_types allow_untrusted_attestation
          allow_unknown_attestation_format allowed_algs
        )
      };

    my $client_data_json = decode_base64url($client_data_json_b64);
    my $client_data      = _decode_client_data($client_data_json);

    # 7. Verify that the value of C.type is webauthn.create
    unless ( ( $client_data->{type} // "" ) eq "webauthn.create" ) {
        croak("Type is not webauthn.create");
    }

    # 8. Verify that the value of C.challenge equals the base64url encoding
    # of options.challenge.
    unless ($challenge_b64) {
        croak("Empty registration challenge");
    }

    unless ( $challenge_b64 eq ( $client_data->{challenge} // "" ) ) {
        croak(  "Challenge received from client data " . "("
              . ( $client_data->{challenge} // "none" ) . ") "
              . "does not match server challenge "
              . "($challenge_b64)" );
    }

    # 9. Verify that the value of C.origin matches the Relying Party's origin.

    unless ( $client_data->{origin} ) {
        croak("Empty origin in client data");
    }

    my $matched_origin = $self->_check_origin( $client_data->{origin} );
    $self->_check_cross_origin($client_data);

    # 11. Let hash be the result of computing a hash over
    # response.clientDataJSON using SHA-256.
    my $client_data_hash = sha256($client_data_json);

    # 12. Perform CBOR decoding on the attestationObject field of the
    # AuthenticatorAttestationResponse structure to obtain the attestation
    # statement format fmt, the authenticator data authData, and the
    # attestation statement attStmt.
    my $attestation_object = getAttestationObject($attestation_object_b64);
    my $authenticator_data = $attestation_object->{authData};

    # uncoverable branch true note:getAttestationObject requires it
    unless ($authenticator_data) {

        # uncoverable statement
        croak("Authenticator data not found in attestation object");
    }

    unless ( $authenticator_data->{attestedCredentialData} ) {
        croak("Attested credential data not found in authenticator data");
    }

    # 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
    # expected by the Relying Party.
    my $hash_rp_id = sha256( $self->rp_id );
    unless ( $authenticator_data->{rpIdHash} eq $hash_rp_id ) {
        croak(  "RP ID hash received from authenticator " . "("
              . unpack( "H*", $authenticator_data->{rpIdHash} ) . ") "
              . "does not match the hash of this RP ID " . "("
              . unpack( "H*", $hash_rp_id )
              . ")" );
    }

    # 14. Verify that the User Present bit of the flags in authData is set.
    unless ( $authenticator_data->{flags}->{userPresent} == 1 ) {
        croak("User not present during WebAuthn registration");
    }

    # 15. If user verification is required for this registration, verify that
    # the User Verified bit of the flags in authData is set.
    $requested_uv ||= "preferred";
    if (    $requested_uv eq "required"
        and $authenticator_data->{flags}->{userVerified} != 1 )
    {
        croak("User not verified during WebAuthn registration");
    }

    # 16. Verify that the "alg" parameter in the credential public key in
    # authData matches the alg attribute of one of the items in
    # options.pubKeyCredParams.
    # Without allowed_algs, every supported algorithm is accepted
    if ( ref($allowed_algs) eq "ARRAY" and @$allowed_algs ) {
        my $alg_num = $authenticator_data->{attestedCredentialData}
          ->{credentialPublicKeyAlgNum};
        unless ( grep { $_ == $alg_num } @$allowed_algs ) {
            croak("Credential public key algorithm $alg_num is not allowed");
        }
    }

    # 17. Verify that the values of the client extension outputs in
    # clientExtensionResults and the authenticator extension outputs in the
    # extensions in authData are as expected
    # TODO

    # Refuse a key that could never verify an assertion, rather than let the
    # Relying Party store it
    _check_credential_public_key(
        $authenticator_data->{attestedCredentialData}->{credentialPublicKey} );

    # 18. Determine the attestation statement format by performing a USASCII
    # case-sensitive match on fmt against the set of supported WebAuthn
    # Attestation Statement Format Identifier values.
    my $attestation_statement_format = $attestation_object->{'fmt'};
    my $attestation_function =
      $ATTESTATION_FUNCTIONS->{$attestation_statement_format};
    unless ( ref($attestation_function) eq "CODE" ) {
        if ($allow_unknown_attestation_format) {

            # Treat unknown attestation as None
            $attestation_function = $ATTESTATION_FUNCTIONS->{none};
        }
        else {
            croak(
                "Unsupported attestation format during WebAuthn registration: "
                  . $attestation_statement_format );
        }
    }

    # 19. Verify that attStmt is a correct attestation statement, conveying a
    # valid attestation signature, by using the attestation statement format
    # fmt’s verification procedure given attStmt, authData and hash.
    my $attestation_statement  = $attestation_object->{attStmt};
    my $authenticator_data_raw = $attestation_object->{authDataRaw};
    my $attestation_result     = eval {
        $attestation_function->(
            $attestation_statement,  $authenticator_data,
            $authenticator_data_raw, $client_data_hash
        );
    };
    croak( "Failed to validate attestation: " . $@ ) if ($@);

    # uncoverable branch true note:attestation functions croak instead
    unless ( $attestation_result->{success} == 1 ) {

        # uncoverable statement
        croak("Failed to validate attestation: $attestation_result->{error}");
    }

    # 20. If validation is successful, obtain a list of acceptable trust
    # anchors (i.e. attestation root certificates) for that attestation type
    # and attestation statement format fmt, from a trusted source or from
    # policy.
    if ( ref($trust_anchors) eq "CODE" ) {

        my $aaguid = $authenticator_data->{attestedCredentialData}->{aaguid};

        $trust_anchors = $trust_anchors->(
            aaguid             => $aaguid,
            attestation_type   => $attestation_result->{type},
            attestation_format => $attestation_statement_format,
        );

        if ( ref($trust_anchors) ne "ARRAY" ) {
            croak("trust_anchors sub must return an ARRAY reference");
        }
    }
    elsif ( defined($trust_anchors) and ref($trust_anchors) ne "ARRAY" ) {
        croak("trust_anchors parameter must be a SUB or ARRAY reference");
    }

    # 21. Assess the attestation trustworthiness using the outputs of the
    # verification procedure in step 19, as follows:
    $self->check_attestation_trust( $attestation_result, $trust_anchors,
        $allow_untrusted_attestation );
    $self->check_attestation_type( $allowed_attestation_types,
        $attestation_result->{type} );

    # 22. Check that the credentialId is not yet registered to any other user
    # TODO

    # 23. If the attestation statement attStmt verified successfully and is
    # found to be trustworthy, then register the new credential with the
    # account that was denoted in options.user:
    my $credential_id_bin =
      $authenticator_data->{attestedCredentialData}->{credentialId};
    my $credential_pubkey_cose =
      $authenticator_data->{attestedCredentialData}->{credentialPublicKey};
    my $signature_count = $authenticator_data->{signCount};
    return {
        credential_id      => encode_base64url($credential_id_bin),
        credential_pubkey  => encode_base64url($credential_pubkey_cose),
        signature_count    => $signature_count,
        attestation_result => $attestation_result,
        _flags_result( $authenticator_data->{flags} ),
    };
}

# Returns the configured origin that matches the one in client data
sub _check_origin {
    my ( $self, $client_origin ) = @_;

    my $origins = ref( $self->origin ) ? $self->origin : [ $self->origin ];
    for my $origin (@$origins) {
        return $origin if $client_origin eq $origin;
    }
    croak(  "Origin received from client data "
          . "($client_origin) "
          . "does not match any server origin(s) " . "("
          . join( ',', @$origins )
          . ")" );
}

# WebAuthn Level 3, step 10 of registration and 14 of authentication
sub _check_cross_origin {
    my ( $self, $client_data ) = @_;

    return unless $client_data->{crossOrigin};

    my $allowed = $self->allow_cross_origin;
    croak("Cross-origin requests are not allowed") unless $allowed;

    if ( ref($allowed) eq "ARRAY" ) {
        my $top_origin = $client_data->{topOrigin};
        unless ( defined $top_origin
            and grep { $_ eq $top_origin } @$allowed )
        {
            croak(  "Top origin "
                  . ( $top_origin // "(none)" )
                  . " is not allowed" );
        }
    }
    return;
}

# COSE key type for each key type (RFC 8152, section 13)
my $COSE_KTY = { OKP => 1, ECC => 2, RSA => 3 };

my $MIN_RSA_BITS = 2048;

sub _check_credential_public_key {
    my ($cose_raw) = @_;

    my $cose_key =
      _require_map( _decode_cbor($cose_raw), "Credential public key" );

    my $alg_num = $cose_key->{3} // "";
    my $alg     = $COSE_ALG->{$alg_num};
    croak("Unsupported algorithm $alg_num") unless $alg;

    my $kty = $cose_key->{1} // "";
    unless ( $kty eq $COSE_KTY->{ $alg->{key_type} } ) {
        croak("Key type $kty cannot be used with algorithm $alg_num");
    }

    eval { getPubKeyVerifier($cose_raw) };
    croak("Invalid credential public key: $@") if $@;

    if ( $alg->{key_type} eq "RSA" ) {
        ( my $modulus = $cose_key->{-1} ) =~ s/^\x00+//;
        my $bits = 8 * length($modulus);
        if ( $bits < $MIN_RSA_BITS ) {
            croak("RSA key of $bits bits is too short (min: $MIN_RSA_BITS)");
        }
    }
    return;
}

sub validate_assertion {
    my ( $self, %params ) = @_;
    my (
        $challenge_b64,        $credential_pubkey_b64,
        $stored_sign_count,    $requested_uv,
        $client_data_json_b64, $authenticator_data_b64,
        $signature_b64,        $extension_results,
        $appid,
      )
      = @params{
        qw(challenge_b64  credential_pubkey_b64
          stored_sign_count  requested_uv
          client_data_json_b64 authenticator_data_b64
          signature_b64 extension_results
          appid)
      };

    # 7. Using credential.id (or credential.rawId, if base64url encoding is
    # inappropriate for your use case), look up the corresponding credential
    # public key and let credentialPublicKey be that credential public key.
    my $credential_verifier =
      eval { getPubKeyVerifier( decode_base64url($credential_pubkey_b64) ) };
    croak "Cannot get signature validator for assertion: $@" if ($@);

    # 8. Let cData, authData and sig denote the value of response’s
    # clientDataJSON, authenticatorData, and signature respectively.
    my $client_data_json       = decode_base64url($client_data_json_b64);
    my $authenticator_data_raw = decode_base64url($authenticator_data_b64);
    my $authenticator_data     = getAuthData($authenticator_data_raw);
    my $signature              = decode_base64url($signature_b64);

    # 9. Let JSONtext be the result of running UTF-8 decode on the value of
    # cData.
    # 10. Let C, the client data claimed as used for the signature, be the
    # result of running an implementation-specific JSON parser on JSONtext.
    my $client_data = _decode_client_data($client_data_json);

    # 11. Verify that the value of C.type is the string webauthn.get.
    unless ( ( $client_data->{type} // "" ) eq "webauthn.get" ) {
        croak("Type is not webauthn.get");
    }

    # 12. Verify that the value of C.challenge equals the base64url encoding of
    # options.challenge.
    unless ($challenge_b64) {
        croak("Empty authentication challenge");
    }

    unless ( $challenge_b64 eq ( $client_data->{challenge} // "" ) ) {
        croak(  "Challenge received from client data " . "("
              . ( $client_data->{challenge} // "none" ) . ") "
              . "does not match server challenge "
              . "($challenge_b64)" );
    }

    # 13. Verify that the value of C.origin matches the Relying Party's origin.
    unless ( $client_data->{origin} ) {
        croak("Empty origin");
    }

    my $matched_origin = $self->_check_origin( $client_data->{origin} );
    $self->_check_cross_origin($client_data);

    # 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID
    # expected by the Relying Party.
    # If using the appid extension, this step needs some special logic. See
    # § 10.1 FIDO AppID Extension (appid) for details.

    my $hash_rp_id;
    if ( $extension_results->{appid} ) {
        $hash_rp_id = sha256( $appid // $matched_origin );
    }
    else {
        $hash_rp_id = sha256( $self->rp_id );
    }

    unless ( $authenticator_data->{rpIdHash} eq $hash_rp_id ) {
        croak(  "RP ID hash received from authenticator " . "("
              . unpack( "H*", $authenticator_data->{rpIdHash} ) . ") "
              . "does not match the hash of this RP ID " . "("
              . unpack( "H*", $hash_rp_id )
              . ")" );
    }

    # 16. Verify that the User Present bit of the flags in authData is set.
    unless ( $authenticator_data->{flags}->{userPresent} == 1 ) {
        croak("User not present during WebAuthn authentication");
    }

    # 17. If user verification is required for this assertion, verify that the
    # User Verified bit of the flags in authData is set.
    $requested_uv ||= "preferred";
    if (    $requested_uv eq "required"
        and $authenticator_data->{flags}->{userVerified} != 1 )
    {
        croak("User not verified during WebAuthn authentication");
    }

    # 18. Verify that the values of the client extension outputs in
    # clientExtensionResults and the authenticator extension outputs in the
    # extensions in authData are as expected,
    # TODO

    # 19. Let hash be the result of computing a hash over the cData using
    # SHA-256.
    my $client_data_hash = sha256($client_data_json);

    # 20. Using credentialPublicKey, verify that sig is a valid signature over
    # the binary concatenation of authData and hash.
    my $to_sign = $authenticator_data_raw . $client_data_hash;

    unless ( $credential_verifier->( $signature, $to_sign ) ) {
        croak("Webauthn signature was not valid");
    }

    # 21. Let storedSignCount be the stored signature counter value associated
    # with credential.id. If authData.signCount is nonzero or storedSignCount
    # is nonzero, then run the following sub-step:
    $stored_sign_count //= 0;
    my $signature_count = $authenticator_data->{signCount};
    if ( $signature_count > 0 or $stored_sign_count > 0 ) {
        if ( $signature_count <= $stored_sign_count ) {
            croak(  "Stored signature count $stored_sign_count "
                  . "higher than device signature count $signature_count" );
        }
    }

    return {
        success         => 1,
        signature_count => $signature_count,
        _flags_result( $authenticator_data->{flags} ),
    };
}

# The flags of the authenticator data a Relying Party may want to store
sub _flags_result {
    my ($flags) = @_;
    return (
        user_verified   => ( $flags->{userVerified}   ? 1 : 0 ),
        backup_eligible => ( $flags->{backupEligible} ? 1 : 0 ),
        backup_state    => ( $flags->{backupState}    ? 1 : 0 ),
    );
}

# Everything decoded here was sent by the client. A plain CBOR::XS decoder
# turns a value tagged as a Perl object into a call to the THAW method of
# whichever loaded class the value names. Nothing in WebAuthn is tagged, so
# refuse every tag, which also keeps the date and bignum decoders away from
# untrusted input.
sub _cbor_decoder {
    return CBOR::XS->new->validate_utf8->forbid_objects->max_size(1e6)
      ->filter( sub { croak("Unexpected CBOR tag $_[0]") } );
}

sub _decode_cbor {
    my ($cbor_raw) = @_;
    _require_bytes( $cbor_raw, "CBOR data" );

    # CBOR::XS warns on some malformed maps before it dies on them
    no warnings 'uninitialized';
    return _cbor_decoder()->decode($cbor_raw);
}

# The client data members compared here must be strings
sub _decode_client_data {
    my ($client_data_json) = @_;

    my $client_data = eval { decode_json( $client_data_json // "" ) };
    if ($@) {
        croak("Error deserializing client data: $@");
    }
    unless ( ref($client_data) eq "HASH" ) {
        croak("Client data is not a JSON object");
    }
    for my $member (qw(type challenge origin topOrigin)) {
        if ( ref $client_data->{$member} ) {
            croak("Client data member $member is not a string");
        }
    }
    return $client_data;
}

sub _require_bytes {
    my ( $value, $name ) = @_;
    croak("$name is missing") unless defined $value;
    croak("$name is not a byte string") if ref $value;
    return $value;
}

sub _require_map {
    my ( $value, $name ) = @_;
    croak("$name is not a map") unless ref($value) eq "HASH";
    return $value;
}

sub _ecc_obj_to_cose {
    my ($key) = @_;

    $key = $key->key2hash;

    # uncoverable branch true note:only ever called with P-256 keys
    unless ( $key->{curve_name} eq "secp256r1" ) {

        # uncoverable statement
        croak "Invalid ECC curve: " . $key->{curve_name};
    }

    # We want to be compatible with old CBOR::XS versions that don't have as_map
    # The correct code should be
    #return encode_cbor CBOR::XS::as_map [
    #    1  => 2,
    #    3  => -7,
    #    -1 => 1,
    #    -2 => pack( "H*", $key->{pub_x} ),
    #    -3 => pack( "H*", $key->{pub_y} ),
    #];

    # Manually encode the COSE key
    return "\xa5" .                                 #Map of 5 items
      "\x01\x02" .                                  # kty => EC2
      "\x03\x26" .                                  # alg => ES256
      "\x20\x01" .                                  # crv => P-256
      "\x21" .                                      # x =>
      "\x58\x20" . pack( "H*", $key->{pub_x} ) .    # x coordinate as a bstr
      "\x22" .                                      # y =>
      "\x58\x20" . pack( "H*", $key->{pub_y} )      # y coordinate as a bstr
      ;

}

# This function converts public keys from U2F format to COSE format. It can be useful
# for applications who want to migrate existing U2F registrations
sub convert_raw_ecc_to_cose {
    my ($raw_ecc_b64) = @_;

    my $key = Crypt::PK::ECC->new;
    $key->import_key_raw( decode_base64url($raw_ecc_b64), "secp256r1" );
    return encode_base64url( _ecc_obj_to_cose($key) );
}

sub check_attestation_type {
    my ( $self, $allowed_attestation_types, $attestation_type ) = @_;

    if ( ref($allowed_attestation_types) eq "ARRAY"
        and @$allowed_attestation_types )
    {
        if ( !grep { lc($_) eq lc($attestation_type) }
            @$allowed_attestation_types )
        {
            croak("Attestation type $attestation_type is not allowed");
        }
    }
}

sub check_attestation_trust {
    my ( $self, $attestation_result, $trust_anchors,
        $allow_untrusted_attestation )
      = @_;

    return 1 if $attestation_result->{type} eq "Self";
    return 1 if $attestation_result->{type} eq "None";

    #Otherwise, use the X.509 certificates returned as the attestation trust
    #path from the verification procedure to verify that the attestation public
    #key either correctly chains up to an acceptable root certificate, or is
    #itself an acceptable certificate (i.e., it and the root certificate
    #obtained in Step 20 may be the same).

    my $attn_cert = $attestation_result->{trust_path}->[0];

    # uncoverable branch true note:Basic attestation always has a certificate
    unless ($attn_cert) {

        # uncoverable statement
        croak("Missing attestation certificate");
    }

    my @trust_chain = @{ $attestation_result->{trust_path} };
    shift @trust_chain;

    if ( $self->matchCertificateInList( $attn_cert, $trust_anchors ) ) {
        return 1;
    }

    my $verify_result =
      Authen::WebAuthn::SSLeayChainVerifier::verify_chain( $trust_anchors,
        $attn_cert, \@trust_chain );

    if ( $verify_result->{result} == 1 ) {
        return 1;
    }
    else {
        # If the attestation statement attStmt successfully verified but is not
        # trustworthy per step 21 above, the Relying Party SHOULD fail the
        # registration ceremony.
        if ( !$allow_untrusted_attestation ) {
            croak( "Could not validate attestation trust: "
                  . $verify_result->{message} );
        }
        else {
         # NOTE: However, if permitted by policy, the Relying Party MAY register
         # the credential ID and credential public key but treat the credential
         # as one with self attestation
            %$attestation_result = (
                success    => 1,
                type       => "Self",
                trust_path => [],
            );
            return 1;
        }
    }
}

# Try to find a DER-encoded certificate in a list of PEM-encoded certificates
sub matchCertificateInList {
    my ( $self, $attn_cert, $trust_anchors ) = @_;
    return if ref($trust_anchors) ne "ARRAY";

    for my $candidate (@$trust_anchors) {
        my $candidate_x509 = eval {
            Crypt::OpenSSL::X509->new_from_string( $candidate,
                Crypt::OpenSSL::X509::FORMAT_PEM );
        };
        next unless $candidate_x509;
        if ( $attn_cert eq
            $candidate_x509->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) )
        {
            return 1;
        }
    }
    return;
}

# Used by u2f assertion types
sub _getU2FKeyFromCose {
    my ($cose_key) = @_;
    $cose_key = _decode_cbor($cose_key);

    # TODO: do we need to support more algs?
    croak( "Unexpected COSE Alg: " . $cose_key->{3} )
      unless ( $COSE_ALG->{ $cose_key->{3} }->{name} eq "ES256" );

    my $pk = parse_ecc_cose($cose_key);
    return $pk->export_key_raw('public');
}

sub parse_ecc_cose {
    my ($cose_struct) = @_;

    my $curve = $cose_struct->{-1};
    my $x     = _require_bytes( $cose_struct->{-2}, "EC2 key x coordinate" );
    my $y     = _require_bytes( $cose_struct->{-3}, "EC2 key y coordinate" );
    my $id_to_curve = { 1 => 'secp256r1', 2 => 'secp384r1', 3 => 'secp521r1', };

    my $pk         = Crypt::PK::ECC->new();
    my $curve_name = $id_to_curve->{$curve};
    unless ($curve_name) {
        croak "Unsupported curve $curve";
    }

    $pk->import_key( {
            curve_name => $curve_name,
            pub_x      => unpack( "H*", $x ),
            pub_y      => unpack( "H*", $y ),
        }
    );
    return $pk;
}

# This generic method generates a two-argument signature method from
# the public key (RSA, ECC, etc.) and signature options from the COSE_ALG hash
sub make_cryptx_verifier {
    my ( $public_key, @signature_options ) = @_;

    return sub {
        my ( $signature, $message ) = @_;
        return $public_key->verify_message( $signature, $message,
            @signature_options );
    };
}

# Octet Key Pair (RFC 8152, section 13.2). Only Ed25519 is supported
sub parse_okp_cose {
    my ($cose_struct) = @_;

    my $curve = $cose_struct->{-1} // "(none)";
    unless ( $curve eq "6" ) {
        croak "Unsupported curve $curve";
    }

    my $pk = Crypt::PK::Ed25519->new();
    $pk->import_key_raw( _require_bytes( $cose_struct->{-2}, "OKP key" ),
        'public' );
    return $pk;
}

sub parse_okp_pem {
    my ($pem) = @_;
    my $pk = Crypt::PK::Ed25519->new();
    $pk->import_key( \$pem );
    return $pk;
}

sub parse_ecc_pem {
    my ($pem) = @_;
    my $pk = Crypt::PK::ECC->new();
    $pk->import_key( \$pem );
    return $pk;
}

sub parse_rsa_pem {
    my ($pem) = @_;
    my $pk = Crypt::PK::RSA->new();
    $pk->import_key( \$pem );
    return $pk;
}

sub parse_rsa_cose {
    my ($cose_struct) = @_;
    my $n = _require_bytes( $cose_struct->{-1}, "RSA key modulus" );
    my $e = _require_bytes( $cose_struct->{-2}, "RSA key exponent" );

    my $pk = Crypt::PK::RSA->new();

    $pk->import_key( {
            N => unpack( "H*", $n ),
            e => unpack( "H*", $e ),
        }
    );

    return $pk;
}

# This function returns a verification method that is used like this:
# verifier->($signature, $message) returns 1 iff the message matches the
# signature
# Arguments are the COSE alg number from
# https://www.iana.org/assignments/cose/cose.xhtml#algorithms
# some key data, and the name of the function that converts the key data into a
# CryptX key (in KEY_TYPE array)
sub get_verifier_for_alg {
    my ( $alg_num, $key_data, $parse_method ) = @_;

    my $alg_config = $COSE_ALG->{$alg_num};
    unless ($alg_config) {
        croak "Unsupported algorithm $alg_num";
    }

    my $key_type        = $alg_config->{key_type};
    my $key_type_config = $KEY_TYPES->{$key_type};

    # uncoverable branch true note:every algorithm in COSE_ALG has a key type
    unless ($key_type_config) {

        # uncoverable statement
        croak "Unsupported key type $key_type";
    }

    # Get key conversion function
    my $key_function = $key_type_config->{$parse_method};
    unless ( ref($key_function) eq "CODE" ) {
        croak "No conversion method named $parse_method for key type $key_type";
    }

    # Get key
    my $public_key = $key_function->($key_data);

    # uncoverable branch true note:parse functions croak instead
    unless ($public_key) {

        # uncoverable statement
        croak "Could not parse public key";
    }

    my @signature_options = @{ $alg_config->{signature_options} };
    return $key_type_config->{make_verifier}
      ->( $public_key, @signature_options );
}

# This function takes a Base64url encoded COSE key and returns a verification
# method

sub getPubKeyVerifier {
    my ($pubkey_cose) = @_;
    my $cose_key =
      _require_map( _decode_cbor($pubkey_cose), "Credential public key" );

    my $alg_num = $cose_key->{3};
    croak("Missing algorithm in credential public key")
      unless defined $alg_num and !ref $alg_num;

    # An algorithm is tied to one curve: ES256 with a P-384 key is not ES256
    my $curve = $COSE_ALG->{$alg_num} && $COSE_ALG->{$alg_num}->{curve};
    if ( $curve
        and !( defined $cose_key->{-1} and $cose_key->{-1} eq $curve ) )
    {
        croak "Curve "
          . ( $cose_key->{-1} // "(none)" )
          . " cannot be used with algorithm $alg_num";
    }

    return get_verifier_for_alg( $alg_num, $cose_key, "parse_cose" );
}

# Same, but input is a PEM and a COSE alg name (used in assertion validation)
sub getPEMPubKeyVerifier {
    my ( $pem, $alg_num ) = @_;

    return get_verifier_for_alg( $alg_num, $pem, "parse_pem" );
}

sub getCoseAlgAndLength {
    my ($cbor_raw) = @_;

    _require_bytes( $cbor_raw, "Credential public key" );
    my ( $cbor, $length ) = do {
        no warnings 'uninitialized';
        _cbor_decoder()->decode_prefix($cbor_raw);
    };
    _require_map( $cbor, "Credential public key" );

    my $alg_num = $cbor->{3};
    my $alg =
      ( defined $alg_num and !ref $alg_num and $COSE_ALG->{$alg_num} )
      ? $COSE_ALG->{$alg_num}->{name}
      : undef;

    if ($alg) {
        return ( $alg, $length, $alg_num );
    }
    else {
        croak "Unsupported algorithm " . ( $alg_num // "(none)" );
    }
}

# Transform binary AAGUID into string representation
sub formatAaguid {
    my ($aaguid) = @_;
    if ( length($aaguid) == 16 ) {
        return lc join "-",
          unpack( "H*", substr( $aaguid, 0,  4 ) ),
          unpack( "H*", substr( $aaguid, 4,  2 ) ),
          unpack( "H*", substr( $aaguid, 6,  2 ) ),
          unpack( "H*", substr( $aaguid, 8,  2 ) ),
          unpack( "H*", substr( $aaguid, 10, 6 ) ),
          ;
    }
    else {
        croak "Invalid AAGUID length";
    }
}

sub getAttestedCredentialData {
    my ($attestedCredentialData) = @_;

    check_length( $attestedCredentialData, "Attested credential data", 18 );

    my $res    = {};
    my $aaguid = formatAaguid( substr( $attestedCredentialData, 0, 16 ) );
    $res->{aaguid} = $aaguid;
    $res->{credentialIdLength} =
      unpack( 'n', substr( $attestedCredentialData, 16, 2 ) );

    # https://www.w3.org/TR/webauthn-3/#credential-id
    if ( $res->{credentialIdLength} > 1023 ) {
        croak("Credential ID is longer than 1023 bytes");
    }
    if ( length($attestedCredentialData) <= 18 + $res->{credentialIdLength} ) {
        croak("Attested credential data is truncated");
    }
    $res->{credentialId} =
      substr( $attestedCredentialData, 18, $res->{credentialIdLength} );
    my ( $cose_alg, $length_cbor_pubkey, $cose_alg_num ) =
      getCoseAlgAndLength(
        substr( $attestedCredentialData, 18 + $res->{credentialIdLength} ) );

    $res->{credentialPublicKeyAlg}    = $cose_alg;
    $res->{credentialPublicKeyAlgNum} = $cose_alg_num;
    $res->{credentialPublicKey} =
      substr( $attestedCredentialData, 18 + $res->{credentialIdLength},
        $length_cbor_pubkey );
    $res->{credentialPublicKeyLength} = $length_cbor_pubkey;
    return $res;
}

sub check_length {
    my ( $data, $name, $expected_len ) = @_;

    _require_bytes( $data, $name );
    my $len = length($data);
    if ( $len < $expected_len ) {
        croak("$name has incorrect length $len (min: $expected_len)");
    }
}

sub getAuthData {
    my ($ad) = @_;
    my $res = {};

    check_length( $ad, "Authenticator data", 37 );

    $res->{rpIdHash}  = substr( $ad, 0, 32 );
    $res->{flags}     = resolveFlags( unpack( 'C', substr( $ad, 32, 1 ) ) );
    $res->{signCount} = unpack( 'N', substr( $ad, 33, 4 ) );

    # A credential cannot be backed up unless it is eligible for backup
    # https://www.w3.org/TR/webauthn-3/#sctn-credential-backup
    if ( $res->{flags}->{backupState} and !$res->{flags}->{backupEligible} ) {
        croak("Backup State flag is set but Backup Eligibility is not");
    }

    my $attestedCredentialDataLength = 0;
    if ( $res->{flags}->{atIncluded} ) {
        my $attestedCredentialData =
          getAttestedCredentialData( substr( $ad, 37 ) );
        $res->{attestedCredentialData} = $attestedCredentialData;
        $attestedCredentialDataLength =
          18 + $attestedCredentialData->{credentialIdLength} +
          $attestedCredentialData->{credentialPublicKeyLength};
    }

    if ( $res->{flags}->{edIncluded} ) {
        if ( length($ad) <= 37 + $attestedCredentialDataLength ) {
            croak("Extension data flag is set but there is no extension data");
        }
        my $ext = substr( $ad, 37 + $attestedCredentialDataLength );
        $res->{extensions} =
          _require_map( _decode_cbor($ext), "Extension data" );
    }
    else {
        # Check for trailing bytes
        croak("Trailing bytes in authenticator data")
          if ( length($ad) > ( 37 + $attestedCredentialDataLength ) );
    }

    return $res;
}

sub resolveFlags {
    my ($bits) = @_;
    return {
        userPresent    => ( ( $bits & 1 ) == 1 ),
        userVerified   => ( ( $bits & 4 ) == 4 ),
        backupEligible => ( ( $bits & 8 ) == 8 ),
        backupState    => ( ( $bits & 16 ) == 16 ),
        atIncluded     => ( ( $bits & 64 ) == 64 ),
        edIncluded     => ( ( $bits & 128 ) == 128 ),
    };
}

sub getAttestationObject {
    my ($dat)   = @_;
    my $decoded = decode_base64url($dat);
    my $res     = {};
    my $h       = _require_map( _decode_cbor($decoded), "Attestation object" );
    _require_bytes( $h->{fmt},      "Attestation statement format" );
    _require_bytes( $h->{authData}, "Authenticator data" );
    _require_map( $h->{attStmt}, "Attestation statement" );
    $res->{authData}    = getAuthData( $h->{authData} );
    $res->{authDataRaw} = $h->{authData};
    $res->{attStmt}     = $h->{attStmt};
    $res->{fmt}         = $h->{fmt};
    return $res;
}

# https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
sub attest_none {
    my (
        $attestation_statement,  $auhenticator_data,
        $authenticator_data_raw, $client_data_hash
    ) = @_;
    return {
        success    => 1,
        type       => "None",
        trust_path => [],
    };

}

# https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
sub attest_packed {
    my (
        $attestation_statement,  $authenticator_data,
        $authenticator_data_raw, $client_data_hash
    ) = @_;

    # Verify that attStmt is valid CBOR conforming to the syntax defined above
    # and perform CBOR decoding on it to extract the contained fields.
    croak "Missing algorithm field in attestation statement"
      unless ( $attestation_statement->{alg} );
    croak "Invalid algorithm field in attestation statement"
      if ref $attestation_statement->{alg};

    croak "Missing signature field in attestation statement"
      unless ( $attestation_statement->{sig} );
    _require_bytes( $attestation_statement->{sig},
        "Attestation statement signature" );

    if ( defined $attestation_statement->{x5c} ) {
        my $x5c = $attestation_statement->{x5c};
        unless ( ref($x5c) eq "ARRAY"
            and @$x5c
            and !grep { !defined $_ or ref $_ } @$x5c )
        {
            croak "Invalid certificate field in attestation statement";
        }
    }

    my $signed_value = $authenticator_data_raw . $client_data_hash;

    #If x5c is present:
    if ( $attestation_statement->{x5c} ) {
        return attest_packed_x5c( $attestation_statement, $authenticator_data,
            $signed_value );

        #If x5c is not present, self attestation is in use.
    }
    else {
        return attest_packed_self( $attestation_statement, $authenticator_data,
            $signed_value );
    }
}

sub attest_packed_x5c {
    my ( $attestation_statement, $authenticator_data, $signed_value ) = @_;

    my $x5c_der = $attestation_statement->{x5c}->[0];
    my $sig_alg = $attestation_statement->{alg};
    my $sig     = $attestation_statement->{sig};

    my ( $x5c, $key, $key_alg );
    eval {
        $x5c = Crypt::OpenSSL::X509->new_from_string( $x5c_der,
            Crypt::OpenSSL::X509::FORMAT_ASN1 );

        # Crypt::OpenSSL::X509 cannot read Ed25519 keys
        my $alg = $COSE_ALG->{$sig_alg};
        $key =
          ( $alg and $alg->{key_type} eq "OKP" )
          ? Crypt::PK::Ed25519->new( \$x5c_der )->export_key_pem('public')
          : $x5c->pubkey();
    };

    croak "Cannot extract public key from attestation certificate: $@" if ($@);

    # Verify that sig is a valid signature over the concatenation of
    # authenticatorData and clientDataHash using the attestation public key in
    # attestnCert with the algorithm specified in alg.
    my $attestation_verifier = eval { getPEMPubKeyVerifier( $key, $sig_alg ) };
    croak "Cannot get signature validator for attestation: $@" if ($@);

    # Verify that attestnCert meets the requirements in § 8.2.1 Packed
    # Attestation Statement Certificate Requirements.
    eval { attest_packed_check_cert_requirements($x5c) };
    croak "Attestation certificate does not satisfy requirements: $@" if ($@);

    # If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
    # (id-fido-gen-ce-aaguid) verify that the value of this extension matches
    # the aaguid in authenticatorData.
    my $aaguid_ext = $x5c->extensions_by_oid->{'1.3.6.1.4.1.45724.1.1.4'};
    if ($aaguid_ext) {
        my $ad_aaguid = $authenticator_data->{attestedCredentialData}->{aaguid};
        my $cert_aaguid = $aaguid_ext->value;
        croak "Invalid id-fido-gen-ce-aaguid extension format"
          unless $cert_aaguid =~ /^#0410.{32}$/;

        # Reformat aaguids so they can be compared
        ($cert_aaguid) = $cert_aaguid =~ /^#0410(.{32})$/;
        $ad_aaguid =~ s/-//g;
        $ad_aaguid = uc($ad_aaguid);

        croak "AAGUID from certificate ($cert_aaguid)"
          . " does not match AAGUID from authenticator data ($ad_aaguid)"
          if $ad_aaguid ne $cert_aaguid;
    }

    # Optionally, inspect x5c and consult externally provided knowledge to
    # determine whether attStmt conveys a Basic or AttCA attestation.
    # TODO

    # If successful, return implementation-specific values representing
    # attestation type Basic, AttCA or uncertainty, and attestation trust path
    # x5c.
    if ( $attestation_verifier->( $sig, $signed_value ) ) {
        return {
            success    => 1,
            type       => "Basic",
            trust_path => $attestation_statement->{x5c},
            aaguid => $authenticator_data->{attestedCredentialData}->{aaguid},
        };
    }
    else {
        croak "Invalid attestation signature";
    }
}

# Implements 8.2.1. Packed Attestation Statement Certificate Requirements
sub attest_packed_check_cert_requirements {
    my ($x5c) = @_;

    my $version = $x5c->version;

    # Version MUST be set to 3
    # (which is indicated by an ASN.1 INTEGER with value 2).
    croak "Invalid certificate version" unless $version eq "02";

    # Subject field
    croak "Missing subject C" unless $x5c->subject_name->get_entry_by_type("C");
    croak "Missing subject O" unless $x5c->subject_name->get_entry_by_type("O");
    croak "Missing subject CN"
      unless $x5c->subject_name->get_entry_by_type("CN");
    croak "Missing subject OU"
      unless $x5c->subject_name->get_entry_by_type("OU");
    croak "Unexpected OU"
      unless $x5c->subject_name->get_entry_by_type("OU")->value eq
      "Authenticator Attestation";

    # The Basic Constraints extension MUST have the CA component set to false.
    my $basic_constraints = $x5c->extensions_by_oid->{"2.5.29.19"};
    croak "Missing Basic Constraints extension" unless $basic_constraints;
    croak "Basic Constraints CA is true" if $basic_constraints->basicC("ca");

    return;
}

sub attest_packed_self {
    my ( $attestation_statement, $authenticator_data, $signed_value ) = @_;

    my $sig          = $attestation_statement->{sig};
    my $sign_alg_num = $attestation_statement->{alg};
    my $cose_key =
      $authenticator_data->{attestedCredentialData}->{credentialPublicKey};

    # Validate that alg matches the algorithm of the credentialPublicKey in
    # authenticatorData.
    my $cose_alg =
      $authenticator_data->{attestedCredentialData}->{credentialPublicKeyAlg};
    my $sign_alg = $COSE_ALG->{$sign_alg_num}->{name};
    croak "Unknown key type in attestation data: $sign_alg_num"
      unless ($sign_alg);

    unless ( $sign_alg eq $cose_alg ) {
        croak "Attestation algorithm $sign_alg does not match "
          . "credential key type $cose_alg";
    }

    # Verify that sig is a valid signature over the concatenation of
    # authenticatorData and clientDataHash using the credential public key with
    # alg.
    my $credential_verifier = eval { getPubKeyVerifier($cose_key) };
    croak "Cannot get signature validator for attestation: $@" if ($@);

    # If successful, return implementation-specific values representing
    # attestation type Self and an empty attestation trust path.
    if ( $credential_verifier->( $sig, $signed_value ) ) {
        return {
            success    => 1,
            type       => "Self",
            trust_path => [],
        };
    }
    else {
        croak "Invalid attestation signature";
    }
}

# https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
sub attest_u2f {
    my (
        $attestation_statement,  $authenticator_data,
        $authenticator_data_raw, $client_data_hash
    ) = @_;

   # 1. Verify that attStmt is valid CBOR conforming to the syntax defined above
   # and perform CBOR decoding on it to extract the contained fields.
    croak "Missing signature field in attestation statement"
      unless ( $attestation_statement->{sig} );

    my $sig = $attestation_statement->{sig};

    # 2. Check that x5c has exactly one element and let attCert be that
    # element. Let certificate public key be the public key conveyed by
    # attCert. If certificate public key is not an Elliptic Curve (EC) public
    # key over the P-256 curve, terminate this algorithm and return an
    # appropriate error.
    unless ($attestation_statement->{x5c}
        and ref( $attestation_statement->{x5c} ) eq "ARRAY"
        and $attestation_statement->{x5c}->[0] )
    {
        croak "Missing certificate field in attestation statement";
    }

    my $x5c_der         = $attestation_statement->{x5c}->[0];
    my $attestation_key = Crypt::PK::ECC->new();
    eval {
        my $x5c = Crypt::OpenSSL::X509->new_from_string( $x5c_der,
            Crypt::OpenSSL::X509::FORMAT_ASN1 );
        my $key_pem = $x5c->pubkey();
        $attestation_key->import_key( \$key_pem );
    };
    croak "Could not extract ECC key from attestation certificate: $@" if ($@);

    if ( $attestation_key->key2hash->{curve_name} ne "secp256r1" ) {
        croak "Invalid attestation certificate curve name: "
          . $attestation_key->key2hash->{curve_name};
    }

    # 3. Extract the claimed rpIdHash from authenticatorData, and the claimed
    # credentialId and credentialPublicKey from
    # authenticatorData.attestedCredentialData.
    my $rp_id_hash = $authenticator_data->{rpIdHash};
    my $credential_id =
      $authenticator_data->{attestedCredentialData}->{credentialId};
    my $credential_public_key =
      $authenticator_data->{attestedCredentialData}->{credentialPublicKey};

    # 4.Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of
    # [RFC8152]) to Raw ANSI X9.62 public key format
    my $public_u2f_key = eval { _getU2FKeyFromCose($credential_public_key) };
    croak "Could not convert attested credential to U2F key: $@" if ($@);

    # 5.Let verificationData be the concatenation of (0x00 || rpIdHash ||
    # clientDataHash || credentialId || publicKeyU2F)
    my $verification_data = "\x00"
      . $rp_id_hash
      . $client_data_hash
      . $credential_id
      . $public_u2f_key;

    if (
        $attestation_key->verify_message( $sig, $verification_data, "SHA256" ) )
    {
        return {
            success    => 1,
            type       => "Basic",
            trust_path => $attestation_statement->{x5c},
        };
    }
    else {
        croak "Signature verification failed";
    }
}

1;
