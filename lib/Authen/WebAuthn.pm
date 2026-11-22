package Authen::WebAuthn;

use strict;
use warnings;

# VERSION
use Mouse;
use MIME::Base64 3.11 qw(encode_base64url decode_base64url);
use JSON              qw(decode_json from_json to_json);
use Digest::SHA       qw(sha256);
use Scalar::Util      ();
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use CryptX 0.089 ();
use Crypt::PK::Ed25519;
use Crypt::PK::Ed448;
use Crypt::PRNG;
use Crypt::OpenSSL::X509 1.808;
use CBOR::XS 1.6      ();
use B                 ();
use Encode            ();
use Types::Serialiser ();
use URI;
use Carp;
use Authen::WebAuthn::SSLeayChainVerifier;

has rp_id  => ( is => 'rw', required => 1 );
has origin => ( is => 'rw', required => 1 );

# 1 to accept any cross-origin iframe, or an arrayref of allowed top origins
has allow_cross_origin => ( is => 'rw', default => 0 );

my $ATTESTATION_FUNCTIONS = {
    none          => \&attest_none,
    packed        => \&attest_packed,
    "fido-u2f"    => \&attest_u2f,
    apple         => \&attest_apple,
    "android-key" => \&attest_android_key,
    tpm           => \&attest_tpm,
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

    # The fully-specified identifiers of RFC 9864, which in WebAuthn mean the
    # same as ES256, ES384, ES512 and EdDSA above
    -9 => {
        name              => "ESP256",
        key_type          => "ECC",
        curve             => 1,
        signature_options => ["SHA256"]
    },
    -51 => {
        name              => "ESP384",
        key_type          => "ECC",
        curve             => 2,
        signature_options => ["SHA384"]
    },
    -52 => {
        name              => "ESP512",
        key_type          => "ECC",
        curve             => 3,
        signature_options => ["SHA512"]
    },
    -19 => {
        name              => "Ed25519",
        key_type          => "OKP",
        curve             => 6,
        signature_options => []
    },
    -53 => {
        name              => "Ed448",
        key_type          => "OKP",
        curve             => 7,
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

# The CryptX class for each COSE OKP curve (RFC 9053, section 7.2)
my %OKP_CLASS = ( 6 => "Crypt::PK::Ed25519", 7 => "Crypt::PK::Ed448" );

# EdDSA, ES256 and RS256, which WebAuthn Level 3 says a Relying Party that
# wants to support a wide range of authenticators should offer
my $DEFAULT_ALGS = [ -8, -7, -257 ];

# ASN.1 universal types and classes, as _der_read returns them
my $DER_CONSTRUCTED = 0x20;
my $DER_CONTEXT     = 0xa0;    # context-specific, constructed (explicit)
my %DER             = (
    INTEGER      => [ 0x00,             2 ],
    BIT_STRING   => [ 0x00,             3 ],
    OCTET_STRING => [ 0x00,             4 ],
    OID          => [ 0x00,             6 ],
    SEQUENCE     => [ $DER_CONSTRUCTED, 16 ],
    SET          => [ $DER_CONSTRUCTED, 17 ],
);

# COSE elliptic curves (RFC 9053, section 7.1) by CryptX's name
my %COSE_CURVE_NAME = ( 1 => 'secp256r1', 2 => 'secp384r1', 3 => 'secp521r1' );

# Values the WebAuthn enumerations allow, for the options that take one
my %OPTION_VALUES = (
    requested_uv             => [qw(required preferred discouraged)],
    attestation              => [qw(none indirect direct enterprise)],
    resident_key             => [qw(required preferred discouraged)],
    authenticator_attachment => [qw(platform cross-platform)],
    hints                    => [qw(security-key client-device hybrid)],
);

# https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id
my $MAX_USER_ID_LENGTH = 64;

sub generate_registration_options {
    my ( $self, %params ) = @_;

    for my $required (qw(rp_name user_id user_name)) {
        unless ( defined $params{$required} and length $params{$required} ) {
            croak("Missing $required");
        }
    }

    # An opaque byte string: a character string has no defined length here
    croak("user_id must be bytes, not characters")
      unless utf8::downgrade( my $user_id = $params{user_id}, 1 );
    if ( length($user_id) > $MAX_USER_ID_LENGTH ) {
        croak("user_id is longer than $MAX_USER_ID_LENGTH bytes");
    }
    _check_option_values( \%params );

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
                $params{resident_key}
                ? ( residentKey => $params{resident_key} )
                : ()
            ),

            # For browsers that predate residentKey (WebAuthn Level 1)
            (
                  ( $params{resident_key} // "" ) eq "required"
                ? ( requireResidentKey => JSON::true )
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
    _add_optional_options( $options, \%params );

    return $options;
}

sub generate_assertion_options {
    my ( $self, %params ) = @_;

    _check_option_values( \%params );

    my $options = {
        rpId             => $self->rp_id,
        challenge        => $params{challenge_b64} // _generate_challenge(),
        userVerification => $params{requested_uv}  // "preferred",
        allowCredentials =>
          _credential_descriptors( $params{allow_credentials} ),
    };
    _add_optional_options( $options, \%params );

    return $options;
}

# Croaks on a value the WebAuthn enumerations do not have, or a malformed
# timeout or extensions
sub _check_option_values {
    my ($params) = @_;

    for my $name ( sort keys %OPTION_VALUES ) {
        next unless defined $params->{$name};
        my @values =
          $name eq "hints"
          ? @{ _require_list( $params->{$name}, $name ) }
          : ( $params->{$name} );
        for my $value (@values) {
            unless ( grep { $_ eq $value } @{ $OPTION_VALUES{$name} } ) {
                croak("Invalid $name: $value");
            }
        }
    }
    if ( defined $params->{timeout} and $params->{timeout} !~ /^[1-9]\d*$/ ) {
        croak("Invalid timeout: $params->{timeout}");
    }
    if ( defined $params->{extensions}
        and ref( $params->{extensions} ) ne "HASH" )
    {
        croak("extensions must be a HASH reference");
    }
    return;
}

sub _require_list {
    my ( $value, $name ) = @_;
    croak("$name must be an ARRAY reference") unless ref($value) eq "ARRAY";
    return $value;
}

sub _add_optional_options {
    my ( $options, $params ) = @_;

    $options->{timeout}    = $params->{timeout} + 0 if $params->{timeout};
    $options->{hints}      = $params->{hints}       if $params->{hints};
    $options->{extensions} = $params->{extensions}  if $params->{extensions};
    return;
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
    my $credential;
    ( $credential, %params ) = _credential_params( "registration", %params );

    my ( $challenge_b64, $requested_uv,
        $client_data_json_b64, $attestation_object_b64,
        $allowed_algs, $extension_results, $requested_extensions, )
      = @params{ qw(
          challenge_b64        requested_uv
          client_data_json_b64 attestation_object_b64
          allowed_algs
          extension_results requested_extensions
        )
      };

    my $metadata = $params{metadata};
    _check_metadata_freshness( $params{metadata}, %params )
      if defined $params{metadata};

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

    # 14. If options.mediation is not set to conditional, verify that the
    # User Present bit of the flags in authData is set.
    my $mediation = $params{mediation} // "optional";
    unless ( grep { $_ eq $mediation }
        qw(silent optional conditional required) )
    {
        croak("Invalid mediation: $mediation");
    }
    unless ( $mediation eq "conditional"
        or $authenticator_data->{flags}->{userPresent} == 1 )
    {
        croak("User not present during WebAuthn registration");
    }

    # 15. If user verification is required for this registration, verify that
    # the User Verified bit of the flags in authData is set.
    $requested_uv ||= "preferred";
    _check_option_values( { requested_uv => $requested_uv } );
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
    my %extensions = _check_extensions(
        "registration", $extension_results, $requested_extensions,
        $params{allow_unsolicited_extensions} // 1,
        $authenticator_data->{extensions},
    );

    # Refuse a key that could never verify an assertion, rather than let the
    # Relying Party store it
    _check_credential_public_key(
        $authenticator_data->{attestedCredentialData}->{credentialPublicKey} );

    # 18. Determine the attestation statement format by performing a USASCII
    # case-sensitive match on fmt against the set of supported WebAuthn
    # Attestation Statement Format Identifier values.
    my $attestation_statement_format = $attestation_object->{'fmt'};
    my @statement                    = (
        $attestation_object->{attStmt},
        $authenticator_data, $attestation_object->{authDataRaw},
        $client_data_hash,   %params
    );
    my ( $attestation_result, $metadata_entry ) =
      $self->_verify_statement( $attestation_statement_format, @statement );

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

    # The credential the browser reports is the one the authenticator made
    if ( defined $params{credential_id_b64} ) {
        my $reported = _decode_base64url_strict( $params{credential_id_b64},
            "credential_id_b64" );
        unless ( $reported eq $credential_id_bin ) {
            croak(  "Credential $params{credential_id_b64} is not the one "
                  . "in the authenticator data" );
        }
    }

    return {
        _transports($credential),
        credential_id      => encode_base64url($credential_id_bin),
        credential_pubkey  => encode_base64url($credential_pubkey_cose),
        signature_count    => $signature_count,
        attestation_result => $attestation_result,
        _flags_result( $authenticator_data->{flags} ),
        %extensions,
        _discoverable( $extensions{extension_results} ),
        (
            $metadata_entry
            ? ( metadata => _metadata_summary($metadata_entry) )
            : ()
        ),
    };
}

# Steps 18 to 21 for one attestation statement: verify it by its format,
# then check its trust path
sub _verify_statement {
    my ( $self, $format, $attestation_statement, $authenticator_data,
        $authenticator_data_raw, $client_data_hash, %params )
      = @_;

    return $self->_verify_compound_statement( @_[ 2 .. $#_ ] )
      if $format eq "compound";
    _require_map( $attestation_statement, "Attestation statement" );

    my $attestation_function = $ATTESTATION_FUNCTIONS->{$format};
    unless ( ref($attestation_function) eq "CODE" ) {
        if ( $params{allow_unknown_attestation_format} ) {

            # Treat unknown attestation as None
            $attestation_function = $ATTESTATION_FUNCTIONS->{none};
        }
        else {
            croak(
                "Unsupported attestation format during WebAuthn registration: "
                  . $format );
        }
    }

    # 19. Verify that attStmt is a correct attestation statement, conveying a
    # valid attestation signature, by using the attestation statement format
    # fmt’s verification procedure given attStmt, authData and hash.
    my $attestation_result = eval {
        $attestation_function->(
            $attestation_statement,
            $authenticator_data,
            $authenticator_data_raw,
            $client_data_hash,
            { android_key_require_tee => $params{android_key_require_tee} },
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
    my $trust_anchors = $params{trust_anchors};
    if ( ref($trust_anchors) eq "CODE" ) {

        my $aaguid = $authenticator_data->{attestedCredentialData}->{aaguid};

        $trust_anchors = $trust_anchors->(
            aaguid             => $aaguid,
            attestation_type   => $attestation_result->{type},
            attestation_format => $format,
        );

        if ( ref($trust_anchors) ne "ARRAY" ) {
            croak("trust_anchors sub must return an ARRAY reference");
        }
    }
    elsif ( defined($trust_anchors) and ref($trust_anchors) ne "ARRAY" ) {
        croak("trust_anchors parameter must be a SUB or ARRAY reference");
    }

    # Metadata names the roots of an attested model, and refuses models
    # whose attestation can no longer be trusted
    my $metadata_entry;
    if ( defined $params{metadata}
        and $attestation_result->{type} !~ /^(?:Self|None)$/ )
    {
        $metadata_entry =
          _check_metadata( $attestation_result, $authenticator_data, $format,
            %params );
        $trust_anchors = [
            @{ $trust_anchors || [] },
            @{ $metadata_entry->{attestation_roots} }
          ]
          if $metadata_entry;
    }

    # 21. Assess the attestation trustworthiness using the outputs of the
    # verification procedure in step 19, as follows:
    $self->check_attestation_trust( $attestation_result, $trust_anchors,
        $params{allow_untrusted_attestation} );
    $self->check_attestation_type( $params{allowed_attestation_types},
        $attestation_result->{type} );

    return ( $attestation_result, $metadata_entry );
}

# A compound statement (WebAuthn Level 3, section 8.9) holds two or more
# statements of other formats; every one must verify and be trusted
sub _verify_compound_statement {
    my ( $self, $statements, @rest ) = @_;

    croak("Compound attestation statement is not a list of two or more")
      unless ref($statements) eq "ARRAY" and @$statements >= 2;

    my @results;
    for my $i ( 0 .. $#$statements ) {
        my $format;
        my ( $result, $entry ) = eval {
            my $statement =
              _require_map( $statements->[$i], "Attestation statement" );
            $format = _require_text( $statement->{fmt},
                "Attestation statement format" );
            croak("A compound attestation statement cannot hold another")
              if $format eq "compound";
            $self->_verify_statement( $format, $statement->{attStmt}, @rest );
        };
        croak("Compound attestation statement $i: $@") if $@;
        $result->{format}   = $format;
        $result->{metadata} = _metadata_summary($entry) if $entry;
        push @results, $result;
    }
    return {
        success    => 1,
        type       => "Compound",
        trust_path => [],
        statements => \@results,
    };
}

sub _metadata_summary {
    my ($entry) = @_;
    return { map { $_ => $entry->{$_} }
          qw(aaguid description status status_report statement) };
}

# MDS statuses for which FIDO says a model should not be trusted
my @REFUSED_STATUSES = qw(REVOKED ATTESTATION_KEY_COMPROMISE
  USER_KEY_REMOTE_COMPROMISE USER_KEY_PHYSICAL_COMPROMISE
  USER_VERIFICATION_BYPASS);

# Attestation types as metadata statements name them
my %MDS_ATTESTATION_TYPE =
  ( Basic => "basic_full", AttCA => "attca", AnonCA => "anonca" );

sub _check_metadata_freshness {
    my ( $metadata, %params ) = @_;

    croak("metadata must be an Authen::WebAuthn::Metadata object")
      unless Scalar::Util::blessed($metadata)
      and $metadata->isa("Authen::WebAuthn::Metadata");
    return if $params{allow_stale_metadata};

    # The clock attestation chains are checked at
    $metadata->check_freshness(
        now => $Authen::WebAuthn::SSLeayChainVerifier::verification_time
          // time,
        grace_days => $params{metadata_grace_days},
    );
    return;
}

sub _check_metadata {
    my ( $attestation_result, $authenticator_data, $format, %params ) = @_;
    my $metadata = $params{metadata};

    my @chain  = @{ $attestation_result->{trust_path} };
    my $aaguid = $authenticator_data->{attestedCredentialData}->{aaguid};
    my $entry =
      (
             $format eq "fido-u2f"
          or $aaguid eq "00000000-0000-0000-0000-000000000000"
      )
      ? $metadata->entry( key_identifier => _key_identifier( $chain[0] ) )
      : $metadata->entry( aaguid         => $aaguid );

    unless ($entry) {
        croak("Authenticator $aaguid is not in the metadata")
          if $params{metadata_required};
        return;
    }
    my $name = ( $entry->{description} // "Authenticator" )
      . ( defined $entry->{aaguid} ? " ($entry->{aaguid})" : "" );

    my $status = $entry->{status} // "";
    my %refused =
      map { $_ => 1 } @{ $params{refused_statuses} || \@REFUSED_STATUSES };
    if ( $refused{$status} ) {
        my $report = $entry->{status_report};

        # A compromised key named in the report concerns only its chains
        my @named =
          grep { defined } @{$report}{qw(certificate batchCertificate)};
        my %in_chain = map { $_ => 1 } @chain;
        my $concerned =
             $status ne "ATTESTATION_KEY_COMPROMISE"
          || !@named
          || grep { $in_chain{ MIME::Base64::decode_base64($_) } } @named;
        croak(
            "$name has metadata status $status"
              . (
                defined $report->{effectiveDate}
                ? " since $report->{effectiveDate}"
                : ""
              )
        ) if $concerned;
    }

    my $type = $MDS_ATTESTATION_TYPE{ $attestation_result->{type} };
    croak(  "$name does not offer $attestation_result->{type} attestation"
          . " according to its metadata" )
      if $type
      and !grep { $_ eq $type } @{ $entry->{attestation_types} };

    return $entry;
}

# RFC 5280's method 1: the SHA-1 of the subject public key's bits, which
# U2F metadata uses to name a model
sub _key_identifier {
    my ($der) = @_;

    my $pem = _read_certificate($der)->pubkey;
    $pem =~ s/-----[^-]+-----//g;
    my ( undef, undef, $spki ) = _der_read( MIME::Base64::decode_base64($pem) );
    my ( undef, $bits ) = _der_read_all($spki);

    # uncoverable branch true note:OpenSSL writes the public key it read
    unless ( $bits and _der_is( @$bits[ 0, 1 ], "BIT_STRING" ) ) {

        # uncoverable statement
        croak("Invalid subject public key");
    }
    return unpack( "H*", Digest::SHA::sha1( substr( $bits->[2], 1 ) ) );
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

    # A topOrigin without crossOrigin is still a request from an iframe
    return
      unless $client_data->{crossOrigin}
      or defined $client_data->{topOrigin};

    my $allowed = $self->allow_cross_origin;
    croak("Cross-origin requests are not allowed") unless $allowed;

    # A single origin given as a string would otherwise allow them all
    unless ( ref($allowed) eq "ARRAY" or $allowed eq "1" ) {
        croak("allow_cross_origin must be 0, 1 or an arrayref of origins");
    }

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

    my $cose_key = _decode_cose_key($cose_raw);

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
        my $bits = _rsa_bits( $cose_key->{-1} );
        if ( $bits < $MIN_RSA_BITS ) {
            croak("RSA key of $bits bits is too short (min: $MIN_RSA_BITS)");
        }
    }
    return;
}

sub validate_assertion {
    my ( $self, %params ) = @_;
    ( undef, %params ) = _credential_params( "authentication", %params );
    my (
        $challenge_b64,        $credential_pubkey_b64,
        $stored_sign_count,    $requested_uv,
        $client_data_json_b64, $authenticator_data_b64,
        $signature_b64,        $extension_results,
        $appid,                $requested_extensions,
      )
      = @params{
        qw(challenge_b64  credential_pubkey_b64
          stored_sign_count  requested_uv
          client_data_json_b64 authenticator_data_b64
          signature_b64 extension_results
          appid requested_extensions)
      };

    # 5. If options.allowCredentials is not empty, verify that credential.id
    # identifies one of the public key credentials listed in
    # options.allowCredentials.
    # 6. Identify the user being authenticated, and verify that the user
    # handle, if present, is that of the credential's owner.
    my $user_handle_b64 = _check_credential_and_user(%params);

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

    # An appid output counts only if the appid extension was requested, when
    # the caller says what was requested
    my $requested_appid =
      ref($requested_extensions) eq "HASH"
      ? $requested_extensions->{appid}
      : undef;
    my $hash_rp_id;
    if (
            ref($extension_results) eq "HASH"
        and $extension_results->{appid}
        and !(
            ref($requested_extensions) eq "HASH"
            and !exists $requested_extensions->{appid}
        )
      )
    {
        $hash_rp_id = sha256( $appid // $requested_appid // $matched_origin );
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
    _check_option_values( { requested_uv => $requested_uv } );
    if (    $requested_uv eq "required"
        and $authenticator_data->{flags}->{userVerified} != 1 )
    {
        croak("User not verified during WebAuthn authentication");
    }

    # 18. Verify that the values of the client extension outputs in
    # clientExtensionResults and the authenticator extension outputs in the
    # extensions in authData are as expected,
    my %extensions = _check_extensions(
        "authentication", $extension_results, $requested_extensions,
        $params{allow_unsolicited_extensions} // 1,
        $authenticator_data->{extensions},
    );

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
    my $sign_count_regressed;
    if ( $signature_count > 0 or $stored_sign_count > 0 ) {
        if ( $signature_count <= $stored_sign_count ) {
            croak(  "Device signature count $signature_count is not higher "
                  . "than stored signature count $stored_sign_count" )
              unless $params{allow_sign_count_regression};
            $sign_count_regressed = 1;
        }
    }

    return {
        success         => 1,
        signature_count => $signature_count,
        ( $sign_count_regressed ? ( sign_count_regressed => 1 ) : () ),
        _flags_result( $authenticator_data->{flags} ),
        %extensions,
        (
            defined $user_handle_b64
            ? ( user_handle_b64 => $user_handle_b64 )
            : ()
        ),
    };
}

# The members of a credential, as PublicKeyCredential.toJSON() writes it,
# that stand for each argument
my %CREDENTIAL_MEMBERS = (
    registration => {
        credential_id_b64      => ["rawId"],
        client_data_json_b64   => [qw(response clientDataJSON)],
        attestation_object_b64 => [qw(response attestationObject)],
    },
    authentication => {
        credential_id_b64      => ["rawId"],
        client_data_json_b64   => [qw(response clientDataJSON)],
        authenticator_data_b64 => [qw(response authenticatorData)],
        signature_b64          => [qw(response signature)],
        user_handle_b64        => [qw(response userHandle)],
    },
);

# Replaces credential_json with the arguments it stands for. Returns the
# decoded credential too.
sub _credential_params {
    my ( $ceremony, %params ) = @_;

    my $json = delete $params{credential_json};
    return ( undef, %params ) unless defined $json;

    my $credential =
      ref $json ? $json : eval { JSON->new->utf8->decode($json) };
    croak("credential_json is not valid JSON: $@") unless defined $credential;
    _require_map( $credential,             "credential_json" );
    _require_map( $credential->{response}, "credential_json response" );
    unless ( ( $credential->{type} // "" ) eq "public-key" ) {
        croak("credential_json type is not public-key");
    }
    unless (_is_string( $credential->{id} )
        and _is_string( $credential->{rawId} )
        and $credential->{id} eq $credential->{rawId} )
    {
        croak("credential_json id and rawId differ");
    }

    my $members = $CREDENTIAL_MEMBERS{$ceremony};
    for my $name ( sort keys %$members ) {
        my $value = $credential;
        $value = ref $value eq "HASH" ? $value->{$_} : undef
          for @{ $members->{$name} };
        next unless defined $value;
        croak(  "credential_json "
              . join( ".", @{ $members->{$name} } )
              . " is not a string" )
          unless _is_string($value);
        croak("$name is given both as an argument and in credential_json")
          if defined $params{$name};
        $params{$name} = $value;
    }
    if ( defined $credential->{clientExtensionResults} ) {
        croak(  "extension_results is given both as an argument and in "
              . "credential_json" )
          if defined $params{extension_results};
        $params{extension_results} = $credential->{clientExtensionResults};
    }
    return ( $credential, %params );
}

# The transports the browser reports for a new credential, which the
# Relying Party stores to offer in allowCredentials
sub _transports {
    my ($credential) = @_;
    my $transports = $credential && $credential->{response}->{transports};
    return () unless ref($transports) eq "ARRAY";
    return ( transports => [ grep { _is_string($_) } @$transports ] );
}

# Steps 5 and 6 of authentication. Returns the user handle, if the client
# sent one.
sub _check_credential_and_user {
    my (%params) = @_;

    my $allowed = $params{allowed_credential_ids};
    if ( defined $allowed
        and @{ _require_list( $allowed, "allowed_credential_ids" ) } )
    {
        my $credential_id_b64 = $params{credential_id_b64};
        croak("Missing credential_id_b64") unless $credential_id_b64;
        my $credential_id =
          _decode_base64url_strict( $credential_id_b64, "credential_id_b64" );
        unless (
            grep {
                _decode_base64url_strict( $_, "allowed_credential_ids" ) eq
                  $credential_id
            } @$allowed
          )
        {
            croak(  "Credential $credential_id_b64 is not one of the "
                  . "allowed credentials" );
        }
    }

    my $user_handle_b64 = $params{user_handle_b64};
    undef $user_handle_b64
      unless defined $user_handle_b64 and length $user_handle_b64;

    # When the user was not identified before the ceremony, the user handle
    # is what identifies them
    if ( $params{require_user_handle} and !defined $user_handle_b64 ) {
        croak("Missing user handle");
    }
    if ( defined $user_handle_b64 ) {
        my $expected = $params{expected_user_handle_b64};
        unless ( defined $expected ) {
            croak(  "expected_user_handle_b64 is required to check the "
                  . "user handle" );
        }
        my $user_handle =
          _decode_base64url_strict( $user_handle_b64, "user_handle_b64" );
        unless ( $user_handle eq
            _decode_base64url_strict( $expected, "expected_user_handle_b64" ) )
        {
            croak(  "User handle ($user_handle_b64) does not match the "
                  . "credential's owner ($expected)" );
        }
        $user_handle_b64 = encode_base64url($user_handle);
    }
    return $user_handle_b64;
}

# decode_base64url skips characters outside the alphabet, so "AA.AA" would
# be the credential "AAAA"
sub _decode_base64url_strict {
    my ( $value, $name ) = @_;
    croak("$name is not valid base64url")
      unless _is_string($value)
      and $value =~ /^[A-Za-z0-9_-]*\z/
      and length($value) % 4 != 1;
    return decode_base64url($value);
}

# The outputs of the extensions this module knows, by ceremony, and the type
# of each member. Client outputs are as PublicKeyCredential.toJSON() writes
# them, with bytes in base64url; authenticator outputs are as CBOR decodes
# them.
my %CLIENT_EXTENSION_OUTPUTS = (
    registration => {
        appidExclude => "boolean",
        credProps    => { rk        => "boolean" },
        largeBlob    => { supported => "boolean" },
        prf          => {
            enabled => "boolean",
            results => { first => "base64url", second => "base64url" },
        },
    },
    authentication => {
        appid     => "boolean",
        largeBlob => { blob => "base64url", written => "boolean" },
        prf => { results => { first => "base64url", second => "base64url" } },
    },
);

my %AUTHENTICATOR_EXTENSION_OUTPUTS = (
    registration => {
        credProtect      => "credProtect",
        "hmac-secret"    => "boolean",
        minPinLength     => "count",
        credBlob         => "boolean",
        "hmac-secret-mc" => "bytes",
    },
    authentication => {
        "hmac-secret" => "bytes",
        credBlob      => "bytes",
    },
);

# The authenticator extension each client extension input asks for
my %AUTHENTICATOR_EXTENSION_FOR = (
    credentialProtectionPolicy => "credProtect",
    prf                        => [qw(hmac-secret hmac-secret-mc)],
    hmacCreateSecret           => "hmac-secret",
    minPinLength               => "minPinLength",
    credBlob                   => "credBlob",
    getCredBlob                => "credBlob",
);

# Checks the client and authenticator extension outputs against what was
# requested and against the types above. Returns extension_results and,
# if there are any, authenticator_extensions, without the unsolicited
# outputs it ignored.
sub _check_extensions {
    my ( $ceremony, $client, $requested, $allow_unsolicited, $authenticator ) =
      @_;

    $client //= {};
    _require_map( $client,    "Client extension results" );
    _require_map( $requested, "requested_extensions" ) if defined $requested;

    my ( $solicited_client, $solicited_authenticator );
    if ($requested) {
        $solicited_client        = { map { $_ => 1 } keys %$requested };
        $solicited_authenticator = {
            map { $_ => 1 }
            map {
                my $ids = $AUTHENTICATOR_EXTENSION_FOR{$_} // $_;
                ref $ids ? @$ids : $ids
            } keys %$requested
        };
    }

    my %checked = (
        extension_results => _check_extension_outputs(
            "Client extension",                   $client,
            $CLIENT_EXTENSION_OUTPUTS{$ceremony}, $solicited_client,
            $allow_unsolicited,
        )
    );
    if ( defined $authenticator ) {
        $checked{authenticator_extensions} = _check_extension_outputs(
            "Authenticator extension",
            $authenticator,
            $AUTHENTICATOR_EXTENSION_OUTPUTS{$ceremony},
            $solicited_authenticator,
            $allow_unsolicited,
        );
    }
    return %checked;
}

sub _check_extension_outputs {
    my ( $kind, $outputs, $types, $solicited, $allow_unsolicited ) = @_;

    my %checked;
    for my $id ( sort keys %$outputs ) {
        if ( $solicited and !$solicited->{$id} ) {
            croak("$kind output $id was not requested")
              unless $allow_unsolicited;
            next;
        }
        if ( $types->{$id} ) {
            my $valid = eval {
                _check_extension_value( "$kind output $id",
                    $outputs->{$id}, $types->{$id} );
                1;
            };

            # Without requested_extensions, nothing was asked for: a
            # malformed output is left out of the results, not refused
            unless ($valid) {
                die $@ if $solicited;
                next;
            }
        }
        $checked{$id} = $outputs->{$id};
    }
    return \%checked;
}

my %IS_VALID = (
    boolean   => \&_is_boolean,
    base64url => sub { _is_string( $_[0] ) and $_[0] =~ /^[A-Za-z0-9_-]*$/ },
    bytes     => sub { _is_string( $_[0] ) and !utf8::is_utf8( $_[0] ) },
    count     => sub { _is_string( $_[0] ) and $_[0] =~ /^\d+$/ },

    # userVerificationOptional (1), userVerificationOptionalWithCredentialIDList
    # (2) or userVerificationRequired (3)
    credProtect => sub { _is_string( $_[0] ) and $_[0] =~ /^[123]$/ },
);

sub _check_extension_value {
    my ( $name, $value, $type ) = @_;

    if ( ref($type) eq "HASH" ) {
        _require_map( $value, $name );
        for my $member ( sort keys %$type ) {
            next unless exists $value->{$member};
            _check_extension_value( "$name.$member", $value->{$member},
                $type->{$member} );
        }
        return;
    }
    croak("$name is not a valid $type") unless $IS_VALID{$type}->($value);
    return;
}

sub _is_string {
    my ($value) = @_;
    return ( defined $value and !ref $value );
}

sub _is_boolean {
    my ($value) = @_;
    return 1 if JSON::is_bool($value) or Types::Serialiser::is_bool($value);
    return ( _is_string($value) and $value =~ /^[01]?\z/ );
}

# credProps tells whether the credential is discoverable
sub _discoverable {
    my ($results) = @_;
    my $credProps = $results->{credProps};
    return () unless ref($credProps) eq "HASH" and exists $credProps->{rk};
    return ( discoverable => $credProps->{rk} ? 1 : 0 );
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

# Everything decoded here was sent by the client, so it is decoded here
# rather than by CBOR::XS, which expands string references (tags 25 and
# 256) and shared values whatever its options say: a few bytes become
# gigabytes. WebAuthn uses CTAP2's subset of CBOR: integers, byte and text
# strings, arrays, maps, booleans and null, with definite lengths.
my $CBOR_MAX_DEPTH = 16;

sub _decode_cbor {
    my ($cbor_raw) = @_;
    my ( $value, $length ) = _decode_cbor_prefix($cbor_raw);
    croak("Trailing bytes after CBOR data") if $length < length $cbor_raw;
    return $value;
}

# The first CBOR item, and the number of bytes it took
sub _decode_cbor_prefix {
    my ($cbor_raw) = @_;
    _require_bytes( $cbor_raw, "CBOR data" );
    my $offset = 0;
    my $value  = _cbor_item( \$cbor_raw, \$offset, 0 );
    return ( $value, $offset );
}

sub _cbor_take {
    my ( $data, $offset, $length ) = @_;
    croak("CBOR data is truncated")
      if $length > length($$data) - $$offset;
    my $bytes = substr( $$data, $$offset, $length );
    $$offset += $length;
    return $bytes;
}

sub _cbor_item {
    my ( $data, $offset, $depth ) = @_;
    croak("CBOR data is nested too deeply") if $depth > $CBOR_MAX_DEPTH;

    my $initial = ord _cbor_take( $data, $offset, 1 );
    my ( $major, $info ) = ( $initial >> 5, $initial & 0x1f );

    if ( $major == 7 ) {
        return Types::Serialiser::false if $info == 20;
        return Types::Serialiser::true  if $info == 21;
        return undef                    if $info == 22;    ## no critic (ProhibitExplicitReturnUndef)
        croak("Unsupported CBOR simple value or float");
    }

    my $argument;
    if ( $info < 24 ) {
        $argument = $info;
    }
    elsif ( $info == 24 ) {
        $argument = unpack( "C", _cbor_take( $data, $offset, 1 ) );
    }
    elsif ( $info == 25 ) {
        $argument = unpack( "n", _cbor_take( $data, $offset, 2 ) );
    }
    elsif ( $info == 26 ) {
        $argument = unpack( "N", _cbor_take( $data, $offset, 4 ) );
    }
    elsif ( $info == 27 ) {
        my ( $high, $low ) = unpack( "NN", _cbor_take( $data, $offset, 8 ) );

        # Beyond 2**53 a Perl number on a 32-bit build is no longer exact
        croak("CBOR integer is too large") if $high >= 2**21;
        $argument = $high * 2**32 + $low;
    }
    else {
        croak("Indefinite-length or reserved CBOR item");
    }

    return $argument                               if $major == 0;
    return -1 - $argument                          if $major == 1;
    return _cbor_take( $data, $offset, $argument ) if $major == 2;
    if ( $major == 3 ) {
        my $text = _cbor_take( $data, $offset, $argument );
        $text = eval { Encode::decode( "UTF-8", $text, Encode::FB_CROAK ) };
        croak("CBOR text string is not valid UTF-8") unless defined $text;

        # Marks it as text even when it is ASCII
        utf8::upgrade($text);
        return $text;
    }
    croak("Unexpected CBOR tag $argument") if $major == 6;

    # Every item takes a byte at least: refuse a count the data cannot hold
    # before looping over it
    croak("CBOR data is truncated")
      if $argument > length($$data) - $$offset;
    if ( $major == 4 ) {
        return [ map { _cbor_item( $data, $offset, $depth + 1 ) }
              1 .. $argument ];
    }

    my %map;
    for ( 1 .. $argument ) {

        # Integer and text keys only, and since Perl hash keys are strings,
        # no text key that reads as an integer: "3" would be the label 3
        my $key_major = ord( substr( $$data, $$offset, 1 ) ) >> 5;
        my $key       = _cbor_item( $data, $offset, $depth + 1 );
        croak("Unsupported CBOR map key")
          unless $key_major <= 1
          or ( $key_major == 3 and $key !~ /^-?[0-9]+\z/ );
        croak("Duplicate CBOR map key $key") if exists $map{$key};
        $map{$key} = _cbor_item( $data, $offset, $depth + 1 );
    }
    return \%map;
}

sub _decode_cose_key {
    my ($cose_raw) = @_;
    return _check_cose_key( _decode_cbor($cose_raw) );
}

# kty, alg and crv are compared as Perl strings, where the text "-7" or
# the bytes "-7" would read as ES256: they must have been CBOR integers,
# which the decoder returns as numbers
sub _check_cose_key {
    my ($cose) = @_;
    _require_map( $cose, "Credential public key" );
    my @labels = ( 1, 3 );
    push @labels, -1
      if defined $cose->{1} and ( $cose->{1} eq "1" or $cose->{1} eq "2" );
    for my $label (@labels) {
        my $value = $cose->{$label};
        next unless defined $value;
        croak("Credential public key member $label is not an integer")
          if ref $value
          or
          !( B::svref_2object( \$value )->FLAGS & ( B::SVf_IOK | B::SVf_NOK ) );
    }
    return $cose;
}

# The client data members compared here must be strings
sub _decode_client_data {
    my ($client_data_json) = @_;

    # UTF-8 decode, as both ceremonies say, strips a leading byte order mark.
    # The hash is still computed over the bytes as received.
    ( my $json_text = $client_data_json // "" ) =~ s/\A\xEF\xBB\xBF//;
    my $client_data = eval { decode_json($json_text) };
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

# The decoder marks CBOR text strings as character strings
sub _require_bytes {
    my ( $value, $name ) = @_;
    croak("$name is missing") unless defined $value;
    croak("$name is not a byte string")
      if ref $value
      or utf8::is_utf8($value);
    return $value;
}

sub _require_text {
    my ( $value, $name ) = @_;
    croak("$name is missing") unless defined $value;
    croak("$name is not a text string")
      if ref $value
      or !utf8::is_utf8($value);
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

    my $attn_cert =
      _fix_signature_unused_bits( $attestation_result->{trust_path}->[0] );

    # uncoverable branch true note:Basic attestation always has a certificate
    unless ($attn_cert) {

        # uncoverable statement
        croak("Missing attestation certificate");
    }

    my @trust_chain = @{ $attestation_result->{trust_path} };
    shift @trust_chain;

    # An anchor that does not parse would otherwise fail every chain, or
    # with allow_untrusted_attestation, quietly make every attestation Self
    if ( ref($trust_anchors) eq "ARRAY" ) {
        for my $i ( 0 .. $#$trust_anchors ) {
            next if eval {
                Crypt::OpenSSL::X509->new_from_string( $trust_anchors->[$i],
                    Crypt::OpenSSL::X509::FORMAT_PEM );
            };
            my $error = $@;
            Net::SSLeay::ERR_clear_error();
            croak("Trust anchor $i is not a PEM certificate: $error");
        }
    }

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
    $cose_key = _decode_cose_key($cose_key);

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

    my $pk         = Crypt::PK::ECC->new();
    my $curve_name = $COSE_CURVE_NAME{$curve};
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

# Octet Key Pair (RFC 8152, section 13.2): Ed25519 and Ed448
sub parse_okp_cose {
    my ($cose_struct) = @_;

    my $curve = $cose_struct->{-1} // "(none)";
    my $class = $OKP_CLASS{$curve} or croak "Unsupported curve $curve";

    my $pk = $class->new();
    $pk->import_key_raw( _require_bytes( $cose_struct->{-2}, "OKP key" ),
        'public' );
    return $pk;
}

sub parse_okp_pem {
    my ($pem) = @_;
    for my $class ( @OKP_CLASS{ sort keys %OKP_CLASS } ) {
        my $pk = eval { $class->new( \$pem ) };
        return $pk if $pk;
    }
    croak "Cannot read OKP key";
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

# CryptX converts the key in time quadratic in its size, so a client's
# oversized key is refused before it is read
my $MAX_RSA_BITS           = 4096;
my $MAX_RSA_EXPONENT_BYTES = 32;

sub _rsa_bits {
    my ($modulus) = @_;
    $modulus =~ s/^\x00+//;
    return 0 unless length $modulus;
    return 8 * length($modulus) - 8 + length( sprintf( "%b", ord $modulus ) );
}

sub parse_rsa_cose {
    my ($cose_struct) = @_;
    my $n = _require_bytes( $cose_struct->{-1}, "RSA key modulus" );
    my $e = _require_bytes( $cose_struct->{-2}, "RSA key exponent" );
    s/^\x00+// for $n, $e;

    my $bits = _rsa_bits($n);
    croak("RSA key of $bits bits is too long (max: $MAX_RSA_BITS)")
      if $bits > $MAX_RSA_BITS;
    croak("Invalid RSA key modulus")
      if $bits == 0
      or ord( substr( $n, -1 ) ) % 2 == 0;

    # Odd and at least 3 (RFC 8017, section 3.1)
    croak("Invalid RSA key exponent")
      if length($e) == 0
      or length($e) > $MAX_RSA_EXPONENT_BYTES
      or ord( substr( $e, -1 ) ) % 2 == 0
      or ( length($e) == 1 and ord($e) < 3 );

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

    # A certificate key says its curve only once read: ES256 with a P-384
    # key is not ES256
    if ( $alg_config->{curve} and $public_key->isa("Crypt::PK::ECC") ) {
        my $curve_name = $public_key->key2hash->{curve_name};
        unless ( $curve_name eq $COSE_CURVE_NAME{ $alg_config->{curve} } ) {
            croak "Curve $curve_name cannot be used with algorithm $alg_num";
        }
    }
    if ( $key_type eq "OKP"
        and !$public_key->isa( $OKP_CLASS{ $alg_config->{curve} } ) )
    {
        croak "A "
          . ref($public_key)
          . " key cannot be used with algorithm $alg_num";
    }

    my @signature_options = @{ $alg_config->{signature_options} };
    return $key_type_config->{make_verifier}
      ->( $public_key, @signature_options );
}

# This function takes a Base64url encoded COSE key and returns a verification
# method

sub getPubKeyVerifier {
    my ($pubkey_cose) = @_;
    my $cose_key = _decode_cose_key($pubkey_cose);

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
    my ( $cbor, $length ) = _decode_cbor_prefix($cbor_raw);
    _check_cose_key($cbor);

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
    _require_text( $h->{fmt}, "Attestation statement format" );
    _require_bytes( $h->{authData}, "Authenticator data" );

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
        $x5c = _read_certificate($x5c_der);

        # Crypt::OpenSSL::X509 cannot read Ed25519 keys
        my $alg = $COSE_ALG->{$sig_alg};
        $key =
          ( $alg and $alg->{key_type} eq "OKP" )
          ? $OKP_CLASS{ $alg->{curve} }->new( \$x5c_der )
          ->export_key_pem('public')
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
    _check_aaguid_extension( $x5c, $authenticator_data );

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

# These early Yubico U2F attestation certificates say their signature has
# unused bits, which OpenSSL 1.1 and later refuse. Yubico's libraries set
# the count to 0, as here.
my %UNUSED_BITS_CERTIFICATES = map { ( "CN=Yubico U2F EE Serial $_" => 1 ) }
  qw(776137165 1086591525 1973679733 13503277888 13831167861 14803321578);

sub _fix_signature_unused_bits {
    my ($der) = @_;
    my $x509 = eval { _read_certificate($der) } or return $der;

    # uncoverable condition right note:each has a 2048-bit RSA signature
    return $der
      unless $UNUSED_BITS_CERTIFICATES{ $x509->subject }
      and substr( $der, -261, 4 ) eq "\x03\x82\x01\x01";
    substr( my $fixed = $der, -257, 1 ) = "\0";
    return $fixed;
}

# A DER certificate, with nothing after it
sub _read_certificate {
    my ($der) = @_;
    my $x509 = Crypt::OpenSSL::X509->new_from_string( $der,
        Crypt::OpenSSL::X509::FORMAT_ASN1 );
    croak "Trailing bytes after certificate"
      if length( $x509->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1) ) !=
      length $der;
    return $x509;
}

# If the attestation certificate has an id-fido-gen-ce-aaguid extension,
# it must match the AAGUID in the authenticator data
sub _check_aaguid_extension {
    my ( $x509, $authenticator_data ) = @_;

    my $aaguid_ext = $x509->extensions_by_oid->{'1.3.6.1.4.1.45724.1.1.4'};
    return unless $aaguid_ext;
    croak "id-fido-gen-ce-aaguid extension must not be critical"
      if $aaguid_ext->critical;

    my $ad_aaguid   = $authenticator_data->{attestedCredentialData}->{aaguid};
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
    return;
}

# TPM 2.0 constants (TPM 2.0 Library, Part 2)
my $TPM_GENERATED_VALUE   = 0xff544347;
my $TPM_ST_ATTEST_CERTIFY = 0x8017;
my $TPM_ALG_RSA           = 0x0001;
my $TPM_ALG_ECC           = 0x0023;
my $TPM_ALG_NULL          = 0x0010;
my %TPM_HASH              = (
    0x0004 => \&Digest::SHA::sha1,
    0x000b => \&Digest::SHA::sha256,
    0x000c => \&Digest::SHA::sha384,
    0x000d => \&Digest::SHA::sha512,
);

# TPM_ECC_CURVE to COSE curve
my %TPM_ECC_CURVE = ( 0x0003 => 1, 0x0004 => 2, 0x0005 => 3 );

my %HASH_FUNCTION = (
    SHA1   => \&Digest::SHA::sha1,
    SHA256 => \&Digest::SHA::sha256,
    SHA384 => \&Digest::SHA::sha384,
    SHA512 => \&Digest::SHA::sha512,
);

# Reads TPM structures: big-endian integers and size-prefixed buffers
sub _tpm_reader {
    my ( $bytes, $name ) = @_;

    my $offset = 0;
    my $take   = sub {
        my ($length) = @_;
        croak "$name is truncated" if $offset + $length > length $bytes;
        my $value = substr( $bytes, $offset, $length );
        $offset += $length;
        return $value;
    };
    return {
        u16   => sub { unpack( "n", $take->(2) ) },
        u32   => sub { unpack( "N", $take->(4) ) },
        skip  => sub { $take->(shift); return },
        sized => sub { $take->( unpack( "n", $take->(2) ) ) },
        done  => sub {
            croak "$name has trailing bytes" if $offset != length $bytes;
        },
    };
}

# The key a TPMT_PUBLIC describes, as COSE fields, and its nameAlg
sub _tpm_public_area {
    my ($pub_area) = @_;

    my $read     = _tpm_reader( $pub_area, "pubArea" );
    my $type     = $read->{u16}->();
    my $name_alg = $read->{u16}->();
    $read->{u32}->();      # objectAttributes
    $read->{sized}->();    # authPolicy

    # TPMT_SYM_DEF_OBJECT, then the scheme
    my $symmetric = $read->{u16}->();
    $read->{skip}->(4) unless $symmetric == $TPM_ALG_NULL;
    my $scheme = $read->{u16}->();
    $read->{skip}->(2) unless $scheme == $TPM_ALG_NULL;

    my %key;
    if ( $type == $TPM_ALG_RSA ) {
        $read->{u16}->();    # keyBits
        my $exponent = $read->{u32}->() || 65537;
        %key = (
            kty => 3,
            n   => $read->{sized}->(),
            e   => $exponent,
        );
    }
    elsif ( $type == $TPM_ALG_ECC ) {
        my $curve = $read->{u16}->();
        my $kdf   = $read->{u16}->();
        $read->{skip}->(2) unless $kdf == $TPM_ALG_NULL;
        %key = (
            kty   => 2,
            curve => $TPM_ECC_CURVE{$curve}
              // croak("Unsupported TPM curve $curve"),
            x => $read->{sized}->(),
            y => $read->{sized}->(),
        );
    }
    else {
        croak "Unsupported TPM key type $type";
    }
    $read->{done}->();
    return ( \%key, $name_alg );
}

# Whether the key in pubArea is the credential public key
sub _tpm_same_key {
    my ( $key, $cose_raw ) = @_;

    my $cose = _decode_cose_key($cose_raw);
    return 0 unless ( $cose->{1} // "" ) eq $key->{kty};
    if ( $key->{kty} == 3 ) {
        ( my $e = $cose->{-2} // "" ) =~ s/^\0+//;
        my $exponent = 0;
        $exponent = $exponent * 256 + $_ for unpack( "C*", $e );
        return ( ( $cose->{-1} // "" ) eq $key->{n}
              and $exponent == $key->{e} );
    }
    return (  ( $cose->{-1} // "" ) eq $key->{curve}
          and ( $cose->{-2} // "" ) eq $key->{x}
          and ( $cose->{-3} // "" ) eq $key->{y} );
}

# https://www.w3.org/TR/webauthn-3/#sctn-tpm-cert-requirements
sub _tpm_check_cert_requirements {
    my ($x509) = @_;

    croak "Invalid certificate version" unless $x509->version eq "02";
    croak "Subject is not empty" if @{ $x509->subject_name->entries };

    # Subject Alternative Name: a directoryName with the TPM manufacturer,
    # model and version (TCG EK Credential Profile, section 3.2.9)
    my $san = _certificate_extension( $x509, "2.5.29.17" );
    croak "Missing Subject Alternative Name" unless defined $san;
    my %tpm_attributes;
    my ( $class, $number, $names ) = _der_read($san);
    croak "Invalid Subject Alternative Name"
      unless _der_is( $class, $number, "SEQUENCE" );
    for my $name ( _der_read_all($names) ) {
        next unless $name->[0] == $DER_CONTEXT and $name->[1] == 4;

        # A Name: a SEQUENCE of SETs of SEQUENCEs that start with an OID
        my ( $name_class, $name_number, $rdns ) = _der_read( $name->[2] );
        croak "Invalid Subject Alternative Name"
          unless _der_is( $name_class, $name_number, "SEQUENCE" );
        for my $rdn ( _der_read_all($rdns) ) {
            croak "Invalid Subject Alternative Name"
              unless _der_is( $rdn->[0], $rdn->[1], "SET" );
            for my $attribute ( _der_read_all( $rdn->[2] ) ) {
                my ($type) = _der_read_all( $attribute->[2] );
                croak "Invalid Subject Alternative Name"
                  unless _der_is( $attribute->[0], $attribute->[1], "SEQUENCE" )
                  and $type
                  and _der_is( $type->[0], $type->[1], "OID" );
                $tpm_attributes{ unpack( "H*", $type->[2] ) } = 1;
            }
        }
    }
    for my $oid (qw(6781050201 6781050202 6781050203)) {
        croak "Subject Alternative Name does not name the TPM"
          unless $tpm_attributes{$oid};
    }

    # Extended Key Usage: tcg-kp-AIKCertificate (2.23.133.8.3)
    my $eku = _certificate_extension( $x509, "2.5.29.37" );
    croak "Missing Extended Key Usage" unless defined $eku;
    my ( $eku_class, $eku_number, $usages ) = _der_read($eku);
    croak "Invalid Extended Key Usage"
      unless _der_is( $eku_class, $eku_number, "SEQUENCE" );
    unless (
        grep {
            _der_is( $_->[0], $_->[1], "OID" )
              and unpack( "H*", $_->[2] ) eq "6781050803"
        } _der_read_all($usages)
      )
    {
        croak "Extended Key Usage is not tcg-kp-AIKCertificate";
    }

    my $basic_constraints = $x509->extensions_by_oid->{"2.5.29.19"};
    croak "Missing Basic Constraints extension" unless $basic_constraints;
    croak "Basic Constraints CA is true" if $basic_constraints->basicC("ca");
    return;
}

# https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation
sub attest_tpm {
    my (
        $attestation_statement,  $authenticator_data,
        $authenticator_data_raw, $client_data_hash
    ) = @_;

    # Verify that attStmt is valid CBOR conforming to the syntax defined
    # above and perform CBOR decoding on it to extract the contained fields.
    my ( $ver, $alg_num, $x5c, $sig, $cert_info, $pub_area ) =
      @{$attestation_statement}{qw(ver alg x5c sig certInfo pubArea)};
    croak "Unsupported TPM version" unless ( $ver // "" ) eq "2.0";
    croak "Unsupported algorithm " . ( $alg_num // "(none)" )
      unless defined $alg_num
      and !ref $alg_num
      and $COSE_ALG->{$alg_num};
    _require_bytes( $sig,       "Attestation statement signature" );
    _require_bytes( $cert_info, "certInfo" );
    _require_bytes( $pub_area,  "pubArea" );

    # Verify that the public key specified by the parameters and unique
    # fields of pubArea is identical to the credentialPublicKey in the
    # attestedCredentialData in authenticatorData.
    my ( $key, $name_alg ) = _tpm_public_area($pub_area);
    unless (
        _tpm_same_key(
            $key,
            $authenticator_data->{attestedCredentialData}->{credentialPublicKey}
        )
      )
    {
        croak "Credential public key does not match pubArea";
    }

    # Concatenate authenticatorData and clientDataHash to form
    # attToBeSigned.
    my $att_to_be_signed = $authenticator_data_raw . $client_data_hash;

    # Verify integrity of certInfo
    # - Verify that x5c is present.
    unless ( ref($x5c) eq "ARRAY"
        and @$x5c
        and !grep { !defined $_ or ref $_ } @$x5c )
    {
        croak "Invalid certificate field in attestation statement";
    }
    my $aik_cert = eval { _read_certificate( $x5c->[0] ) }
      or croak "Cannot read attestation certificate: $@";

    # - Verify that aikCert meets the requirements in § 8.3.1 TPM
    #   Attestation Statement Certificate Requirements.
    eval { _tpm_check_cert_requirements($aik_cert) };
    croak "Attestation certificate does not satisfy requirements: $@" if $@;

    # - If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4
    #   (id-fido-gen-ce-aaguid) verify that the value of this extension
    #   matches the aaguid in authenticatorData.
    _check_aaguid_extension( $aik_cert, $authenticator_data );

    # - Verify the sig is a valid signature over certInfo using the
    #   attestation public key in aikCert with the algorithm specified in
    #   alg.
    my $verifier = eval {
        getPEMPubKeyVerifier(
            _certificate_public_key( $aik_cert, $x5c->[0], $alg_num ),
            $alg_num );
    };
    croak "Cannot get signature validator for attestation: $@" if $@;
    croak "Invalid attestation signature"
      unless $verifier->( $sig, $cert_info );

    # Validate that certInfo is valid:
    _tpm_check_cert_info( $cert_info, $alg_num, $att_to_be_signed, $pub_area,
        $name_alg );

    # - If successful, return implementation-specific values representing
    #   attestation type AttCA and attestation trust path x5c.
    return {
        success    => 1,
        type       => "AttCA",
        trust_path => $x5c,
    };
}

sub _tpm_check_cert_info {
    my ( $cert_info, $alg_num, $att_to_be_signed, $pub_area, $name_alg ) = @_;

    my $read = _tpm_reader( $cert_info, "certInfo" );

    # - Verify that magic is set to TPM_GENERATED_VALUE.
    croak "certInfo magic is not TPM_GENERATED_VALUE"
      unless $read->{u32}->() == $TPM_GENERATED_VALUE;

    # - Verify that type is set to TPM_ST_ATTEST_CERTIFY.
    croak "certInfo type is not TPM_ST_ATTEST_CERTIFY"
      unless $read->{u16}->() == $TPM_ST_ATTEST_CERTIFY;

    # - Verify that extraData is set to the hash of attToBeSigned using the
    #   hash algorithm employed in "alg".
    $read->{sized}->();    # qualifiedSigner
    my $extra_data = $read->{sized}->();
    my $hash =
      $HASH_FUNCTION{ $COSE_ALG->{$alg_num}->{signature_options}->[0] // "" }
      or croak "Algorithm $alg_num has no hash for extraData";
    croak "certInfo extraData does not match"
      unless $extra_data eq $hash->($att_to_be_signed);

    # - Verify that attested contains a TPMS_CERTIFY_INFO structure as
    #   specified in [TPMv2-Part2] section 10.12.3, whose name field contains
    #   a valid Name for pubArea, as computed using the procedure specified
    #   in [TPMv2-Part1] section 16 using the nameAlg in the pubArea.
    $read->{skip}->(17);    # clockInfo
    $read->{skip}->(8);     # firmwareVersion
    my $name = $read->{sized}->();
    $read->{sized}->();     # qualifiedName
    $read->{done}->();
    my $name_hash = $TPM_HASH{$name_alg}
      or croak "Unsupported pubArea nameAlg $name_alg";
    croak "certInfo name does not match pubArea"
      unless $name eq pack( "n", $name_alg ) . $name_hash->($pub_area);
    return;
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

# Reads one DER (X.690) value: returns its class and constructed bits (the
# top three bits of the first byte), its tag number, its contents, and the
# rest of the input. Enough of DER to read the attestation certificate
# extensions: definite lengths only.
sub _der_read {
    my ($der) = @_;

    my $offset = 0;
    my $take   = sub {
        my ($length) = @_;
        croak("DER value is truncated") if $length > length($der) - $offset;
        my $bytes = substr( $der, $offset, $length );
        $offset += $length;
        return $bytes;
    };

    my $identifier = unpack( "C", $take->(1) );
    my $number     = $identifier & 0x1f;
    if ( $number == 0x1f ) {
        $number = 0;
        while (1) {
            my $byte = unpack( "C", $take->(1) );
            $number = ( $number << 7 ) | ( $byte & 0x7f );
            croak("DER tag is too long") if $number > 0xffffff;
            last unless $byte & 0x80;
        }
    }
    my $length = unpack( "C", $take->(1) );
    if ( $length & 0x80 ) {
        my $bytes = $length & 0x7f;
        croak("DER length is not supported") if $bytes < 1 or $bytes > 4;
        $length = unpack( "N", ( "\0" x ( 4 - $bytes ) ) . $take->($bytes) );
    }
    my $contents = $take->($length);
    return ( $identifier & 0xe0, $number, $contents, substr( $der, $offset ) );
}

sub _der_is {
    my ( $class, $number, $type ) = @_;
    return ( $class == $DER{$type}->[0] and $number == $DER{$type}->[1] );
}

# Reads all the DER values in a constructed value's contents
sub _der_read_all {
    my ($der) = @_;

    my @values;
    while ( length $der ) {
        my ( $class, $number, $contents );
        ( $class, $number, $contents, $der ) = _der_read($der);
        push @values, [ $class, $number, $contents ];
    }
    return @values;
}

# A non-negative DER INTEGER or ENUMERATED, as a number
sub _der_unsigned {
    my ($contents) = @_;

    croak("DER integer is empty") unless length $contents;
    croak("DER integer is negative or too large")
      if unpack( "C", $contents ) & 0x80
      or length($contents) > 5;
    my $value = 0;
    $value = $value * 256 + $_ for unpack( "C*", $contents );
    return $value;
}

# The value of a certificate extension, as DER, or undef if absent
sub _certificate_extension {
    my ( $x509, $oid ) = @_;

    my $extension = $x509->extensions_by_oid->{$oid} or return;

    # uncoverable condition right note:OpenSSL writes unknown extensions as hex
    my ($hex) = $extension->value =~ /^#([0-9A-Fa-f]*)$/
      or croak("Cannot read certificate extension $oid");
    return pack( "H*", $hex );
}

# Whether a COSE credential public key and the public key of a DER
# certificate are the same key
sub _same_public_key {
    my ( $cose_raw, $certificate_der ) = @_;

    my $cose = _decode_cose_key($cose_raw);

    # uncoverable condition right note:the credential key is checked first
    my $alg = $COSE_ALG->{ $cose->{3} // "" }
      or croak( "Unsupported algorithm " . ( $cose->{3} // "(none)" ) );
    my $credential  = $KEY_TYPES->{ $alg->{key_type} }->{parse_cose}->($cose);
    my $certificate = eval { ref($credential)->new( \$certificate_der ) }
      or return 0;

    return $credential->export_key_der("public") eq
      $certificate->export_key_der("public");
}

# The nonce in Apple's extension: a SEQUENCE holding an [1] holding an OCTET
# STRING
sub _apple_nonce {
    my ($extension) = @_;

    my ( $sequence_class, $sequence_number, $sequence ) = _der_read($extension);
    my ( $explicit_class, $explicit_number, $explicit ) = _der_read($sequence);
    my ( $octets_class,   $octets_number,   $octets )   = _der_read($explicit);
    unless ( _der_is( $sequence_class, $sequence_number, "SEQUENCE" )
        and $explicit_class == $DER_CONTEXT
        and $explicit_number == 1
        and _der_is( $octets_class, $octets_number, "OCTET_STRING" ) )
    {
        croak "Invalid nonce extension in attestation certificate";
    }
    return $octets;
}

# https://www.w3.org/TR/webauthn-3/#sctn-apple-anonymous-attestation
sub attest_apple {
    my (
        $attestation_statement,  $authenticator_data,
        $authenticator_data_raw, $client_data_hash
    ) = @_;

    # 1. Verify that attStmt is valid CBOR conforming to the syntax defined
    # above and perform CBOR decoding on it to extract the contained fields.
    my $x5c = $attestation_statement->{x5c};
    unless ( ref($x5c) eq "ARRAY"
        and @$x5c
        and !grep { !defined $_ or ref $_ } @$x5c )
    {
        croak "Invalid certificate field in attestation statement";
    }
    my $cred_cert = eval { _read_certificate( $x5c->[0] ) }
      or croak "Cannot read attestation certificate: $@";

    # 2. Concatenate authenticatorData and clientDataHash to form
    # nonceToHash.
    # 3. Perform SHA-256 hash of nonceToHash to produce nonce.
    my $nonce = sha256( $authenticator_data_raw . $client_data_hash );

    # 4. Verify that nonce equals the value of the extension with OID
    # 1.2.840.113635.100.8.2 in credCert.
    my $extension =
      _certificate_extension( $cred_cert, "1.2.840.113635.100.8.2" );
    croak "Missing nonce extension in attestation certificate"
      unless defined $extension;
    croak "Attestation nonce does not match"
      unless _apple_nonce($extension) eq $nonce;

    # 5. Verify that the credential public key equals the Subject Public Key
    # of credCert.
    unless (
        _same_public_key(
            $authenticator_data->{attestedCredentialData}
              ->{credentialPublicKey},
            $x5c->[0]
        )
      )
    {
        croak "Credential public key does not match attestation certificate";
    }

    # 6. If successful, return implementation-specific values representing
    # attestation type Anonymization CA and attestation trust path x5c.
    return {
        success    => 1,
        type       => "AnonCA",
        trust_path => $x5c,
    };
}

# The public key of an attestation certificate, as PEM. Crypt::OpenSSL::X509
# cannot read Ed25519 keys.
sub _certificate_public_key {
    my ( $x509, $certificate_der, $alg_num ) = @_;

    my $alg = $COSE_ALG->{$alg_num};
    return $OKP_CLASS{ $alg->{curve} }->new( \$certificate_der )
      ->export_key_pem('public')
      if $alg and $alg->{key_type} eq "OKP";
    return $x509->pubkey();
}

# Android KeyMaster/KeyMint values the verification procedure names
my $KM_ORIGIN_GENERATED = 0;
my $KM_PURPOSE_SIGN     = 2;

# https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation
sub attest_android_key {
    my (
        $attestation_statement, $authenticator_data, $authenticator_data_raw,
        $client_data_hash,      $options
    ) = @_;

    # Verify that attStmt is valid CBOR conforming to the syntax defined
    # above and perform CBOR decoding on it to extract the contained fields.
    my $alg_num = $attestation_statement->{alg};
    my $sig     = $attestation_statement->{sig};
    my $x5c     = $attestation_statement->{x5c};
    croak "Missing algorithm field in attestation statement"
      unless defined $alg_num and !ref $alg_num;
    _require_bytes( $sig, "Attestation statement signature" );
    unless ( ref($x5c) eq "ARRAY"
        and @$x5c
        and !grep { !defined $_ or ref $_ } @$x5c )
    {
        croak "Invalid certificate field in attestation statement";
    }
    my $cred_cert = eval { _read_certificate( $x5c->[0] ) }
      or croak "Cannot read attestation certificate: $@";

    # Verify that sig is a valid signature over the concatenation of
    # authenticatorData and clientDataHash using the public key in the first
    # certificate in x5c with the algorithm specified in alg.
    my $verifier = eval {
        getPEMPubKeyVerifier(
            _certificate_public_key( $cred_cert, $x5c->[0], $alg_num ),
            $alg_num );
    };
    croak "Cannot get signature validator for attestation: $@" if $@;
    croak "Invalid attestation signature"
      unless $verifier->( $sig, $authenticator_data_raw . $client_data_hash );

    # Verify that the public key in the first certificate in x5c matches the
    # credentialPublicKey in the attestedCredentialData in
    # authenticatorData.
    unless (
        _same_public_key(
            $authenticator_data->{attestedCredentialData}
              ->{credentialPublicKey},
            $x5c->[0]
        )
      )
    {
        croak "Credential public key does not match attestation certificate";
    }

    # Verify that the attestationChallenge field in the attestation
    # certificate extension data is identical to clientDataHash.
    my $extension =
      _certificate_extension( $cred_cert, "1.3.6.1.4.1.11129.2.1.17" );
    croak "Missing key description extension in attestation certificate"
      unless defined $extension;
    _check_android_key_description( _android_key_description($extension),
        $client_data_hash, $options );

    # If successful, return implementation-specific values representing
    # attestation type Basic and attestation trust path x5c.
    return {
        success    => 1,
        type       => "Basic",
        trust_path => $x5c,
    };
}

sub _check_android_key_description {
    my ( $description, $client_data_hash, $options ) = @_;

    croak "Attestation challenge does not match"
      unless $description->{attestation_challenge} eq $client_data_hash;

    # Verify the following using the appropriate authorization list from
    # the attestation certificate extension data:
    # - The AuthorizationList.allApplications field is not present on either
    #   authorization list (softwareEnforced nor teeEnforced), since
    #   PublicKeyCredential MUST be scoped to the RP ID.
    if (   $description->{software_enforced}->{all_applications}
        or $description->{tee_enforced}->{all_applications} )
    {
        croak "Attestation key is not scoped to the RP ID (allApplications)";
    }

    # - For the following, use only the teeEnforced authorization list if
    #   the RP wants to accept only keys from a trusted execution
    #   environment, otherwise use the union of teeEnforced and
    #   softwareEnforced.
    my @lists = ( $description->{tee_enforced} );
    push @lists, $description->{software_enforced}
      unless $options->{android_key_require_tee};

    #   - The value in the AuthorizationList.origin field is equal to
    #     KM_ORIGIN_GENERATED.
    #   - The value in the AuthorizationList.purpose field is equal to
    #     KM_PURPOSE_SIGN.
    unless ( grep { ( $_->{origin} // -1 ) == $KM_ORIGIN_GENERATED } @lists ) {
        croak "Attestation key was not generated by the authenticator";
    }
    unless (
        grep {
            grep { $_ == $KM_PURPOSE_SIGN }
              @{ $_->{purpose} }
        } @lists
      )
    {
        croak "Attestation key is not for signing";
    }
    return;
}

# The parts of an Android key description (OID 1.3.6.1.4.1.11129.2.1.17)
# the verification procedure uses
# https://developer.android.com/privacy-and-security/security-key-attestation#certificate_schema
sub _android_key_description {
    my ($der) = @_;

    my ( $class, $number, $contents ) = _der_read($der);
    croak "Invalid key description in attestation certificate"
      unless _der_is( $class, $number, "SEQUENCE" );
    my @fields = _der_read_all($contents);

    # attestationVersion, attestationSecurityLevel, keymasterVersion,
    # keymasterSecurityLevel, attestationChallenge, uniqueId,
    # softwareEnforced, teeEnforced
    unless ( @fields >= 8
        and _der_is( @{ $fields[4] }[ 0, 1 ], "OCTET_STRING" )
        and _der_is( @{ $fields[6] }[ 0, 1 ], "SEQUENCE" )
        and _der_is( @{ $fields[7] }[ 0, 1 ], "SEQUENCE" ) )
    {
        croak "Invalid key description in attestation certificate";
    }
    return {
        attestation_challenge => $fields[4]->[2],
        software_enforced     => _android_authorization_list( $fields[6]->[2] ),
        tee_enforced          => _android_authorization_list( $fields[7]->[2] ),
    };
}

# purpose [1], allApplications [600] and origin [702] of an
# AuthorizationList; the other fields are not used
sub _android_authorization_list {
    my ($der) = @_;

    my %list = ( purpose => [] );
    for my $field ( _der_read_all($der) ) {
        my ( $class, $number, $contents ) = @$field;
        next unless $class == $DER_CONTEXT;
        if ( $number == 1 ) {
            my ( $set_class, $set_number, $set ) = _der_read($contents);
            croak "Invalid purpose in key description"
              unless _der_is( $set_class, $set_number, "SET" );
            $list{purpose} = [
                map  { _der_unsigned( $_->[2] ) }
                grep { _der_is( @{$_}[ 0, 1 ], "INTEGER" ) } _der_read_all($set)
            ];
        }
        elsif ( $number == 600 ) {
            $list{all_applications} = 1;
        }
        elsif ( $number == 702 ) {
            my ( $integer_class, $integer_number, $integer ) =
              _der_read($contents);
            croak "Invalid origin in key description"
              unless _der_is( $integer_class, $integer_number, "INTEGER" );
            $list{origin} = _der_unsigned($integer);
        }
    }
    return \%list;
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
    unless ( @{ $attestation_statement->{x5c} } == 1 ) {
        croak "fido-u2f attestation must have exactly one certificate";
    }

    my $x5c_der         = $attestation_statement->{x5c}->[0];
    my $attestation_key = Crypt::PK::ECC->new();
    eval {
        my $x5c     = _read_certificate($x5c_der);
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
