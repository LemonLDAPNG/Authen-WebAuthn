use Test::More;
use CBOR::XS;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use Digest::SHA  qw(sha256);
use JSON         qw(decode_json);
use MIME::Base64 qw(encode_base64 encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# The apple, android-key and tpm attestation formats. The specification's
# test vectors (t/21-Spec-test-vectors.t) show each accepts a valid
# attestation; this tests what each refuses.

my $vectors = do {
    open my $fh, "<", "t/spec-vectors/vectors.json" or die "vectors.json: $!";
    local $/;
    decode_json(<$fh>);
};
my $root_pem = "-----BEGIN CERTIFICATE-----\n"
  . encode_base64( pack "H*",
    $vectors->{"sctn-test-vectors-attestation-root-cert"}->{common}
      ->{attestation_ca_cert} )
  . "-----END CERTIFICATE-----\n";

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

sub der_certificate {
    return Crypt::OpenSSL::X509->new_from_string( pem(shift) )
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
}

# Just enough DER to build test inputs
sub der {
    my ( $identifier, $contents ) = @_;
    my $length = length $contents;
    my $encoded_length =
        $length < 0x80  ? pack( "C", $length )
      : $length < 0x100 ? pack( "CC", 0x81, $length )
      :                   pack( "Cn", 0x82, $length );
    return $identifier . $encoded_length . $contents;
}

my $rp = Authen::WebAuthn->new(
    rp_id  => "example.org",
    origin => "https://example.org",
);

# A vector's registration, decoded, so its parts can be changed
sub registration {
    my ($name) = @_;
    my $r      = $vectors->{"sctn-test-vectors-$name"}->{registration};
    my $object = CBOR::XS::decode_cbor( pack "H*", $r->{attestationObject} );
    my $client_data_json = pack "H*", $r->{clientDataJSON};
    return {
        challenge          => $r->{challenge},
        client_data_json   => $client_data_json,
        client_data_hash   => sha256($client_data_json),
        object             => $object,
        statement          => $object->{attStmt},
        authenticator_data =>
          Authen::WebAuthn::getAuthData( $object->{authData} ),
        authenticator_data_raw => $object->{authData},
    };
}

sub register {
    my ( $registration, %options ) = @_;
    return scalar eval {
        $rp->validate_registration(
            challenge_b64 =>
              encode_base64url( pack "H*", $registration->{challenge} ),
            client_data_json_b64 =>
              encode_base64url( $registration->{client_data_json} ),
            attestation_object_b64 => encode_base64url(
                CBOR::XS->new->text_keys(1)->encode( $registration->{object} )
            ),
            trust_anchors => [$root_pem],
            %options,
        );
    };
}

# Calls an attestation function directly, with a statement and
# authenticator data that may have been changed after the fact
sub attest {
    my ( $function, $registration, %change ) = @_;
    my $statement =
      { %{ $registration->{statement} }, %{ $change{statement} || {} } };
    my $authenticator_data = $registration->{authenticator_data};
    if ( $change{credential_public_key} ) {
        $authenticator_data = {
            %$authenticator_data,
            attestedCredentialData => {
                %{ $authenticator_data->{attestedCredentialData} },
                credentialPublicKey => $change{credential_public_key},
            },
        };
    }
    no strict 'refs';
    return scalar eval {
        &{"Authen::WebAuthn::$function"}(
            $statement,
            $authenticator_data,
            $change{authenticator_data_raw}
              // $registration->{authenticator_data_raw},
            $change{client_data_hash} // $registration->{client_data_hash},
            $change{options} || {},
        );
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

my $other_key = do {
    my $key = Crypt::PK::ECC->new;
    $key->generate_key("secp256r1");
    Authen::WebAuthn::Test->new(
        key           => $key->export_key_pem("private"),
        credential_id => "x",
    )->encode_cosekey;
};

subtest "apple" => sub {
    my $apple = registration("apple-es256");

    # The same client data with a space added: a different hash, so a
    # different nonce
    my $changed = {
        %$apple,
        client_data_json => "{ " . substr( $apple->{client_data_json}, 1 )
    };
    refused(
        register($changed),
        qr/Attestation nonce does not match/,
        "Client data other than what the nonce covers"
    );

    refused(
        attest( "attest_apple", $apple, credential_public_key => $other_key ),
        qr/Credential public key does not match attestation certificate/,
        "A credential key other than the certificate's"
    );
    refused(
        attest(
            "attest_apple", $apple,
            statement => { x5c => [ der_certificate("packed-p256") ] }
        ),
        qr/Missing nonce extension in attestation certificate/,
        "A certificate without the nonce extension"
    );
    refused(
        attest( "attest_apple", $apple, statement => { x5c => "x" } ),
        qr/Invalid certificate field in attestation statement/,
        "A certificate field that is not a list"
    );
    refused(
        attest( "attest_apple", $apple, statement => { x5c => ["x"] } ),
        qr/Cannot read attestation certificate/,
        "A certificate that does not parse"
    );

    is(
        Authen::WebAuthn::_apple_nonce(
            der( "\x30", der( "\xa1", der( "\x04", "nonce" ) ) )
        ),
        "nonce",
        "The nonce is read from its extension"
    );
    eval {
        Authen::WebAuthn::_apple_nonce(
            der( "\x30", der( "\xa2", der( "\x04", "nonce" ) ) ) );
    };
    like( $@, qr/Invalid nonce extension/, "Another tag is refused" );
};

subtest "android-key" => sub {
    my $android = registration("android-key-es256");

    ok(
        register( $android, android_key_require_tee => 1 ),
        "A key in the TEE is accepted when only the TEE is"
    ) or diag($@);

    my %tampered = %$android;
    $tampered{statement} = {
        %{ $android->{statement} },
        sig => scalar reverse $android->{statement}->{sig}
    };
    $tampered{object} =
      { %{ $android->{object} }, attStmt => $tampered{statement} };
    refused(
        register( \%tampered ),
        qr/Invalid attestation signature/,
        "A wrong signature"
    );

    refused(
        attest(
            "attest_android_key", $android,
            credential_public_key => $other_key
        ),
        qr/Credential public key does not match attestation certificate/,
        "A credential key other than the certificate's"
    );
    refused(
        attest( "attest_android_key", $android, statement => { alg => undef } ),
        qr/Missing algorithm field/,
        "No algorithm"
    );
    refused(
        attest( "attest_android_key", $android, statement => { x5c => [] } ),
        qr/Invalid certificate field/,
        "No certificate"
    );
    refused(
        attest( "attest_android_key", $android, statement => { x5c => ["x"] } ),
        qr/Cannot read attestation certificate/,
        "A certificate that does not parse"
    );
    refused(
        attest( "attest_android_key", $android, statement => { alg => -257 } ),
        qr/Cannot get signature validator for attestation/,
        "An algorithm that is not the certificate key's"
    );

    # Signed properly, by a certificate without the key description
    my $key  = Crypt::PK::ECC->new( \pem("packed-p256-key") );
    my $cose = Authen::WebAuthn::Test->new(
        key           => pem("packed-p256-key"),
        credential_id => "x",
    )->encode_cosekey;
    refused(
        attest(
            "attest_android_key",
            $android,
            credential_public_key => $cose,
            statement             => {
                x5c => [ der_certificate("packed-p256") ],
                sig => $key->sign_message(
                    $android->{authenticator_data_raw}
                      . $android->{client_data_hash},
                    "SHA256"
                ),
            },
        ),
        qr/Missing key description extension/,
        "A certificate without the key description"
    );
};

subtest "android-key description" => sub {
    my $context = sub {    # [n] EXPLICIT, n > 30 in high-tag form
        my ( $number, $contents ) = @_;
        my $identifier =
          $number < 31 ? pack( "C", 0xa0 + $number )
          : pack( "C", 0xbf )
          . (
            $number < 128 ? pack( "C", $number )
            : pack( "CC", 0x80 | ( $number >> 7 ), $number & 0x7f )
          );
        return der( $identifier, $contents );
    };
    my $integer     = sub { der( "\x02", pack( "C", shift ) ) };
    my $list        = sub { der( "\x30", join "", @_ ) };
    my $description = sub {
        my ( $software, $tee ) = @_;
        return der(
            "\x30",                     join "",
            $integer->(3),              der( "\x0a", "\x01" ),
            $integer->(4),              der( "\x0a", "\x01" ),
            der( "\x04", "challenge" ), der( "\x04", "" ),
            $software,                  $tee
        );
    };

    my $parsed = Authen::WebAuthn::_android_key_description(
        $description->(
            $list->( $context->( 600, "\x05\x00" ) ),
            $list->(
                $context->( 1,   der( "\x31", $integer->(2) . $integer->(3) ) ),
                $context->( 702, $integer->(0) ),
                $context->( 5,   der( "\x31", $integer->(4) ) ),
            ),
        )
    );
    is_deeply(
        $parsed,
        {
            attestation_challenge => "challenge",
            software_enforced => { purpose => [],       all_applications => 1 },
            tee_enforced      => { purpose => [ 2, 3 ], origin           => 0 },
        },
        "Purpose, allApplications and origin are read, other fields skipped"
    );

    my $invalid = sub {
        my ( $der, $message, $name ) = @_;
        eval { Authen::WebAuthn::_android_key_description($der) };
        like( $@, $message, $name );
    };
    $invalid->(
        der( "\x31", "" ),
        qr/Invalid key description/,
        "Not a sequence"
    );
    $invalid->(
        der( "\x30", $integer->(3) ),
        qr/Invalid key description/,
        "Too few fields"
    );
    $invalid->(
        $description->( $list->(), $list->( $context->( 1, $integer->(2) ) ) ),
        qr/Invalid purpose in key description/,
        "A purpose that is not a set"
    );
    $invalid->(
        $description->(
            $list->(), $list->( $context->( 702, der( "\x04", "0" ) ) )
        ),
        qr/Invalid origin in key description/,
        "An origin that is not an integer"
    );

    my $check = sub {
        my ( $software, $tee, %options ) = @_;
        return scalar eval {
            Authen::WebAuthn::_check_android_key_description(
                {
                    attestation_challenge => "hash",
                    software_enforced     => { purpose => [], %$software },
                    tee_enforced          => { purpose => [], %$tee },
                },
                $options{hash} // "hash",
                \%options
            );
            1;
        };
    };
    ok( $check->( {}, { origin => 0, purpose => [2] } ), "A valid key" );
    refused(
        $check->( {}, { origin => 0, purpose => [2] }, hash => "other" ),
        qr/Attestation challenge does not match/,
        "Another challenge"
    );
    refused(
        $check->( { all_applications => 1 }, { origin => 0, purpose => [2] } ),
        qr/not scoped to the RP ID/,
        "allApplications in softwareEnforced"
    );
    refused(
        $check->( {}, { all_applications => 1, origin => 0, purpose => [2] } ),
        qr/not scoped to the RP ID/,
        "allApplications in teeEnforced"
    );
    refused(
        $check->( {}, { origin => 1, purpose => [2] } ),
        qr/was not generated by the authenticator/,
        "An imported key"
    );
    refused(
        $check->( {}, { origin => 0, purpose => [3] } ),
        qr/is not for signing/,
        "A key not for signing"
    );
    ok(
        $check->( { origin => 0, purpose => [2] }, {} ),
        "Software-enforced values, accepted by default"
    );
    refused(
        $check->(
            { origin => 0, purpose => [2] },
            {},
            android_key_require_tee => 1
        ),
        qr/was not generated by the authenticator/,
        "... and refused when only the TEE is accepted"
    );
};

subtest "tpm" => sub {
    my $tpm = registration("tpm-es256");

    for my $field (qw(ver pubArea)) {
        my %changed   = %$tpm;
        my %statement = %{ $tpm->{statement} };
        if ( $field eq "ver" ) {
            $statement{ver} = "1.2";
        }
        else {
            substr( $statement{pubArea}, -1 ) ^= "\x01";
        }
        $changed{object} = { %{ $tpm->{object} }, attStmt => \%statement };
        refused(
            register( \%changed ),
            $field eq "ver"
            ? qr/Unsupported TPM version/
            : qr/Credential public key does not match pubArea/,
            "A changed $field"
        );
    }

    refused(
        attest(
            "attest_tpm", $tpm,
            statement => { sig => scalar reverse $tpm->{statement}->{sig} }
        ),
        qr/Invalid attestation signature/,
        "A wrong signature"
    );
    refused(
        attest( "attest_tpm", $tpm, statement => { alg => -999 } ),
        qr/Unsupported algorithm -999/,
        "An unsupported algorithm"
    );
    refused(
        attest( "attest_tpm", $tpm, statement => { x5c => [] } ),
        qr/Invalid certificate field/,
        "No certificate"
    );
    refused(
        attest( "attest_tpm", $tpm, statement => { x5c => ["x"] } ),
        qr/Cannot read attestation certificate/,
        "A certificate that does not parse"
    );
    refused(
        attest(
            "attest_tpm", $tpm,
            statement => { x5c => [ der_certificate("packed-p256") ] }
        ),
qr/Attestation certificate does not satisfy requirements: Subject is not empty/,
        "A certificate that is not an AIK certificate"
    );
};

subtest "tpm certificate requirements" => sub {
    my $check = sub {
        my ($name) = @_;
        my $x509 = Crypt::OpenSSL::X509->new_from_string( pem($name) );
        return scalar eval {
            Authen::WebAuthn::_tpm_check_cert_requirements($x509);
            1;
        };
    };
    ok( $check->("tpm-aik"), "A valid AIK certificate" ) or diag($@);
    my %expected = (
        "bad-v1"        => qr/Invalid certificate version/,
        "packed-p256"   => qr/Subject is not empty/,
        "tpm-no-san"    => qr/Missing Subject Alternative Name/,
        "tpm-san-other" => qr/Subject Alternative Name does not name the TPM/,
        "tpm-no-eku"    => qr/Missing Extended Key Usage/,
        "tpm-eku-other" => qr/Extended Key Usage is not tcg-kp-AIKCertificate/,
        "tpm-ca"        => qr/Basic Constraints CA is true/,
        "tpm-no-bc"     => qr/Missing Basic Constraints extension/,
    );
    for my $name ( sort keys %expected ) {
        refused( $check->($name), $expected{$name}, $name );
    }
};

subtest "tpm certInfo" => sub {
    my $tpm = registration("tpm-es256");
    my ( undef, $name_alg ) =
      Authen::WebAuthn::_tpm_public_area( $tpm->{statement}->{pubArea} );
    my $att_to_be_signed =
      $tpm->{authenticator_data_raw} . $tpm->{client_data_hash};
    my $cert_info = $tpm->{statement}->{certInfo};

    my $check = sub {
        my ( $info, %args ) = @_;
        return scalar eval {
            Authen::WebAuthn::_tpm_check_cert_info(
                $info, $args{alg} // -7,
                $att_to_be_signed,
                $tpm->{statement}->{pubArea},
                $args{name_alg} // $name_alg,
            );
            1;
        };
    };
    ok( $check->($cert_info), "The vector's certInfo is valid" ) or diag($@);

    # magic (4 bytes), type (2), qualifiedSigner (2 + n), extraData (2 + n)
    my $signer_length = unpack( "n", substr( $cert_info, 6, 2 ) );
    my $extra_data_at = 8 + $signer_length + 2;
    my $changed       = sub {
        my ( $offset, $byte ) = @_;
        my $info = $cert_info;
        substr( $info, $offset, 1 ) ^= $byte // "\x01";
        return $info;
    };
    refused(
        $check->( $changed->(0) ),
        qr/magic is not TPM_GENERATED_VALUE/,
        "Another magic"
    );
    refused(
        $check->( $changed->(4) ),
        qr/type is not TPM_ST_ATTEST_CERTIFY/,
        "Another type"
    );
    refused(
        $check->( $changed->($extra_data_at) ),
        qr/extraData does not match/,
        "Another extraData"
    );
    refused(
        $check->( $changed->( length($cert_info) - 3 ) ),
        qr/name does not match pubArea/,
        "Another name"
    );
    refused(
        $check->( $cert_info . "\0" ),
        qr/certInfo has trailing bytes/,
        "Trailing bytes"
    );
    refused( $check->( substr( $cert_info, 0, 20 ) ),
        qr/certInfo is truncated/, "Truncated" );
    refused(
        $check->( $cert_info, alg => -8 ),
        qr/Algorithm -8 has no hash for extraData/,
        "An algorithm without a hash"
    );
    refused(
        $check->( $cert_info, name_alg => 0x9999 ),
        qr/Unsupported pubArea nameAlg/,
        "An unsupported nameAlg"
    );
};

subtest "tpm pubArea" => sub {
    my $pub_area = sub {
        my (%f)   = @_;
        my $sized = sub { pack( "n", length $_[0] ) . $_[0] };
        my $area  = pack( "nnN", $f{type}, 0x000b, 0 ) . $sized->("");
        $area .= pack( "n",  $f{symmetric} // 0x0010 );
        $area .= pack( "nn", 128, 0x0043 ) if defined $f{symmetric};
        $area .= pack( "n",  $f{scheme} // 0x0010 );
        $area .= pack( "n",  0x000b ) if defined $f{scheme};
        if ( $f{type} == 0x0001 ) {
            $area .= pack( "nN", 2048, $f{exponent} // 0 ) . $sized->( $f{n} );
        }
        else {
            $area .= pack( "n", $f{curve} // 0x0003 );
            $area .= pack( "n", $f{kdf}   // 0x0010 );
            $area .= pack( "n", 0x000b ) if defined $f{kdf};
            $area .= $sized->( $f{x} ) . $sized->( $f{y} );
        }
        return $area;
    };
    my $n = "\xc1" . ( "\x02" x 255 );

    my ( $key, $name_alg ) =
      Authen::WebAuthn::_tpm_public_area(
        $pub_area->( type => 0x0001, n => $n ) );
    is_deeply(
        $key,
        { kty => 3, n => $n, e => 65537 },
        "An RSA key, with the default exponent"
    );
    is( $name_alg, 0x000b, "... and its nameAlg" );

    my $rsa_cose = Authen::WebAuthn::Test::_canonical_cbor(
        { 1 => 3, 3 => -257, -1 => $n, -2 => "\x01\x00\x01" } );
    ok(
        Authen::WebAuthn::_tpm_same_key( $key, $rsa_cose ),
        "... which is the same as the COSE key"
    );
    ok( !Authen::WebAuthn::_tpm_same_key( { %$key, e => 3 }, $rsa_cose ),
        "... and not with another exponent" );
    ok( !Authen::WebAuthn::_tpm_same_key( $key, $other_key ),
        "... nor with another key type" );

    ( $key, undef ) = Authen::WebAuthn::_tpm_public_area(
        $pub_area->(
            type      => 0x0023,
            symmetric => 0x0006,
            scheme    => 0x0018,
            kdf       => 0x0020,
            curve     => 0x0004,
            x         => "x" x 48,
            y         => "y" x 48,
        )
    );
    is_deeply(
        $key,
        { kty => 2, curve => 2, x => "x" x 48, y => "y" x 48 },
        "An ECC key on P-384, with symmetric, scheme and kdf set"
    );

    my $invalid = sub {
        my ( $area, $message, $name ) = @_;
        eval { Authen::WebAuthn::_tpm_public_area($area) };
        like( $@, $message, $name );
    };
    $invalid->(
        $pub_area->( type => 0x0008 ),
        qr/Unsupported TPM key type 8/,
        "Another key type"
    );
    $invalid->(
        $pub_area->( type => 0x0023, curve => 0x0010, x => "", y => "" ),
        qr/Unsupported TPM curve 16/,
        "Another curve"
    );
    $invalid->(
        substr( $pub_area->( type => 0x0001, n => $n ), 0, 20 ),
        qr/pubArea is truncated/, "Truncated"
    );
    $invalid->(
        $pub_area->( type => 0x0001, n => $n ) . "\0",
        qr/pubArea has trailing bytes/,
        "Trailing bytes"
    );
};

subtest "DER" => sub {
    my @value = Authen::WebAuthn::_der_read( "\x04\x81\x02ab" . "rest" );
    is_deeply( \@value, [ 0x00, 4, "ab", "rest" ], "A long-form length" );
    @value = Authen::WebAuthn::_der_read("\xbf\x85\x3e\x00");
    is_deeply( \@value, [ 0xa0, 702, "", "" ], "A high tag number" );

    my $invalid = sub {
        my ( $der, $message, $name ) = @_;
        eval { Authen::WebAuthn::_der_read($der) };
        like( $@, $message, $name );
    };
    $invalid->( "\x04",          qr/truncated/,     "One byte" );
    $invalid->( "\x04\x05abc",   qr/truncated/,     "Contents cut short" );
    $invalid->( "\xbf\x85",      qr/truncated/,     "A tag number cut short" );
    $invalid->( "\xbf\x85\x3e",  qr/truncated/,     "No length" );
    $invalid->( "\x04\x80",      qr/not supported/, "Indefinite length" );
    $invalid->( "\x04\x85abcde", qr/not supported/, "A length of 5 bytes" );
    $invalid->(
        "\xbf\xff\xff\xff\xff\x7f\x00",
        qr/tag is too long/,
        "A huge tag number"
    );

    is( Authen::WebAuthn::_der_unsigned("\x01\x00"), 256, "An integer" );
    for my $case (
        [ "",         "empty" ],
        [ "\x80",     "negative" ],
        [ "\x01" x 6, "too large" ]
      )
    {
        eval { Authen::WebAuthn::_der_unsigned( $case->[0] ) };
        like( $@, qr/integer/, "An integer that is $case->[1]" );
    }
};

done_testing();
