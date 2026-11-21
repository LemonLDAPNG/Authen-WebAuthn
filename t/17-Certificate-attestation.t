use Test::More;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# Attestation signed with certificates from the test PKI in t/pki (see
# t/pki/generate), through the simulator

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $credential_key = Crypt::PK::ECC->new;
$credential_key->generate_key("secp256r1");

sub authenticator {
    my (%args) = @_;
    my $certificate = delete $args{certificate};
    return Authen::WebAuthn::Test->new(
        origin             => "http://auth.example.com",
        rp_id              => "auth.example.com",
        credential_id      => "credential",
        aaguid             => "00000000-0000-0000-0000-000000000000",
        key                => $credential_key->export_key_pem("private"),
        attestation_format => "packed",
        (
            $certificate
            ? (
                attestation_key          => pem("$certificate-key"),
                attestation_certificates => [ pem($certificate) ],
              )
            : ()
        ),
        %args,
    );
}

sub register {
    my ( $authenticator, %options ) = @_;
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
            trust_anchors => [ pem("root") ],
            %options,
        );
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Packed attestation, each key type" => sub {
    for my $certificate (qw(packed-p256 packed-p384 packed-rsa packed-ed25519))
    {
        my $reg = register( authenticator( certificate => $certificate ) );
        ok( $reg, $certificate ) or diag($@);
        is( $reg && $reg->{attestation_result}->{type},
            "Basic", "... as Basic attestation" );
    }
};

subtest "Certificate chains" => sub {
    my $chained = authenticator(
        attestation_key          => pem("packed-chained-key"),
        attestation_certificates =>
          [ pem("packed-chained"), pem("intermediate") ],
    );
    ok( register($chained), "Through an intermediate" ) or diag($@);

    $chained->attestation_certificates( [ pem("packed-chained") ] );
    refused(
        register($chained),
        qr/Could not verify X.509 chain/,
        "Without the intermediate"
    );

    my $direct = authenticator( certificate => "packed-p256" );
    ok( register( $direct, trust_anchors => [ pem("packed-p256") ] ),
        "Trusting the attestation certificate itself" );
    refused(
        register( $direct, trust_anchors => [ pem("intermediate") ] ),
        qr/Could not verify X.509 chain/,
        "Trusting another authority"
    );
};

subtest "AAGUID extension" => sub {
    my $aaguid = "01020304-0506-0708-090a-0b0c0d0e0f10";
    my $reg    = register(
        authenticator( certificate => "packed-aaguid", aaguid => $aaguid ) );
    ok( $reg, "Matching the authenticator data" ) or diag($@);
    is( $reg && $reg->{attestation_result}->{aaguid},
        $aaguid, "... and reported" );

    refused(
        register( authenticator( certificate => "packed-aaguid" ) ),
qr/AAGUID from certificate \(0102030405060708090A0B0C0D0E0F10\) does not match/,
        "Not matching"
    );

    # Refused by the chain check too, but not when the leaf is the anchor
    refused(
        register(
            authenticator(
                certificate => "packed-aaguid-critical",
                aaguid      => $aaguid
            ),
            trust_anchors => [ pem("packed-aaguid-critical") ],
        ),
        qr/id-fido-gen-ce-aaguid extension must not be critical/,
        "Marked critical"
    );
};

subtest "Certificate key and algorithm" => sub {
    my $key = sub {
        Crypt::OpenSSL::X509->new_from_string( pem(shift) )->pubkey;
    };
    for my $case (
        [ "packed-p384", -7 ],
        [ "packed-p256", -35 ],
        [ "packed-p384", -9 ]
      )
    {
        my ( $certificate, $alg ) = @$case;
        ok(
            !eval {
                Authen::WebAuthn::getPEMPubKeyVerifier( $key->($certificate),
                    $alg );
            },
            "$certificate with algorithm $alg is refused"
        );
        like(
            $@,
            qr/Curve secp\d+r1 cannot be used with algorithm $alg/,
            "... with the expected message"
        );
    }
    ok( Authen::WebAuthn::getPEMPubKeyVerifier( $key->("packed-p384"), -35 ),
        "packed-p384 with ES384 is accepted" );
};

subtest "Bytes after a certificate" => sub {
    my $der = Crypt::OpenSSL::X509->new_from_string( pem("packed-p256") )
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
    ok( Authen::WebAuthn::_read_certificate($der), "A certificate" );
    ok( !eval { Authen::WebAuthn::_read_certificate( $der . "JUNK" ) },
        "... with bytes after it is refused" );
    like(
        $@,
        qr/Trailing bytes after certificate/,
        "... with the expected message"
    );

    my $result = eval {
        Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [ pem("root") ],
            $der . "JUNK", [] );
    };
    ok( !( $result && $result->{result} ), "... also by the chain verifier" );
    like(
        $@ || $result->{message},
        qr/Trailing bytes after certificate/,
        "... with the expected message"
    );
    is( Net::SSLeay::ERR_peek_error(), 0, "OpenSSL's error queue is empty" );
};

# validate_registration checks trust anchors before they get here, but the
# chain verifier is also called directly
subtest "Chain verifier input that does not parse" => sub {
    my $der = Crypt::OpenSSL::X509->new_from_string( pem("packed-p256") )
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
    for my $case (
        [ [ pem("root") ], "garbage", "A certificate" ],
        [ [ pem("root"), "garbage" ], $der, "The second of two anchors" ],
      )
    {
        my ( $anchors, $leaf, $name ) = @$case;
        my $result = eval {
            Authen::WebAuthn::SSLeayChainVerifier::verify_chain( $anchors,
                $leaf, [] );
        };
        ok( !( $result && $result->{result} ), "$name is refused" );
        like(
            $@ || $result->{message},
            qr/Could not parse certificate/,
            "... with the expected message"
        );
        is( Net::SSLeay::ERR_peek_error(), 0,
            "... leaving OpenSSL's error queue empty" );
    }
};

subtest "Certificate requirements" => sub {
    my %expected = (
        "bad-v1"    => qr/Invalid certificate version/,
        "bad-no-c"  => qr/Missing subject C/,
        "bad-no-o"  => qr/Missing subject O/,
        "bad-no-cn" => qr/Missing subject CN/,
        "bad-no-ou" => qr/Missing subject OU/,
        "bad-ou"    => qr/Unexpected OU/,
        "bad-ca"    => qr/Basic Constraints CA is true/,
        "bad-no-bc" => qr/Missing Basic Constraints extension/,
    );
    for my $certificate ( sort keys %expected ) {
        refused( register( authenticator( certificate => $certificate ) ),
            $expected{$certificate}, $certificate );
    }
};

subtest "Packed attestation signatures" => sub {
    refused(
        register(
            authenticator(
                attestation_key          => pem("bad-ou-key"),
                attestation_certificates => [ pem("packed-p256") ],
            )
        ),
        qr/Invalid attestation signature/,
        "Signed with another key"
    );
    refused(
        register(
            authenticator(
                attestation_key          => pem("packed-p256-key"),
                attestation_certificates => [ pem("packed-rsa") ],
            )
        ),
        qr/Cannot get signature validator for attestation/,
        "A certificate key of another type than the algorithm"
    );
};

subtest "FIDO U2F attestation" => sub {
    my $reg = register(
        authenticator(
            certificate        => "packed-p256",
            attestation_format => "fido-u2f"
        )
    );
    ok( $reg, "With a P-256 certificate" ) or diag($@);
    is( $reg && $reg->{attestation_result}->{type}, "Basic", "... as Basic" );

    refused(
        register(
            authenticator(
                certificate        => "packed-p384",
                attestation_format => "fido-u2f"
            )
        ),
        qr/Invalid attestation certificate curve name: secp384r1/,
        "With a P-384 certificate"
    );
    refused(
        register(
            authenticator(
                certificate        => "packed-rsa",
                attestation_format => "fido-u2f"
            )
        ),
        qr/Could not extract ECC key from attestation certificate/,
        "With an RSA certificate"
    );

    my $p384 = Crypt::PK::ECC->new;
    $p384->generate_key("secp384r1");
    refused(
        register(
            authenticator(
                certificate        => "packed-p256",
                attestation_format => "fido-u2f",
                key                => $p384->export_key_pem("private"),
            )
        ),
        qr/Could not convert attested credential to U2F key/,
        "For a credential key other than P-256"
    );
};

done_testing();
