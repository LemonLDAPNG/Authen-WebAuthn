use Test::More;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::Ed448;
use Crypt::PK::RSA;
use JSON         qw(decode_json);
use MIME::Base64 qw(encode_base64url decode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

my $message = "authenticator data and client data hash";

sub dies_like {
    my ( $code, $message, $name ) = @_;
    eval { $code->() };
    like( $@, $message, $name );
}

subtest "convert_raw_ecc_to_cose" => sub {
    my $key = Crypt::PK::ECC->new;
    $key->generate_key("secp256r1");

    my $cose = decode_base64url(
        Authen::WebAuthn::convert_raw_ecc_to_cose(
            encode_base64url( $key->export_key_raw("public") )
        )
    );
    my $verifier = Authen::WebAuthn::getPubKeyVerifier($cose);
    ok(
        $verifier->( $key->sign_message( $message, "SHA256" ), $message ),
        "A U2F key converted to COSE verifies its signatures"
    );

    # The canonical layout, written out, for a key whose x coordinate
    # starts with a zero byte, which must not be dropped
    my $raw;
    do {
        $key->generate_key("secp256r1");
        $raw = $key->export_key_raw("public");
    } until substr( $raw, 1, 1 ) eq "\0";
    my ( $x, $y ) = ( substr( $raw, 1, 32 ), substr( $raw, 33, 32 ) );
    is(
        unpack(
            "H*",
            decode_base64url(
                Authen::WebAuthn::convert_raw_ecc_to_cose(
                    encode_base64url($raw)
                )
            )
        ),
        unpack(
            "H*",
            pack( "H*", "a5010203262001215820" )
              . $x
              . pack( "H*", "225820" )
              . $y
        ),
        "kty, alg, crv, x and y, in canonical order and padded"
    );
};

# Attestation certificates hold PEM keys
subtest "getPEMPubKeyVerifier" => sub {
    my $rsa = Crypt::PK::RSA->new;
    $rsa->generate_key( 256, 65537 );
    my $verifier =
      Authen::WebAuthn::getPEMPubKeyVerifier( $rsa->export_key_pem("public"),
        -257 );
    ok(
        $verifier->(
            $rsa->sign_message( $message, "SHA256", "v1.5" ), $message
        ),
        "RSA"
    );

    my $ed25519 = Crypt::PK::Ed25519->new;
    $ed25519->generate_key;
    $verifier = Authen::WebAuthn::getPEMPubKeyVerifier(
        $ed25519->export_key_pem("public"), -8 );
    ok( $verifier->( $ed25519->sign_message($message), $message ), "Ed25519" );
};

subtest "Refusals of the key helpers" => sub {
    my $off_curve = Authen::WebAuthn::Test::_canonical_cbor(
        { 1 => 2, 3 => -7, -1 => 1, -2 => "\x01" x 32, -3 => "\x02" x 32 } );
    dies_like(
        sub {
            Authen::WebAuthn::attest_packed(
                { alg => -7, sig => "x" },
                {
                    attestedCredentialData => {
                        credentialPublicKey    => $off_curve,
                        credentialPublicKeyAlg => "ES256",
                    }
                },
                "", ""
            );
        },
        qr/Cannot get signature validator for attestation/,
        "Self attestation with a key that cannot verify"
    );
    dies_like(
        sub {
            Authen::WebAuthn::_check_credential_public_key(
                Authen::WebAuthn::Test::_canonical_cbor(
                    { 1 => 2, 3 => -999 }
                )
            );
        },
        qr/Unsupported algorithm -999/,
        "A credential key of an algorithm this module does not support"
    );
    dies_like(
        sub {
            Authen::WebAuthn::parse_ecc_cose(
                { -1 => 9, -2 => "\x01" x 32, -3 => "\x02" x 32 } );
        },
        qr/Unsupported curve 9/,
        "An unknown EC2 curve"
    );
    dies_like(
        sub {
            Authen::WebAuthn::parse_okp_cose( { -1 => 4, -2 => "\x01" x 32 } );
        },
        qr/Unsupported curve 4/,
        "An OKP curve that is not for signatures (X25519)"
    );
    dies_like(
        sub { Authen::WebAuthn::get_verifier_for_alg( -7, {}, "parse_der" ) },
        qr/No conversion method named parse_der for key type ECC/,
        "An unknown key format"
    );
    dies_like(
        sub { Authen::WebAuthn::formatAaguid("short") },
        qr/Invalid AAGUID length/,
        "An AAGUID that is not 16 bytes"
    );
    dies_like(
        sub { Authen::WebAuthn::parse_okp_pem("not a key") },
        qr/Cannot read OKP key/,
        "A PEM that is no OKP key"
    );
};

subtest "Ed448" => sub {
    my $ed448 = Crypt::PK::Ed448->new;
    $ed448->generate_key;
    my $verifier =
      Authen::WebAuthn::getPEMPubKeyVerifier( $ed448->export_key_pem("public"),
        -53 );
    ok( $verifier->( $ed448->sign_message($message), $message ),
        "An Ed448 key verifies Ed448 signatures" );

    my $ed25519 = Crypt::PK::Ed25519->new;
    $ed25519->generate_key;
    dies_like(
        sub {
            Authen::WebAuthn::getPEMPubKeyVerifier(
                $ed25519->export_key_pem("public"), -53 );
        },
        qr/A Crypt::PK::Ed25519 key cannot be used with algorithm -53/,
        "An Ed25519 key is refused for Ed448"
    );
    dies_like(
        sub {
            Authen::WebAuthn::getPEMPubKeyVerifier(
                $ed448->export_key_pem("public"), -19 );
        },
        qr/A Crypt::PK::Ed448 key cannot be used with algorithm -19/,
        "... and the reverse"
    );
};

subtest "Simulator" => sub {
    my $key = Crypt::PK::ECC->new;
    $key->generate_key("secp256r1");
    my %params = (
        origin        => "http://auth.example.com",
        credential_id => "credential",
        aaguid        => "00000000-0000-0000-0000-000000000000",
        key           => $key->export_key_pem("private"),
    );

    dies_like(
        sub {
            Authen::WebAuthn::Test->new( %params, aaguid => "abc" )
              ->get_credential_response( { request => { challenge => "x" } } );
        },
        qr/Invalid AAGUID length/,
        "An AAGUID that is not 16 bytes"
    );
    dies_like(
        sub {
            Authen::WebAuthn::Test->new( %params, key => "not a key" )
              ->encode_cosekey;
        },
        qr/Unsupported key/,
        "A key it cannot read"
    );

    my $authenticator = Authen::WebAuthn::Test->new(%params);

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "x" } } );
    my %raw = (
        rawId => $assertion->{rawId},
        map { $_ => $assertion->{response}->{$_} }
          qw(clientDataJSON authenticatorData signature)
    );
    my $json = decode_json( $authenticator->encode_credential($assertion) );
    is( decode_base64url( $json->{rawId} ),
        $raw{rawId}, "encode_credential encodes rawId" );
    is( decode_base64url( $json->{response}->{$_} ),
        $raw{$_}, "encode_credential encodes $_" )
      for qw(clientDataJSON authenticatorData signature);

    my $registration = $authenticator->get_credential_response(
        { request => { challenge => "x" } } );
    my $attestation_object = $registration->{response}->{attestationObject};
    $json = decode_json( $authenticator->encode_credential($registration) );
    is( decode_base64url( $json->{response}->{attestationObject} ),
        $attestation_object, "encode_credential encodes attestationObject" );
};

subtest "Refusals tested directly" => sub {
    dies_like(
        sub {
            Authen::WebAuthn::getPubKeyVerifier(
                Authen::WebAuthn::Test::_canonical_cbor(
                    { 1 => 2, -1 => 1, -2 => "x" x 32, -3 => "y" x 32 }
                )
            );
        },
        qr/^Missing algorithm in credential public key/,
        "A credential public key without an algorithm"
    );

    dies_like(
        sub {
            Authen::WebAuthn::getAuthData(
                ( "\0" x 32 ) . "\x81" . "\0\0\0\1" );
        },
        qr/^Extension data flag is set but there is no extension data/,
        "Authenticator data flagging extensions it does not have"
    );

    # Only a malformed certificate can carry such an extension
    {

        package FakeExtension;
        sub critical { 0 }
        sub value    { "#0409" . ( "0" x 32 ) }

        package FakeCertificate;

        sub extensions_by_oid {
            return { "1.3.6.1.4.1.45724.1.1.4" => bless {}, "FakeExtension" };
        }
    }
    dies_like(
        sub {
            Authen::WebAuthn::_check_aaguid_extension(
                bless( {}, "FakeCertificate" ),
                { attestedCredentialData => { aaguid => "0" x 32 } } );
        },
        qr/^Invalid id-fido-gen-ce-aaguid extension format/,
        "An AAGUID extension that is not a 16-byte OCTET STRING"
    );
};

subtest "Early Yubico certificates with unused signature bits" => sub {
    my ($security_key) = grep { $_->{name} eq "RealExamples/SecurityKey" } @{
        decode_json(
            do { local ( @ARGV, $/ ) = "t/real-devices/fixtures.json"; <> }
        )
    };
    my $object = Authen::WebAuthn::_decode_cbor(
        decode_base64url( $security_key->{attestation_object_b64} ) );
    my $der = $object->{attStmt}->{x5c}->[0];

    my $fixed = Authen::WebAuthn::_fix_signature_unused_bits($der);
    is( length $fixed, length $der, "The length is kept" );
    is( ord substr( $der,   -257, 1 ), 2, "The certificate says 2 bits" );
    is( ord substr( $fixed, -257, 1 ), 0, "The fixed one says none" );
    is(
        substr( $fixed, 0, -257 ) . substr( $fixed, -256 ),
        substr( $der,   0, -257 ) . substr( $der,   -256 ),
        "Nothing else changes"
    );

    my $other = Crypt::OpenSSL::X509->new_from_file("t/pki/packed-p256.pem")
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
    is( Authen::WebAuthn::_fix_signature_unused_bits($other),
        $other, "Other certificates are left alone" );
    is( Authen::WebAuthn::_fix_signature_unused_bits("x"),
        "x", "So is anything that is not a certificate" );
};

done_testing();
