use Test::More;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
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
            Authen::WebAuthn::parse_okp_cose( { -1 => 7, -2 => "\x01" x 57 } );
        },
        qr/Unsupported curve 7/,
        "An OKP curve other than Ed25519"
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

done_testing();
