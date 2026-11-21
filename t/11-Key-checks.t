use Test::More;
use MIME::Base64 qw(encode_base64url);
use CBOR::XS;
use Crypt::PK::RSA;
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $ecdsa_key = <<ENDKEY;
-----BEGIN EC PRIVATE KEY-----
MIIBUQIBAQQgWEGujn2kkOVckTIKhIJDSqH99bxydPGloXvbeaq9swiggeMwgeAC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MEQEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwRBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLesz
oPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////
AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAaFEA0IABM/oQXEUzjPwEhM4
gWmIbCuOXc4Ja8jPDKxbQaZckal7/9a693/nkf7flk1S9AV2tjrtJPF6kg8TCGbF
KoeD9Wc=
-----END EC PRIVATE KEY-----
ENDKEY

my $authenticator = Authen::WebAuthn::Test->new(
    origin        => "http://auth.example.com",
    rp_id         => "auth.example.com",
    credential_id => "lZYltP9MtoRNuXK8f8tWf",
    aaguid        => "00000000-0000-0000-0000-000000000000",
    key           => $ecdsa_key,
);

sub register {
    my ( $options, $override ) = @_;

    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } }, $override );

    return eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 => encode_base64url(
                $credential->{response}->{attestationObject}
            ),
            %{ $options || {} },
        );
    };
}

sub authenticate {
    my ( $override, %options ) = @_;

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } }, $override );

    return eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 =>
              encode_base64url( $authenticator->encode_cosekey ),
            stored_sign_count    => 0,
            client_data_json_b64 =>
              encode_base64url( $assertion->{response}->{clientDataJSON} ),
            authenticator_data_b64 =>
              encode_base64url( $assertion->{response}->{authenticatorData} ),
            signature_b64 =>
              encode_base64url( $assertion->{response}->{signature} ),
            %options,
        );
    };
}

sub with_key {
    my ($cose) = @_;
    return {
        response => {
            attestationObject => {
                authData => {
                    attestedCredentialData =>
                      { credentialPublicKey => $cose }
                }
            }
        }
    };
}

sub rsa_key {
    my ($bytes) = @_;
    my $key = Crypt::PK::RSA->new;
    $key->generate_key( $bytes, 65537 );
    my $hash = $key->key2hash;
    return CBOR::XS::encode_cbor( {
            1  => 3,
            3  => -257,
            -1 => pack( "H*", $hash->{N} ),
            -2 => pack( "H*", $hash->{e} ),
        }
    );
}

ok( register(), "A valid ES256 key is accepted" );

ok(
    !register(
        undef,
        with_key(
            CBOR::XS::encode_cbor(
                { 1 => 2, 3 => -7, -1 => 1, -2 => "\x01" x 32, -3 => "\x02" x 32 }
            )
        )
    ),
    "A point that is not on the curve is refused"
);
like( $@, qr/Invalid credential public key/, "With the expected message" );

ok(
    !register(
        undef,
        with_key(
            CBOR::XS::encode_cbor(
                { 1 => 1, 3 => -7, -1 => 1, -2 => "\x01" x 32, -3 => "\x02" x 32 }
            )
        )
    ),
    "An OKP key claiming ES256 is refused"
);
like( $@, qr/Key type 1 cannot be used with algorithm -7/,
    "With the expected message" );

ok( register( undef, with_key( rsa_key(256) ) ),
    "A 2048 bit RSA key is accepted" );

ok( !register( undef, with_key( rsa_key(128) ) ),
    "A 1024 bit RSA key is refused" );
like( $@, qr/RSA key of 1024 bits is too short \(min: 2048\)/,
    "With the expected message" );

done_testing();
