use Test::More;
use MIME::Base64 qw(encode_base64url);
use CBOR::XS;
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# A value tagged as a Perl object (CBOR tag 26) asks the decoder to call
# THAW on the class it names. Nothing sent by a client may get that far.
my $thawed = 0;
{

    package Local::Thawed;
    sub THAW { $thawed++; return bless {}, shift }
}
my $tagged = CBOR::XS::tag( 26, [ "Local::Thawed", "x" ] );

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

is( ref( CBOR::XS::decode_cbor( CBOR::XS::encode_cbor($tagged) ) ),
    "Local::Thawed", "A plain decoder does call THAW" );
$thawed = 0;

subtest "Attestation statement" => sub {
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );

    my $object =
      CBOR::XS::decode_cbor( $credential->{response}->{attestationObject} );
    $object->{attStmt} = { x => $tagged };
    my $attestation_object = CBOR::XS->new->text_keys(1)->encode($object);

    eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 => encode_base64url($attestation_object),
        );
    };
    is( $thawed, 0, "THAW was not called" );
};

subtest "Extensions in a registration" => sub {
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } },
        {
            response => {
                attestationObject => {
                    authData => {
                        flags      => { edIncluded => 1 },
                        extensions => $tagged,
                    }
                }
            }
        }
    );

    eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
        );
    };
    is( $thawed, 0, "THAW was not called" );
};

# Authenticator data is decoded before the signature is checked
subtest "Extensions in an assertion" => sub {
    my $registration = $rp->validate_registration(
        challenge_b64 => "abc",
        do {
            my $credential = $authenticator->get_credential_response(
                { request => { challenge => "abc" } } );
            (
                client_data_json_b64 =>
                  encode_base64url( $credential->{response}->{clientDataJSON} ),
                attestation_object_b64 => encode_base64url(
                    $credential->{response}->{attestationObject}
                ),
            );
        },
    );

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } },
        {
            response => {
                authenticatorData => {
                    flags      => { edIncluded => 1 },
                    extensions => $tagged,
                }
            }
        }
    );

    eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 => $registration->{credential_pubkey},
            stored_sign_count     => 0,
            client_data_json_b64  =>
              encode_base64url( $assertion->{response}->{clientDataJSON} ),
            authenticator_data_b64 =>
              encode_base64url( $assertion->{response}->{authenticatorData} ),
            signature_b64 =>
              encode_base64url( $assertion->{response}->{signature} ),
        );
    };
    is( $thawed, 0, "THAW was not called" );
};

done_testing();
