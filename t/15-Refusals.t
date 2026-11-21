use Test::More;
use MIME::Base64 qw(encode_base64url);
use CBOR::XS;
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

    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
            %{ $options || {} },
        );
    };
}

sub authenticate {
    my ( $override, %options ) = @_;

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } }, $override );

    return scalar eval {
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

sub client_data { { response => { clientDataJSON => {@_} } } }

sub registration_data {
    { response => { attestationObject => { authData => {@_} } } }
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Registration" => sub {
    refused(
        register( undef, client_data( type => "webauthn.get" ) ),
        qr/Type is not webauthn.create/,
        "Wrong client data type"
    );
    refused(
        register( { challenge_b64 => "" } ),
        qr/Empty registration challenge/,
        "No challenge"
    );
    refused(
        register( undef, client_data( origin => "" ) ),
        qr/Empty origin in client data/,
        "No origin"
    );
    refused(
        register( undef, registration_data( flags => { userPresent => 0 } ) ),
        qr/User not present during WebAuthn registration/,
        "User not present"
    );
    refused(
        register(
            undef,
            registration_data(
                flags                  => { atIncluded => 0 },
                attestedCredentialData => undef,
            )
        ),
        qr/Attested credential data not found in authenticator data/,
        "No attested credential data"
    );
    refused(
        register(
            undef,
            registration_data(
                attestedCredentialData => {
                    credentialPublicKey =>
                      Authen::WebAuthn::Test::_canonical_cbor(
                        { 1 => 2, 3 => -999, -1 => 1 }
                      )
                }
            )
        ),
        qr/Unsupported algorithm -999/,
        "A credential key with an unsupported algorithm"
    );
};

subtest "Authentication" => sub {
    refused(
        scalar authenticate( client_data( type => "webauthn.create" ) ),
        qr/Type is not webauthn.get/,
        "Wrong client data type"
    );
    refused(
        scalar authenticate( undef, challenge_b64 => "" ),
        qr/Empty authentication challenge/,
        "No challenge"
    );
    refused(
        scalar authenticate( client_data( origin => "" ) ),
        qr/Empty origin/,
        "No origin"
    );

    my $unknown_alg = encode_base64url(
        Authen::WebAuthn::Test::_canonical_cbor(
            {
                1  =>  2,
                3  => -999,
                -1 =>  1,
                -2 => "\x01" x 32,
                -3 => "\x02" x 32
            }
        )
    );
    refused(
        scalar authenticate( undef, credential_pubkey_b64 => $unknown_alg ),
qr/Cannot get signature validator for assertion: Unsupported algorithm -999/,
        "A stored key with an unsupported algorithm"
    );
};

done_testing();
