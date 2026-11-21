use Test::More;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA  qw(sha256);
use JSON;
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

sub client_data { { response => { clientDataJSON => {@_} } } }

subtest "Cross-origin requests" => sub {
    my $iframe = client_data(
        crossOrigin => JSON::true,
        topOrigin   => "https://top.example.com"
    );

    ok( authenticate( client_data( crossOrigin => JSON::false ) ),
        "A same-origin request is accepted" );

    ok( !authenticate($iframe), "A cross-origin request is refused" );
    like(
        $@,
        qr/Cross-origin requests are not allowed/,
        "With the expected message"
    );
    ok( !register( undef, $iframe ), "Also when registering" );

    $rp->allow_cross_origin(1);
    ok( authenticate($iframe),      "Accepted when allowed" );
    ok( register( undef, $iframe ), "Also when registering" );

    $rp->allow_cross_origin( ["https://top.example.com"] );
    ok( authenticate($iframe), "Accepted from an allowed top origin" );

    $rp->allow_cross_origin( ["https://other.example.com"] );
    ok( !authenticate($iframe), "Refused from another top origin" );
    like(
        $@,
        qr/Top origin https:\/\/top.example.com is not allowed/,
        "With the expected message"
    );
    ok( !authenticate( client_data( crossOrigin => JSON::true ) ),
        "Refused without a top origin" );

    $rp->allow_cross_origin(0);
};

subtest "AppID extension" => sub {
    my $appid = "https://auth.example.com/u2f-facets.json";
    my $u2f =
      { response => { authenticatorData => { rpIdHash => sha256($appid) } } };
    my $origin = {
        response => {
            authenticatorData =>
              { rpIdHash => sha256("http://auth.example.com") }
        }
    };

    ok(
        authenticate(
            $u2f,
            extension_results => { appid => 1 },
            appid             => $appid
        ),
        "Authenticator data hashed with the given AppID"
    );
    ok(
        !authenticate( $u2f, extension_results => { appid => 1 } ),
        "Without the appid option, the origin is expected"
    );
    ok( authenticate( $origin, extension_results => { appid => 1 } ),
        "Which is the earlier behaviour" );
    ok( !authenticate( $u2f, appid => $appid ),
        "Without the extension result, the RP ID is expected" );
    ok(
        authenticate( undef, extension_results => { appid => 0 } ),
        "And a false extension result changes nothing"
    );
};

done_testing();
