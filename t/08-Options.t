use Test::More;
use JSON         qw(encode_json decode_json);
use MIME::Base64 qw(encode_base64url decode_base64url);
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

subtest "Registration options" => sub {
    my $options = $rp->generate_registration_options(
        rp_name   => "Example",
        user_id   => "user-42",
        user_name => 'alice@example.com',
    );

    is( $options->{rp}->{id},   "auth.example.com", "RP ID" );
    is( $options->{rp}->{name}, "Example",          "RP name" );
    is( decode_base64url( $options->{user}->{id} ),
        "user-42", "User handle is base64url-encoded" );
    is( $options->{user}->{displayName},
        'alice@example.com', "Display name defaults to the user name" );
    is( length( decode_base64url( $options->{challenge} ) ),
        32, "A 32 byte challenge is generated" );
    isnt(
        $options->{challenge},
        $rp->generate_registration_options(
            rp_name   => "Example",
            user_id   => "user-42",
            user_name => "alice"
        )->{challenge},
        "And is different every time"
    );
    is_deeply(
        $options->{pubKeyCredParams},
        [
            { type => "public-key", alg => -8 },
            { type => "public-key", alg => -7 },
            { type => "public-key", alg => -257 }
        ],
        "EdDSA, ES256 and RS256 by default"
    );
    is( $options->{attestation}, "none", "No attestation by default" );
    is( $options->{authenticatorSelection}->{userVerification},
        "preferred", "User verification is preferred by default" );
    is_deeply( $options->{excludeCredentials}, [], "Nothing to exclude" );
    ok( !exists $options->{timeout}, "No timeout by default" );
    like( encode_json($options), qr/"alg":-7\b/,
        "Algorithms are serialized as numbers" );

    $options = $rp->generate_registration_options(
        rp_name             => "Example",
        user_id             => "user-42",
        user_name           => "alice",
        user_display_name   => "Alice",
        challenge_b64       => "abc",
        allowed_algs        => [ -8, -7 ],
        requested_uv        => "required",
        resident_key        => "preferred",
        timeout             => "60000",
        exclude_credentials =>
          [ "aWQx", { id => "aWQy", transports => ["usb"] } ],
    );
    is( $options->{challenge},           "abc",   "Challenge can be given" );
    is( $options->{user}->{displayName}, "Alice", "Display name" );
    is_deeply(
        [ map { $_->{alg} } @{ $options->{pubKeyCredParams} } ],
        [ -8, -7 ],
        "Algorithms in the order given"
    );
    is_deeply(
        $options->{authenticatorSelection},
        { userVerification => "required", residentKey => "preferred" },
        "Authenticator selection"
    );
    is_deeply(
        $options->{excludeCredentials},
        [
            { type => "public-key", id => "aWQx" },
            { type => "public-key", id => "aWQy", transports => ["usb"] }
        ],
        "Excluded credentials, as IDs or as hashrefs"
    );
    like( encode_json($options), qr/"timeout":60000\b/,
        "Timeout is serialized as a number" );

    eval { $rp->generate_registration_options( rp_name => "Example" ) };
    like( $@, qr/Missing user_id/, "The user handle is required" );

    eval {
        $rp->generate_registration_options(
            rp_name      => "Example",
            user_id      => "user-42",
            user_name    => "alice",
            allowed_algs => [-9999],
        );
    };
    like(
        $@,
        qr/Unsupported algorithm -9999/,
        "An algorithm this module cannot verify is refused"
    );
};

subtest "Assertion options" => sub {
    my $options = $rp->generate_assertion_options;

    is( $options->{rpId}, "auth.example.com", "RP ID" );
    is( length( decode_base64url( $options->{challenge} ) ),
        32, "A 32 byte challenge is generated" );
    is( $options->{userVerification}, "preferred", "User verification" );
    is_deeply( $options->{allowCredentials},
        [], "Any discoverable credential by default" );

    $options = $rp->generate_assertion_options(
        allow_credentials => ["aWQx"],
        requested_uv      => "discouraged",
    );
    is_deeply(
        $options->{allowCredentials},
        [ { type => "public-key", id => "aWQx" } ],
        "Allowed credentials"
    );
    is( $options->{userVerification}, "discouraged", "User verification" );
};

subtest "Options are checked" => sub {
    my %required = (
        rp_name   => "Example",
        user_id   => "user-42",
        user_name => "alice",
    );
    my $refused = sub {
        my ( $method, $params, $message, $name ) = @_;
        eval { $rp->$method(%$params) };
        like( $@, $message, $name );
    };
    my $registration = "generate_registration_options";
    my $assertion    = "generate_assertion_options";

    $refused->(
        $registration,
        { %required, user_id => "x" x 65 },
        qr/user_id is longer than 64 bytes/,
        "A user handle over 64 bytes"
    );
    ok( $rp->$registration( %required, user_id => "x" x 64 ),
        "A user handle of 64 bytes" );

    $refused->(
        $registration,
        { %required, requested_uv => "always" },
        qr/Invalid requested_uv: always/,
        "An unknown requested_uv"
    );
    $refused->(
        $assertion,
        { requested_uv => "always" },
        qr/Invalid requested_uv: always/,
        "... also when authenticating"
    );
    $refused->(
        $registration,
        { %required, attestation => "full" },
        qr/Invalid attestation: full/,
        "An unknown attestation"
    );
    $refused->(
        $registration,
        { %required, resident_key => "yes" },
        qr/Invalid resident_key: yes/,
        "An unknown resident_key"
    );
    $refused->(
        $registration,
        { %required, authenticator_attachment => "usb" },
        qr/Invalid authenticator_attachment: usb/,
        "An unknown authenticator_attachment"
    );
    $refused->(
        $assertion,
        { hints => ["phone"] },
        qr/Invalid hints: phone/,
        "An unknown hint"
    );
    $refused->(
        $assertion,
        { hints => "hybrid" },
        qr/hints must be an ARRAY reference/,
        "Hints that are not a list"
    );
    $refused->(
        $assertion,
        { timeout => "soon" },
        qr/Invalid timeout: soon/,
        "A timeout that is not a number"
    );
    $refused->(
        $registration,
        { %required, extensions => ["credProps"] },
        qr/extensions must be a HASH reference/,
        "Extensions that are not a map"
    );
};

subtest "Optional options" => sub {
    my $options = $rp->generate_registration_options(
        rp_name      => "Example",
        user_id      => "user-42",
        user_name    => "alice",
        resident_key => "required",
        hints        => [ "client-device", "hybrid" ],
        extensions   => { credProps => JSON::true },
    );
    is_deeply(
        $options->{authenticatorSelection},
        {
            userVerification   => "preferred",
            residentKey        => "required",
            requireResidentKey => JSON::true,
        },
        "requireResidentKey is set when a resident key is required"
    );
    is_deeply( $options->{hints}, [ "client-device", "hybrid" ], "Hints" );
    is_deeply( $options->{extensions},
        { credProps => JSON::true }, "Extensions" );
    like( encode_json($options), qr/"requireResidentKey":true/,
        "requireResidentKey is serialized as a boolean" );

    $options = $rp->generate_registration_options(
        rp_name      => "Example",
        user_id      => "user-42",
        user_name    => "alice",
        resident_key => "preferred",
    );
    ok( !exists $options->{authenticatorSelection}->{requireResidentKey},
        "... and only then" );
    ok(
        !exists $options->{hints} && !exists $options->{extensions},
        "Hints and extensions are omitted unless given"
    );

    $options = $rp->generate_assertion_options(
        hints      => ["security-key"],
        extensions => { appid => "https://auth.example.com" },
    );
    is_deeply( $options->{hints}, ["security-key"], "Assertion hints" );
    is_deeply(
        $options->{extensions},
        { appid => "https://auth.example.com" },
        "Assertion extensions"
    );
};

subtest "Generated options validate" => sub {
    my $options = decode_json(
        encode_json(
            $rp->generate_registration_options(
                rp_name   => "Example",
                user_id   => "user-42",
                user_name => "alice",
            )
        )
    );
    my $credential =
      $authenticator->get_credential_response( { request => $options } );
    my $registration = $rp->validate_registration(
        challenge_b64 => $options->{challenge},
        allowed_algs => [ map { $_->{alg} } @{ $options->{pubKeyCredParams} } ],
        client_data_json_b64 =>
          encode_base64url( $credential->{response}->{clientDataJSON} ),
        attestation_object_b64 =>
          encode_base64url( $credential->{response}->{attestationObject} ),
    );
    ok( $registration->{credential_id}, "Registration" );

    $options = decode_json(
        encode_json(
            $rp->generate_assertion_options(
                allow_credentials => [ $registration->{credential_id} ],
            )
        )
    );
    my $assertion =
      $authenticator->get_assertion_response( { request => $options } );
    my $result = $rp->validate_assertion(
        challenge_b64         => $options->{challenge},
        credential_pubkey_b64 => $registration->{credential_pubkey},
        stored_sign_count     => 0,
        client_data_json_b64  =>
          encode_base64url( $assertion->{response}->{clientDataJSON} ),
        authenticator_data_b64 =>
          encode_base64url( $assertion->{response}->{authenticatorData} ),
        signature_b64 =>
          encode_base64url( $assertion->{response}->{signature} ),
    );
    is( $result->{success}, 1, "Authentication" );
};

done_testing();
