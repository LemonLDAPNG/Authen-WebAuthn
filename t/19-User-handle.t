use Test::More;
use MIME::Base64 qw(encode_base64url);
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

            # What the browser would pass on
            (
                length $assertion->{response}->{userHandle}
                ? ( user_handle_b64 =>
                      encode_base64url( $assertion->{response}->{userHandle} ) )
                : ()
            ),
            %options,
        );
    };
}

my $credential_id = encode_base64url( $authenticator->credential_id );
my $handle        = encode_base64url("user-42");

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Allowed credentials" => sub {
    ok( authenticate(), "Without allowed_credential_ids, nothing is checked" );

    ok(
        authenticate(
            undef,
            credential_id_b64      => $credential_id,
            allowed_credential_ids => [ "b3RoZXI", $credential_id ],
        ),
        "A credential that was allowed"
    );
    refused(
        authenticate(
            undef,
            credential_id_b64      => $credential_id,
            allowed_credential_ids => ["b3RoZXI"],
        ),
        qr/Credential \Q$credential_id\E is not one of the allowed credentials/,
        "A credential that was not allowed"
    );
    refused(
        authenticate( undef, allowed_credential_ids => [$credential_id] ),
        qr/Missing credential_id_b64/,
        "Allowed credentials without the credential ID"
    );
    refused(
        authenticate( undef, allowed_credential_ids => $credential_id ),
        qr/allowed_credential_ids must be an ARRAY reference/,
        "Allowed credentials that are not a list"
    );
};

subtest "User identified before the ceremony" => sub {
    $authenticator->user_handle("");
    ok( authenticate( undef, expected_user_handle_b64 => $handle ),
        "No user handle returned" );

    $authenticator->user_handle("user-42");
    my $result = authenticate( undef, expected_user_handle_b64 => $handle );
    ok( $result, "The owner's user handle returned" );
    is( $result && $result->{user_handle_b64}, $handle, "... and reported" );

    $authenticator->user_handle("user-43");
    refused(
        authenticate( undef, expected_user_handle_b64 => $handle ),
        qr/User handle \(dXNlci00Mw\) does not match the credential's owner/,
        "Another user's handle"
    );
    $authenticator->user_handle("user-42");
    refused(
        authenticate(),
        qr/expected_user_handle_b64 is required to check the user handle/,
        "A user handle with nothing to check it against"
    );
};

subtest "User identified by the ceremony" => sub {
    ok(
        authenticate(
            undef,
            require_user_handle      => 1,
            user_handle_b64          => $handle,
            expected_user_handle_b64 => $handle,
        ),
        "The user handle identifies the owner"
    );
    for my $missing ( undef, "" ) {
        refused(
            authenticate(
                undef,
                require_user_handle      => 1,
                user_handle_b64          => $missing,
                expected_user_handle_b64 => $handle,
            ),
            qr/Missing user handle/,
            "No user handle (" . ( defined $missing ? "empty" : "undef" ) . ")"
        );
    }
};

# decode_base64url skips characters outside the alphabet: "AA.AA" would
# otherwise be the credential "AAAA"
subtest "Identifiers must be base64url" => sub {
    my $dotted =
      substr( $credential_id, 0, 2 ) . "." . substr( $credential_id, 2 );
    refused(
        authenticate(
            undef,
            credential_id_b64      => $dotted,
            allowed_credential_ids => [$credential_id],
        ),
        qr/credential_id_b64 is not valid base64url/,
        "A credential ID with a character outside the alphabet"
    );
    refused(
        authenticate(
            undef,
            credential_id_b64      => $credential_id,
            allowed_credential_ids => [$dotted],
        ),
        qr/allowed_credential_ids is not valid base64url/,
        "An allowed credential ID with one"
    );
    refused(
        authenticate(
            undef,
            user_handle_b64          => "!",
            expected_user_handle_b64 => "",
        ),
        qr/user_handle_b64 is not valid base64url/,
        "A user handle of \"!\""
    );
    refused(
        authenticate(
            undef,
            user_handle_b64          => $handle,
            expected_user_handle_b64 => "$handle=",
        ),
        qr/expected_user_handle_b64 is not valid base64url/,
        "An expected user handle with padding"
    );
    refused(
        authenticate(
            undef,
            user_handle_b64          => "AAAAA",
            expected_user_handle_b64 => "AAAA",
        ),
        qr/user_handle_b64 is not valid base64url/,
        "A length no base64url encoding has"
    );
};

done_testing();
