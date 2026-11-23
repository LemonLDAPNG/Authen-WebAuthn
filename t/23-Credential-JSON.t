use Test::More;
use Crypt::PK::ECC;
use JSON;
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# The credential as the browser sends it, PublicKeyCredential.toJSON(), in
# place of its parts

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $authenticator = Authen::WebAuthn::Test->new(
    origin        => "http://auth.example.com",
    rp_id         => "auth.example.com",
    credential_id => "\xffcredential",
    aaguid        => "00000000-0000-0000-0000-000000000000",
    user_handle   => "user-42",
    key           => do {
        my $key = Crypt::PK::ECC->new;
        $key->generate_key("secp256r1");
        $key->export_key_pem("private");
    },
);
my $id = encode_base64url( $authenticator->credential_id );

# A registration as a browser serializes it
sub registration_json {
    my (%changed) = @_;
    my $response = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } )->{response};
    my $credential = {
        id       => $id,
        rawId    => $id,
        type     => "public-key",
        response => {
            clientDataJSON => encode_base64url( $response->{clientDataJSON} ),
            attestationObject =>
              encode_base64url( $response->{attestationObject} ),
            transports => [ "hybrid", "internal" ],
        },
        clientExtensionResults  => { credProps => { rk => JSON::true } },
        authenticatorAttachment => "platform",
        %changed,
    };
    return encode_json($credential);
}

sub register {
    my (%params) = @_;
    return
      scalar
      eval { $rp->validate_registration( challenge_b64 => "abc", %params ); };
}

sub assertion_json {
    return $authenticator->encode_credential(
        $authenticator->get_assertion_response(
            { request => { challenge => "def" } }
        )
    );
}

sub authenticate {
    my (%params) = @_;
    return scalar eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 =>
              encode_base64url( $authenticator->encode_cosekey ),
            stored_sign_count        => 0,
            expected_user_handle_b64 => encode_base64url("user-42"),
            %params,
        );
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Registration" => sub {
    my $result = register( credential_json => registration_json() );
    ok( $result, "A registration verifies" ) or diag($@);
    is( $result->{credential_id}, $id, "... with the credential ID" );
    is_deeply(
        $result->{transports},
        [ "hybrid", "internal" ],
        "... and the transports"
    );
    is( $result->{discoverable}, 1, "The extension results are read" );

    ok( register( credential_json => decode_json( registration_json() ) ),
        "A decoded credential is accepted" );

    my $other = encode_base64url("other");
    refused(
        register(
            credential_json =>
              registration_json( id => $other, rawId => $other )
        ),
        qr/Credential \Q$other\E is not the one in the authenticator data/,
        "A rawId other than the attested credential"
    );
    refused(
        register( credential_json => registration_json( id => "x" ) ),
        qr/credential_json id and rawId differ/,
        "An id other than the rawId"
    );
    refused(
        register( credential_json => registration_json( type => "password" ) ),
        qr/credential_json type is not public-key/,
        "Another type"
    );
    refused(
        register(
            credential_json =>
              registration_json( response => { attestationObject => [] } )
        ),
        qr/credential_json response.attestationObject is not a string/,
        "A member that is not a string"
    );
    refused(
        register( credential_json => "{" ),
        qr/credential_json is not valid JSON/,
        "JSON that does not parse"
    );
    refused(
        register(
            credential_json      => registration_json(),
            client_data_json_b64 => "e30",
        ),
qr/client_data_json_b64 is given both as an argument and in credential_json/,
        "An argument given both ways"
    );
    refused(
        register(
            credential_json   => registration_json(),
            extension_results => {},
        ),
        qr/extension_results is given both/,
        "... the extension results too"
    );
};

subtest "Authentication" => sub {
    my $result = authenticate(
        credential_json        => assertion_json(),
        allowed_credential_ids => [$id],
    );
    ok( $result, "An assertion verifies" ) or diag($@);
    is(
        $result && $result->{user_handle_b64},
        encode_base64url("user-42"),
        "... with the user handle"
    );
    refused(
        authenticate(
            credential_json        => assertion_json(),
            allowed_credential_ids => [ encode_base64url("other") ],
        ),
        qr/is not one of the allowed credentials/,
        "The rawId is the credential checked against the allowed ones"
    );
};

subtest "Signature counter" => sub {
    $authenticator->sign_count(3);
    refused(
        authenticate(
            credential_json   => assertion_json(),
            stored_sign_count => 5
        ),
qr/Device signature count 3 is not higher than stored signature count 5/,
        "A lower count is refused"
    );
    my $result = authenticate(
        credential_json             => assertion_json(),
        stored_sign_count           => 5,
        allow_sign_count_regression => 1,
    );
    ok( $result, "... unless allowed" ) or diag($@);
    is( $result && $result->{sign_count_regressed}, 1, "... and reported" );
    ok(
        !exists authenticate(
            credential_json             => assertion_json(),
            stored_sign_count           => 2,
            allow_sign_count_regression => 1,
        )->{sign_count_regressed},
        "A higher count is not reported"
    );
};

done_testing();
