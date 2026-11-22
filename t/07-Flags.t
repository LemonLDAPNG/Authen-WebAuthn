use Test::More;
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;
use Digest::SHA ();

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

sub registration_flags {
    { response => { attestationObject => { authData => { flags => {@_} } } } }
}

sub assertion_flags {
    { response => { authenticatorData => { flags => {@_} } } }
}

my $res = register();
is( $res->{user_verified},   0, "Registration: user not verified" );
is( $res->{backup_eligible}, 0, "Registration: not eligible for backup" );
is( $res->{backup_state},    0, "Registration: not backed up" );

$res = register( undef,
    registration_flags( userVerified => 1, backupEligible => 1 ) );
is( $res->{user_verified},   1, "Registration: user verified" );
is( $res->{backup_eligible}, 1, "Registration: eligible for backup" );
is( $res->{backup_state},    0, "Registration: eligible, not backed up" );

$res = register( undef,
    registration_flags( backupEligible => 1, backupState => 1 ) );
is( $res->{backup_state}, 1, "Registration: backed up" );

ok(
    !register( undef, registration_flags( backupState => 1 ) ),
    "Registration: backed up without being eligible is refused"
);
like(
    $@,
    qr/Backup State flag is set but Backup Eligibility is not/,
    "With the expected message"
);

$res = authenticate();
is( $res->{user_verified},   0, "Assertion: user not verified" );
is( $res->{backup_eligible}, 0, "Assertion: not eligible for backup" );
is( $res->{backup_state},    0, "Assertion: not backed up" );

$res = authenticate(
    assertion_flags(
        userVerified   => 1,
        backupEligible => 1,
        backupState    => 1
    )
);
is( $res->{user_verified},   1, "Assertion: user verified" );
is( $res->{backup_eligible}, 1, "Assertion: eligible for backup" );
is( $res->{backup_state},    1, "Assertion: backed up" );

ok(
    !authenticate( assertion_flags( backupState => 1 ) ),
    "Assertion: backed up without being eligible is refused"
);
like(
    $@,
    qr/Backup State flag is set but Backup Eligibility is not/,
    "With the expected message"
);

ok(
    !register(
        undef,
        {
            response => {
                attestationObject => {
                    authData => {
                        attestedCredentialData => { credentialId => "x" x 1024 }
                    }
                }
            }
        }
    ),
    "A 1024 byte credential ID is refused"
);
like(
    $@,
    qr/Credential ID is longer than 1023 bytes/,
    "With the expected message"
);

ok( !authenticate( assertion_flags( userPresent => 0 ) ),
    "Assertion: user not present is refused" );
like(
    $@,
    qr/User not present during WebAuthn authentication/,
    "With the expected message"
);

# A value outside the enumeration would otherwise read as "preferred"
for my $uv (qw(Required require 1)) {
    ok(
        !authenticate( undef, requested_uv => $uv ),
        "Assertion: requested_uv $uv is refused"
    );
    like( $@, qr/Invalid requested_uv: $uv/, "With the expected message" );
    ok(
        !register( { requested_uv => $uv } ),
        "Registration: requested_uv $uv is refused"
    );
    like( $@, qr/Invalid requested_uv: $uv/, "With the expected message" );
}

subtest "Conditional create" => sub {
    my $absent = registration_flags( userPresent => 0 );
    ok( !register( undef, $absent ), "A registration without User Present" );
    like(
        $@,
        qr/User not present during WebAuthn registration/,
        "... is refused"
    );
    ok(
        register( { mediation => "conditional" }, $absent ),
        "... unless the mediation was conditional"
    );
    ok(
        !register(
            { mediation => "conditional", requested_uv => "required" }, $absent
        ),
        "... which still checks user verification"
    );
    ok(
        !register( { mediation => "Conditional" } ),
        "An unknown mediation is refused"
    );
    like(
        $@,
        qr/Invalid mediation: Conditional/,
        "... with the expected message"
    );
};

subtest "Signature counter" => sub {
    $authenticator->sign_count(5);
    ok( authenticate( undef,  stored_sign_count => 4 ), "A higher count" );
    ok( !authenticate( undef, stored_sign_count => 5 ), "An equal count" );
    like(
        $@,
qr/Device signature count 5 is not higher than stored signature count 5/,
        "... is refused"
    );

    # An authenticator without a counter sends 0, but this one had one
    $authenticator->sign_count(0);
    ok( !authenticate( undef, stored_sign_count => 5 ),
        "A count of 0 after a count of 5" );
    like(
        $@,
qr/Device signature count 0 is not higher than stored signature count 5/,
        "... is refused"
    );
    ok(
        authenticate( undef, stored_sign_count => 0 ),
        "Counts of 0 on both sides are accepted"
    );
};

subtest "Trailing bytes" => sub {
    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } } );
    my $auth_data = $assertion->{response}->{authenticatorData};
    ok( Authen::WebAuthn::getAuthData($auth_data), "Assertion data" );
    ok( !eval { Authen::WebAuthn::getAuthData( $auth_data . "\0" ) },
        "... with a byte more is refused" );
    like(
        $@,
        qr/Trailing bytes in authenticator data/,
        "With the expected message"
    );

    my $object = Authen::WebAuthn::getAttestationObject(
        encode_base64url(
            $authenticator->get_credential_response(
                { request => { challenge => "abc" } }
            )->{response}->{attestationObject}
        )
    );
    ok(
        !eval {
            Authen::WebAuthn::getAuthData( $object->{authDataRaw} . "\0" );
        },
        "Registration data with a byte more is refused"
    );
    like(
        $@,
        qr/Trailing bytes in authenticator data/,
        "With the expected message"
    );
};

subtest "Backup Eligibility does not change" => sub {
    my $eligible = assertion_flags( backupEligible => 1 );
    ok( authenticate( $eligible, stored_backup_eligible => 1 ),
        "Eligible, and eligible at registration" );
    ok(
        authenticate( undef, stored_backup_eligible => 0 ),
        "Not eligible, and not eligible at registration"
    );
    ok( authenticate($eligible), "Not checked without stored_backup_eligible" );

    ok( !authenticate( $eligible, stored_backup_eligible => 0 ),
        "Eligible, but not at registration" );
    like(
        $@,
        qr/Backup Eligibility flag is set but was not set at registration/,
        "... is refused"
    );
    ok(
        !authenticate( undef, stored_backup_eligible => 1 ),
        "Not eligible, but eligible at registration"
    );
    like(
        $@,
        qr/Backup Eligibility flag is not set but was set at registration/,
        "... is refused"
    );
};

subtest "Client data with a byte order mark" => sub {
    my $bom = "\xEF\xBB\xBF";

    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );
    ok(
        eval {
            $rp->validate_registration(
                challenge_b64        => "abc",
                client_data_json_b64 => encode_base64url(
                    $bom . $credential->{response}->{clientDataJSON}
                ),
                attestation_object_b64 => encode_base64url(
                    $credential->{response}->{attestationObject}
                ),
            );
        },
        "Registration"
    ) or diag $@;

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } } );
    my $response         = $assertion->{response};
    my $client_data_json = $bom . $response->{clientDataJSON};
    my %assertion        = (
        challenge_b64         => "def",
        credential_pubkey_b64 =>
          encode_base64url( $authenticator->encode_cosekey ),
        client_data_json_b64   => encode_base64url($client_data_json),
        authenticator_data_b64 =>
          encode_base64url( $response->{authenticatorData} ),
    );
    ok(
        eval {
            $rp->validate_assertion(
                %assertion,
                signature_b64 => encode_base64url(
                    $authenticator->sign(
                        $response->{authenticatorData}
                          . Digest::SHA::sha256($client_data_json)
                    )
                ),
            );
        },
        "Assertion, signed over the client data with its byte order mark"
    ) or diag $@;
    ok(
        !eval {
            $rp->validate_assertion( %assertion,
                signature_b64 => encode_base64url( $response->{signature} ) );
        },
        "... but not one signed over the client data without it"
    );
    like( $@, qr/signature was not valid/, "... with the expected message" );
};

done_testing();
