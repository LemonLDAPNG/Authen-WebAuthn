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
    my ($override) = @_;

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
        );
    };
}

sub registration_flags { { response => { attestationObject => { authData => { flags => {@_} } } } } }
sub assertion_flags    { { response => { authenticatorData => { flags => {@_} } } } }

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

ok( !register( undef, registration_flags( backupState => 1 ) ),
    "Registration: backed up without being eligible is refused" );
like( $@, qr/Backup State flag is set but Backup Eligibility is not/,
    "With the expected message" );

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

ok( !authenticate( assertion_flags( backupState => 1 ) ),
    "Assertion: backed up without being eligible is refused" );
like( $@, qr/Backup State flag is set but Backup Eligibility is not/,
    "With the expected message" );

ok(
    !register(
        undef,
        {
            response => {
                attestationObject => {
                    authData => {
                        attestedCredentialData =>
                          { credentialId => "x" x 1024 }
                    }
                }
            }
        }
    ),
    "A 1024 byte credential ID is refused"
);
like( $@, qr/Credential ID is longer than 1023 bytes/,
    "With the expected message" );

done_testing();
