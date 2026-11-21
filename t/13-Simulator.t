use Test::More;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::RSA;
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# Every key type and attestation format the simulator can produce, through a
# full registration and authentication

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

sub ecc_pem {
    my $key = Crypt::PK::ECC->new;
    $key->generate_key(shift);
    return $key->export_key_pem('private');
}

sub rsa_pem {
    my $key = Crypt::PK::RSA->new;
    $key->generate_key( 256, 65537 );
    return $key->export_key_pem('private');
}

sub ed25519_pem {
    my $key = Crypt::PK::Ed25519->new;
    $key->generate_key;
    return $key->export_key_pem('private');
}

my $rsa_pem = rsa_pem();
my @keys    = (
    [ "ES256", -7,   ecc_pem("secp256r1") ],
    [ "ES384", -35,  ecc_pem("secp384r1") ],
    [ "ES512", -36,  ecc_pem("secp521r1") ],
    [ "RS256", -257, $rsa_pem ],
    [ "PS256", -37,  $rsa_pem, -37 ],
    [ "EdDSA", -8,   ed25519_pem() ],
);

sub authenticator {
    my ( $pem, %args ) = @_;
    return Authen::WebAuthn::Test->new(
        origin        => "http://auth.example.com",
        rp_id         => "auth.example.com",
        credential_id => "credential-" . int( rand 1e9 ),
        aaguid        => "00000000-0000-0000-0000-000000000000",
        key           => $pem,
        %args,
    );
}

sub register {
    my ( $authenticator, $override ) = @_;
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } }, $override );
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
        );
    };
}

sub authenticate {
    my ( $authenticator, $registration ) = @_;
    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } } );
    return scalar eval {
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
}

for my $key (@keys) {
    my ( $name, $alg, $pem, $alg_override ) = @$key;

    for my $format (qw(none packed)) {
        subtest "$name, $format attestation" => sub {
            my $authenticator = authenticator(
                $pem,
                attestation_format => $format,
                ( $alg_override ? ( alg => $alg_override ) : () ),
            );
            is( $authenticator->alg, $alg, "Algorithm" );

            my $registration = register($authenticator);
            ok( $registration, "Registration" ) or diag($@);
            is(
                $registration->{attestation_result}->{type},
                ( $format eq "packed" ? "Self" : "None" ),
                "Attestation type"
            );

            my $result = authenticate( $authenticator, $registration );
            ok( $result && $result->{success}, "Authentication" )
              or diag($@);
        };
    }
}

subtest "Self attestation is verified" => sub {
    my $authenticator =
      authenticator( ecc_pem("secp256r1"), attestation_format => "packed" );

    ok(
        !register(
            $authenticator,
            {
                response => {
                    attestationObject =>
                      { attStmt => { alg => -7, sig => "not a signature" } }
                }
            }
        ),
        "A wrong signature is refused"
    );
    like( $@, qr/Invalid attestation signature/, "With the expected message" );

    ok(
        !register(
            $authenticator,
            {
                response => {
                    attestationObject => {
                        attStmt => sub {
                            { alg => -257, sig => "x" }
                        }
                    }
                }
            }
        ),
        "An algorithm that is not the key's is refused"
    );
    like(
        $@,
qr/Attestation algorithm RS256 does not match credential key type ES256/,
        "With the expected message"
    );
};

done_testing();
