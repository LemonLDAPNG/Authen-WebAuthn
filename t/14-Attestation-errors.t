use Test::More;
use CBOR::XS;
use MIME::Base64 qw(encode_base64url decode_base64url);
use Net::SSLeay;
use strict;

use Authen::WebAuthn;

use lib ".";
require 't/certs.pl';
require 't/responses.pl';

$Authen::WebAuthn::SSLeayChainVerifier::verification_time = 1698765432;

my $webauthn = Authen::WebAuthn->new(
    origin => "http://localhost:5000",
    rp_id  => "localhost",
);

my %packed = %main::packed_attestation_response;
my %u2f    = %main::u2f_attestation_response;

# Re-encodes a response with its attestation statement changed
sub with_statement {
    my ( $response, $change ) = @_;
    my $object = CBOR::XS::decode_cbor(
        decode_base64url( $response->{attestation_object_b64} ) );
    $change->( $object->{attStmt} );
    return ( %$response,
        attestation_object_b64 =>
          encode_base64url( CBOR::XS->new->text_keys(1)->encode($object) ), );
}

sub register {
    my (%params) = @_;
    return scalar eval { $webauthn->validate_registration(%params) };
}

subtest "trust_anchors as a code reference" => sub {
    my %seen;
    my $reg = register(
        %packed,
        trust_anchors => sub {
            %seen = @_;
            return [$main::yubico_u2f_root];
        },
    );
    ok( $reg, "Registration succeeds" ) or diag($@);
    is( $seen{attestation_type},   "Basic",  "Given the attestation type" );
    is( $seen{attestation_format}, "packed", "Given the attestation format" );
    like(
        $seen{aaguid},
        qr/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
        "Given the AAGUID"
    );

    ok(
        !register( %packed, trust_anchors => sub { "not a list" } ),
        "A code reference that does not return a list is refused"
    );
    like(
        $@,
        qr/trust_anchors sub must return an ARRAY reference/,
        "With the expected message"
    );

    ok(
        !register( %packed, trust_anchors => "not a list" ),
        "A trust_anchors that is neither is refused"
    );
    like(
        $@,
        qr/trust_anchors parameter must be a SUB or ARRAY reference/,
        "With the expected message"
    );
};

subtest "A trust anchor that is not a certificate" => sub {
    for my $anchors ( ["garbage"], [ $main::yubico_u2f_root, "garbage" ] ) {
        ok( !register( %packed, trust_anchors => $anchors ),
            "Registration fails" );
        like( $@, qr/Could not parse certificate/,
            "With the expected message" );
        is( Net::SSLeay::ERR_peek_error(),
            0, "OpenSSL's error queue is left empty" );
    }
};

subtest "Packed attestation" => sub {
    ok(
        !register(
            with_statement( \%packed, sub { $_[0]->{sig} = "x" x 70 } ),
            trust_anchors => [$main::yubico_u2f_root],
        ),
        "A wrong signature is refused"
    );
    like( $@, qr/Invalid attestation signature/, "With the expected message" );

    ok(
        !register(
            with_statement( \%packed, sub { $_[0]->{x5c} = "not a list" } ),
            trust_anchors => [$main::yubico_u2f_root],
        ),
        "A certificate field that is not a list is refused"
    );
    like(
        $@,
        qr/Invalid certificate field in attestation statement/,
        "With the expected message"
    );
};

subtest "FIDO U2F attestation" => sub {
    ok(
        !register(
            with_statement( \%u2f, sub { delete $_[0]->{x5c} } ),
            trust_anchors => [$main::yubico_u2f_root],
        ),
        "A missing certificate is refused"
    );
    like(
        $@,
        qr/Missing certificate field in attestation statement/,
        "With the expected message"
    );

    ok(
        !register(
            with_statement( \%u2f, sub { $_[0]->{sig} = "x" x 70 } ),
            trust_anchors => [$main::yubico_u2f_root],
        ),
        "A wrong signature is refused"
    );
    like( $@, qr/Signature verification failed/, "With the expected message" );
};

done_testing();
