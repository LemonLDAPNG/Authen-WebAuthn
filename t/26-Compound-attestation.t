use Test::More;
use Crypt::PK::ECC;
use Digest::SHA  qw(sha1_hex);
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Metadata;
use Authen::WebAuthn::Test;

# Compound attestation (WebAuthn Level 3, section 8.9): two or more
# statements of other formats, each verified by its own format, made by the
# simulator with the test PKI in t/pki
require "./t/mds.pl";

my $AAGUID = "01020304-0506-0708-090a-0b0c0d0e0f10";

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $credential_key = Crypt::PK::ECC->new;
$credential_key->generate_key("secp256r1");

# Statements for compound_statements
sub packed {
    my ($certificate) = @_;
    return { attestation_format => "packed" } unless $certificate;
    return {
        attestation_format       => "packed",
        attestation_key          => mds_pem("$certificate-key.pem"),
        attestation_certificates => [ mds_pem("$certificate.pem") ],
    };
}

sub u2f {
    return {
        attestation_format       => "fido-u2f",
        attestation_key          => mds_pem("packed-p256-key.pem"),
        attestation_certificates => [ mds_pem("packed-p256.pem") ],
    };
}

sub register {
    my ( $statements, %options ) = @_;
    my $override      = delete $options{override};
    my $authenticator = Authen::WebAuthn::Test->new(
        origin              => "http://auth.example.com",
        rp_id               => "auth.example.com",
        credential_id       => "credential",
        aaguid              => $AAGUID,
        key                 => $credential_key->export_key_pem("private"),
        attestation_format  => "compound",
        compound_statements => $statements,
    );
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } }, $override );
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
            trust_anchors => [ mds_pem("root.pem") ],
            %options,
        );
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Verified" => sub {
    my $reg = register( [ packed("packed-aaguid"), u2f() ] );
    ok( $reg, "packed and fido-u2f statements" ) or diag($@);
    my $result = $reg && $reg->{attestation_result};
    is( $result->{type}, "Compound", "... as Compound" );
    is_deeply( $result->{trust_path}, [], "... with no trust path of its own" );
    is_deeply(
        [ map { [ $_->{format}, $_->{type} ] } @{ $result->{statements} } ],
        [ [ "packed", "Basic" ], [ "fido-u2f", "Basic" ] ],
        "... each statement with its format and type"
    );
    is( scalar @{ $result->{statements}->[1]->{trust_path} },
        1, "... and trust path" );

    my $self = register( [ packed(), packed("packed-p256") ] );
    is_deeply(
        [ map { $_->{type} } @{ $self->{attestation_result}->{statements} } ],
        [ "Self", "Basic" ],
        "Self and Basic"
    );

    ok(
        register( [ { attestation_format => "none" }, packed("packed-p256") ] ),
        "A none statement among them"
    );

    my @formats;
    ok(
        register(
            [ packed("packed-p256"), u2f() ],
            trust_anchors => sub {
                my (%params) = @_;
                push @formats, $params{attestation_format};
                return [ mds_pem("root.pem") ];
            }
        ),
        "trust_anchors as a subroutine"
    );
    is_deeply(
        \@formats,
        [ "packed", "fido-u2f" ],
        "... asked for each format"
    );
};

subtest "Every statement must verify" => sub {
    refused(
        register(
            [
                packed("packed-p256"),
                {
                    attestation_format       => "packed",
                    attestation_key          => mds_pem("packed-p384-key.pem"),
                    attestation_certificates => [ mds_pem("packed-p256.pem") ],
                },
            ]
        ),
        qr/^Compound attestation statement 1: Failed to validate attestation/,
        "A statement whose signature does not verify"
    );
    refused(
        register( [ packed("packed-p256"), u2f() ], trust_anchors => [] ),
qr/^Compound attestation statement 0: Could not validate attestation trust/,
        "Statements whose chains are not trusted"
    );
    my $untrusted = register(
        [ packed("packed-p256"), packed() ],
        trust_anchors               => [],
        allow_untrusted_attestation => 1
    );
    is_deeply(
        [
            map { $_->{type} }
              @{ $untrusted->{attestation_result}->{statements} }
        ],
        [ "Self", "Self" ],
        "... which allow_untrusted_attestation makes Self"
    );
    refused(
        register(
            [ packed(), packed("packed-p256") ],
            allowed_attestation_types => ["Basic"]
        ),
qr/^Compound attestation statement 0: Attestation type Self is not allowed/,
        "A type allowed_attestation_types leaves out"
    );
};

subtest "Malformed" => sub {
    refused(
        register( [ packed("packed-p256") ] ),
        qr/Compound attestation statement is not a list of two or more/,
        "One statement"
    );
    refused(
        register(
            [],
            override =>
              { response => { attestationObject => { attStmt => {} } } }
        ),
        qr/Compound attestation statement is not a list of two or more/,
        "A map"
    );
    refused(
        register(
            [
                {
                    attestation_format  => "compound",
                    compound_statements => [ packed(), packed() ]
                },
                packed(),
            ]
        ),
qr/^Compound attestation statement 0: A compound attestation statement cannot hold another/,
        "A compound statement inside"
    );

    my $statements = sub {
        my (@statements) = @_;
        return {
            response => { attestationObject => { attStmt => \@statements } } };
    };
    my $fmt = "packed";
    utf8::upgrade($fmt);
    for (
        [
            [ "x", "y" ],
            qr/statement 0: Attestation statement is not a map/,
            "Statements that are not maps"
        ],
        [
            [ { attStmt => {} }, {} ],
            qr/statement 0: Attestation statement format is missing/,
            "No format"
        ],
        [
            [ { fmt => "packed", attStmt => {} }, {} ],
            qr/statement 0: Attestation statement format is not a text string/,
            "A format in bytes"
        ],
        [
            [ { fmt => $fmt, attStmt => [] }, {} ],
            qr/statement 0: Attestation statement is not a map/,
            "A statement that is not a map"
        ],
      )
    {
        my ( $list, $message, $name ) = @$_;
        refused( register( [], override => $statements->(@$list) ),
            $message, $name );
    }

    my $unknown = "unknown";
    utf8::upgrade($unknown);
    my $override = $statements->(
        { fmt => $unknown, attStmt => {} },
        { fmt => $unknown, attStmt => {} }
    );
    refused(
        register( [], override => $override ),
qr/statement 0: Unsupported attestation format during WebAuthn registration: unknown/,
        "A format the module does not know"
    );
    my $reg = register(
        [],
        override                         => $override,
        allow_unknown_attestation_format => 1
    );
    is_deeply(
        [ map { $_->{type} } @{ $reg->{attestation_result}->{statements} } ],
        [ "None", "None" ],
        "... which allow_unknown_attestation_format makes None"
    );
};

subtest "With metadata" => sub {
    my $key = Crypt::PK::ECC->new( \mds_pem("packed-p256-key.pem") );
    my $md  = sub {
        my (@status) = @_;
        return Authen::WebAuthn::Metadata->new(
            blob => mds_blob(
                entries => [
                    mds_entry( @status ? ( statusReports => [@status] ) : () ),
                    mds_entry(
                        aaguid                               => undef,
                        attestationCertificateKeyIdentifiers =>
                          [ sha1_hex( $key->export_key_raw("public") ) ],
                        statement => { description => "Test U2F key" },
                    ),
                ]
            ),
            root => mds_pem("mds-root.pem"),
        );
    };
    my $reg = register(
        [ packed("packed-aaguid"), u2f() ],
        metadata      => $md->(),
        trust_anchors => undef
    );
    ok( $reg, "Each statement chains to its model's roots" ) or diag($@);
    is_deeply(
        [
            map { $_->{metadata}->{description} }
              @{ $reg->{attestation_result}->{statements} }
        ],
        [ "Test authenticator", "Test U2F key" ],
        "... reporting each model"
    );
    refused(
        register(
            [ packed("packed-aaguid"), u2f() ],
            metadata      => $md->( { status => "REVOKED" } ),
            trust_anchors => undef
        ),
qr/^Compound attestation statement 0: Test authenticator \($AAGUID\) has metadata status REVOKED/,
        "A revoked model among them"
    );
};

done_testing();
