use Test::More;
use JSON         qw(decode_json);
use MIME::Base64 qw(encode_base64 encode_base64url);
use strict;

use Authen::WebAuthn;

# The test vectors of the WebAuthn specification (section 16), extracted by
# t/spec-vectors/extract from https://github.com/w3c/webauthn at commit
# d12a3f32e8df (2026-11-16)

my $vectors = do {
    open my $fh, "<", "t/spec-vectors/vectors.json" or die "vectors.json: $!";
    local $/;
    decode_json(<$fh>);
};

my $root = encode_base64( pack "H*",
    $vectors->{"sctn-test-vectors-attestation-root-cert"}->{common}
      ->{attestation_ca_cert} );
my $root_pem = "-----BEGIN CERTIFICATE-----\n$root-----END CERTIFICATE-----\n";

sub b64 { encode_base64url( pack "H*", shift ) }

sub register {
    my ( $rp, $vector, %options ) = @_;
    my $r = $vector->{registration};
    return scalar eval {
        $rp->validate_registration(
            challenge_b64          => b64( $r->{challenge} ),
            client_data_json_b64   => b64( $r->{clientDataJSON} ),
            attestation_object_b64 => b64( $r->{attestationObject} ),
            trust_anchors          => [$root_pem],
            %options,
        );
    };
}

sub authenticate {
    my ( $rp, $vector, $registration, %options ) = @_;
    my $a = $vector->{authentication};
    return scalar eval {
        $rp->validate_assertion(
            challenge_b64          => b64( $a->{challenge} ),
            credential_pubkey_b64  => $registration->{credential_pubkey},
            stored_sign_count      => 0,
            client_data_json_b64   => b64( $a->{clientDataJSON} ),
            authenticator_data_b64 => b64( $a->{authenticatorData} ),
            signature_b64          => b64( $a->{signature} ),
            %options,
        );
    };
}

my $rp = Authen::WebAuthn->new(
    rp_id  => "example.org",
    origin => "https://example.org",
);

my %supported = (
    "none-es256"                    => "None",
    "none-es256-long-credential-id" => "None",
    "packed-self-es256"             => "Self",
    "packed-es256"                  => "Basic",
    "packed-es384"                  => "Basic",
    "packed-es512"                  => "Basic",
    "packed-rs256"                  => "Basic",
    "packed-eddsa"                  => "Basic",
    "fido-u2f-es256"                => "Basic",
);

for my $name ( sort keys %supported ) {
    my $vector = $vectors->{"sctn-test-vectors-$name"};
    subtest $name => sub {
        my $registration = register( $rp, $vector );
        ok( $registration, "Registration verifies" ) or return diag($@);
        is( $registration->{attestation_result}->{type},
            $supported{$name}, "... as $supported{$name} attestation" );
        is(
            $registration->{credential_id},
            b64( $vector->{registration}->{credential_id} ),
            "... with the credential ID"
        );

        ok( authenticate( $rp, $vector, $registration ),
            "Authentication verifies" )
          or diag($@);

        my %tampered = %$vector;
        $tampered{authentication} = { %{ $vector->{authentication} } };
        substr( $tampered{authentication}->{signature}, -2 ) =
          substr( $tampered{authentication}->{signature}, -2 ) eq "00"
          ? "01"
          : "00";
        ok(
            !authenticate( $rp, \%tampered, $registration ),
            "... and not with its signature altered"
        );
    };
}

subtest "crossOrigin" => sub {
    my $vector = $vectors->{"sctn-test-vectors-none-es256-crossOrigin"};
    ok( !register( $rp, $vector ), "Refused by default" );
    like( $@, qr/Cross-origin requests are not allowed/,
        "... as cross-origin" );

    my $framed = Authen::WebAuthn->new(
        rp_id              => "example.org",
        origin             => "https://example.org",
        allow_cross_origin => 1,
    );
    my $registration = register( $framed, $vector );
    ok( $registration, "Registration verifies when allowed" ) or diag($@);
    ok( authenticate( $framed, $vector, $registration ),
        "... and authentication" )
      or diag($@);
};

subtest "topOrigin" => sub {
    my $vector = $vectors->{"sctn-test-vectors-none-es256-topOrigin"};
    my $framed = Authen::WebAuthn->new(
        rp_id              => "example.org",
        origin             => "https://example.org",
        allow_cross_origin => ["https://example.com"],
    );
    my $registration = register( $framed, $vector );
    ok( $registration, "Registration verifies from an allowed top origin" )
      or diag($@);
    ok( authenticate( $framed, $vector, $registration ),
        "... and authentication" )
      or diag($@);

    $framed->allow_cross_origin( ["https://example.net"] );
    ok( !register( $framed, $vector ), "Refused from another top origin" );
    like(
        $@,
        qr/Top origin https:\/\/example.com is not allowed/,
        "... as not allowed"
    );
};

# Attestation formats this module does not implement: refused, unless
# unknown formats are allowed, when the credential is still usable
for my $name (qw(tpm-es256 android-key-es256 apple-es256)) {
    my $vector = $vectors->{"sctn-test-vectors-$name"};
    subtest $name => sub {
        ok( !register( $rp, $vector ), "Refused" );
        like(
            $@,
            qr/Unsupported attestation format/,
            "... as an unsupported format"
        );

        my $registration =
          register( $rp, $vector, allow_unknown_attestation_format => 1 );
        ok( $registration, "Registers when unknown formats are allowed" )
          or return diag($@);
        is( $registration->{attestation_result}->{type},
            "None", "... as None" );
        ok( authenticate( $rp, $vector, $registration ),
            "... and authenticates" )
          or diag($@);
    };
}

subtest "packed-ed448" => sub {
    ok( !register( $rp, $vectors->{"sctn-test-vectors-packed-ed448"} ),
        "Refused" );
    like( $@, qr/Unsupported algorithm -53/,
        "... as an unsupported algorithm" );
};

is(
    scalar( grep { $vectors->{$_}->{registration} } keys %$vectors ),
    keys(%supported) + 2 + 3 + 1,
    "Every test vector is tested"
);

done_testing();
