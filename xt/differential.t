use Test::More;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::RSA;
use File::Spec;
use File::Temp qw(tempfile);
use IPC::Open3;
use JSON;
use List::Util   qw(sum0);
use MIME::Base64 qw(encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# Differential test against other WebAuthn libraries: py_webauthn
# (https://github.com/duo-labs/py_webauthn) and SimpleWebAuthn
# (https://simplewebauthn.dev). The same registration and authentication
# responses, valid and corrupted, are verified by this module and by each
# library that is installed, which must agree on every one, apart from the
# differences listed for it.
#
#   pip install webauthn
#   npm install @simplewebauthn/server    # then set NODE_PATH to its
#                                         # node_modules
#   prove -l xt/differential.t
#
# DIFFERENTIAL_PYTHON and DIFFERENTIAL_NODE name the interpreters to use;
# by default, python3 and node.

my $registration_key_check = {
    accepts => "theirs",
    ours    => qr/^Invalid credential public key/,
    why     => "Authen::WebAuthn refuses at registration a key that "
      . "could never verify",
};
my $trailing_bytes = {
    accepts => "theirs",
    ours    => qr/^Trailing bytes after CBOR data/,
    why     => "it ignores bytes after the attestation object",
};

# Each library, and where it differs from this module on purpose: which
# side accepts, a pattern for the other side's error, and why
my @LIBRARIES = (
    {
        name    => "py_webauthn",
        command => [
            $ENV{DIFFERENTIAL_PYTHON} // "python3",
            "xt/differential/py_webauthn_verify.py"
        ],
        check =>
          [ $ENV{DIFFERENTIAL_PYTHON} // "python3", "-c", "import webauthn" ],
        known => [
            $registration_key_check,
            $trailing_bytes,
            {
                accepts => "ours",
                theirs  => qr/alg "?-35/,
                why     => "it does not support ES384",
            },
            {
                accepts => "theirs",
                ours    => qr/^Attestation statement is not a map/,
                why     => "it accepts an attestation object without attStmt "
                  . "when fmt is none; the attestation object's syntax "
                  . "requires it",
            },
            {
                accepts => "ours",
                theirs  => qr/AAGUID .* was not expected .*FIDO-U2F/,
                why     => "it requires a zero AAGUID with fido-u2f "
                  . "attestation, which the verification procedure does "
                  . "not; the specification's own fido-u2f test vector has "
                  . "a non-zero one",
            },
        ],
    },
    {
        name    => "SimpleWebAuthn",
        command => [
            $ENV{DIFFERENTIAL_NODE} // "node",
            "xt/differential/simplewebauthn_verify.js"
        ],
        check => [
            $ENV{DIFFERENTIAL_NODE} // "node", "-e",
            "require('\@simplewebauthn/server')"
        ],
        known => [
            $registration_key_check,
            $trailing_bytes,
            {
                accepts => "theirs",
                ours    => qr/^CBOR data is truncated/,
                why => "it reads authData as the bytes that remain when its "
                  . "declared length runs past the end of the attestation "
                  . "object",
            },
            {
                accepts => "theirs",
                ours    => qr/failed to read X509 certificate/,
                why     => "it reads a certificate whose outer SEQUENCE tag "
                  . "has been changed, which is not DER",
            },
        ],
    },
);

sub available {
    my ($command) = @_;
    my $pid = eval { open3( my $in, my $out, undef, @$command ) };
    return $pid && do { waitpid( $pid, 0 ); $? == 0 };
}
@LIBRARIES = grep { available( $_->{check} ) } @LIBRARIES;
plan skip_all => "Neither py_webauthn nor SimpleWebAuthn is available"
  unless @LIBRARIES;

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

my $rp_id  = "auth.example.com";
my $origin = "https://auth.example.com";
my $rp     = Authen::WebAuthn->new( rp_id => $rp_id, origin => $origin );

# Fixed keys, so that the same cases are compared in every run. ES384 is
# not compared: py_webauthn refuses its algorithm before anything else.
my %keys = (
    ES256 => pem("packed-chained-key"),
    ES384 => pem("packed-p384-key"),
    ES512 => <<'P521',
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAG4b2lZydKmrx60ri
plUZjVJU37AFYipC0haYZvCW5yqBLRzvZdDNSZ3DEe2EAV0/R7OArM7a2vk/EftS
MewIWyehgYkDgYYABAEUHJwR9zk/EFX3wxaLB+MMs42iXDYlJvfD/VuGQXK3g0i2
ArYWaFw1xpVcNluvZqDInjHfq0FtKPLL3aHw02lhagCHEdRQShgp0lLg5vjlI5Tp
SMCohREZG3KVTMvUXxxKCO8L1cPAvFeCLP5cIp7iFlJ7TviZutVwxH/SAgjQ3H7Y
Yw==
-----END PRIVATE KEY-----
P521
    RS256 => pem("packed-rsa-key"),
    PS256 => pem("packed-rsa-key"),
    EdDSA => pem("packed-ed25519-key"),
);

my @authenticators;
for my $name ( sort keys %keys ) {
    for my $format ( "none", "packed-self", "packed-x5c",
        ( $name eq "ES256" ? "fido-u2f" : () ) )
    {
        push @authenticators,
          [
            "$name $format",
            Authen::WebAuthn::Test->new(
                origin        => $origin,
                rp_id         => $rp_id,
                credential_id => "credential-$name-$format",
                aaguid        => "00000000-0000-0000-0000-000000000000",
                key           => $keys{$name},
                ( $name eq "PS256" ? ( alg => -37 ) : () ),
                attestation_format => $format eq "fido-u2f" ? "fido-u2f"
                : ( split /-/, $format )[0],
                (
                    $format =~ /x5c|u2f/
                    ? (
                        attestation_key          => pem("packed-p256-key"),
                        attestation_certificates => [ pem("packed-p256") ],
                      )
                    : ()
                ),
            )
          ];
    }
}

# Seeded per case, so that adding a case changes no other
sub corrupt {
    my ( $bytes, $case ) = @_;
    srand( 20261121 + $case );
    for ( 1 .. 1 + int rand 3 ) {
        my $at   = int rand length $bytes;
        my $kind = rand;
        if ( $kind < .6 ) {
            substr( $bytes, $at, 1 ) = chr int rand 256;
        }
        elsif ( $kind < .8 ) {
            $bytes = substr( $bytes, 0, $at );
        }
        else {
            substr( $bytes, $at, 0 ) =
              join( "", map { chr int rand 256 } 1 .. 1 + int rand 8 );
        }
    }
    return $bytes;
}

# Each case: what both libraries are given, and our verdict
my @cases;
for my $entry (@authenticators) {
    my ( $label, $authenticator ) = @$entry;
    my $id = encode_base64url( $authenticator->credential_id );

    my $registration = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } )->{response};
    my $public_key = encode_base64url( $authenticator->encode_cosekey );

    for my $variant ( 0 .. 40 ) {
        my $attestation_object = $registration->{attestationObject};
        $attestation_object = corrupt( $attestation_object, scalar @cases )
          if $variant;
        push @cases,
          {
            label => "$label registration" . ( $variant ? " #$variant" : "" ),
            ceremony      => "registration",
            rp_id         => $rp_id,
            origin        => $origin,
            challenge_b64 => "abc",
            root_pems     => [ pem("root") ],
            credential    => {
                id       => $id,
                rawId    => $id,
                type     => "public-key",
                response => {
                    clientDataJSON =>
                      encode_base64url( $registration->{clientDataJSON} ),
                    attestationObject => encode_base64url($attestation_object),
                },
                clientExtensionResults => {},
            },
          };
    }

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } } );
    for my $variant ( 0 .. 40 ) {
        my %response = %{ $assertion->{response} };
        if ($variant) {
            my $field = $variant % 2 ? "authenticatorData" : "signature";
            $response{$field} = corrupt( $response{$field}, scalar @cases );
        }
        push @cases,
          {
            label => "$label authentication" . ( $variant ? " #$variant" : "" ),
            ceremony       => "authentication",
            rp_id          => $rp_id,
            origin         => $origin,
            challenge_b64  => "def",
            public_key_b64 => $public_key,
            sign_count     => 0,
            credential     => {
                id       => $id,
                rawId    => $id,
                type     => "public-key",
                response => {
                    map { $_ => encode_base64url( $response{$_} ) }
                      qw(clientDataJSON authenticatorData signature)
                },
                clientExtensionResults => {},
            },
          };
    }
}

for my $case (@cases) {
    my $r  = $case->{credential}->{response};
    my $ok = eval {
        if ( $case->{ceremony} eq "registration" ) {
            $rp->validate_registration(
                challenge_b64          => $case->{challenge_b64},
                client_data_json_b64   => $r->{clientDataJSON},
                attestation_object_b64 => $r->{attestationObject},
                trust_anchors          => $case->{root_pems},
            );
        }
        else {
            $rp->validate_assertion(
                challenge_b64          => $case->{challenge_b64},
                credential_pubkey_b64  => $case->{public_key_b64},
                stored_sign_count      => $case->{sign_count},
                client_data_json_b64   => $r->{clientDataJSON},
                authenticator_data_b64 => $r->{authenticatorData},
                signature_b64          => $r->{signature},
            );
        }
        1;
    };
    $case->{ours} =
      $ok ? { ok => 1 } : { ok => 0, error => $@ =~ s/ at \S+ line \d+.*//sr };
}

my ( $fh, $input ) = tempfile( UNLINK => 1 );
print $fh encode_json(
    [
        map {
            { %$_, ours => undef }
        } @cases
    ]
);
close $fh;

for my $library (@LIBRARIES) {
    subtest $library->{name} => sub { compare( $library, $input ) };
}

sub compare {
    my ( $library, $input ) = @_;
    my $name = $library->{name};

    my $command = join " ", map { quotemeta } @{ $library->{command} };
    my $theirs  = decode_json(`$command < $input`);
    is( scalar @$theirs, scalar @cases, "$name verified every case" );

    my ( $agree, %known, @disagree ) = (0);
  CASE: for my $i ( 0 .. $#cases ) {
        my ( $ours, $other ) = ( $cases[$i]{ours}, $theirs->[$i] );
        if ( !!$ours->{ok} == !!$other->{ok} ) {
            $agree++;
            next;
        }
        for my $known ( @{ $library->{known} } ) {
            my ( $accepts, $refuses ) =
              $known->{accepts} eq "ours"
              ? ( $ours, $other )
              : ( $other, $ours );
            my $pattern =
              $known->{ $known->{accepts} eq "ours" ? "theirs" : "ours" };
            if ( $accepts->{ok} and $refuses->{error} =~ $pattern ) {
                $known{ $known->{why} }++;
                next CASE;
            }
        }
        push @disagree, sprintf "%s: ours %s, %s %s",
          $cases[$i]{label},
          $ours->{ok} ? "accepts" : "refuses ($ours->{error})",
          $name,
          $other->{ok} ? "accepts" : "refuses ($other->{error})";
    }
    diag(
            scalar(@cases)
          . " cases, $agree agree, "
          . sum0( values %known )
          . " differ as expected, "
          . scalar(@disagree)
          . " disagree" );
    diag("  $known{$_} because $_") for sort keys %known;

    # For a closer look at the cases
    if ( my $dump = $ENV{DIFFERENTIAL_DUMP} ) {
        open my $fh, ">", "$dump.$name" or die "$dump.$name: $!";
        print $fh encode_json(
            [
                map {
                    { %{ $cases[$_] }, theirs => $theirs->[$_] }
                } 0 .. $#cases
            ]
        );
    }
    diag($_) for @disagree;
    ok( !@disagree, "$name and Authen::WebAuthn agree on every case" );
}

done_testing();
