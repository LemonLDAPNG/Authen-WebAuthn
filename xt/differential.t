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

# Differential test against py_webauthn (https://github.com/duo-labs/py_webauthn):
# the same registration and authentication responses, valid and corrupted,
# are verified by both libraries, which must agree on every one, apart from
# the differences listed in %KNOWN.
#
#   pip install webauthn
#   prove -l xt/differential.t
#
# DIFFERENTIAL_PYTHON names the Python to use; by default, python3.

# Where the two libraries differ on purpose: which side accepts, a pattern
# for the other side's error, and why
my @KNOWN = (
    {
        accepts => "ours",
        theirs  => qr/alg "?-35/,
        why     => "py_webauthn does not support ES384",
    },
    {
        accepts => "theirs",
        ours    => qr/^Invalid credential public key/,
        why     => "Authen::WebAuthn refuses at registration a key that "
          . "could never verify",
    },
    {
        accepts => "theirs",
        ours    => qr/^garbage after CBOR object/,
        why     => "py_webauthn ignores bytes after the attestation object",
    },
    {
        accepts => "ours",
        theirs  => qr/AAGUID .* was not expected .*FIDO-U2F/,
        why     => "py_webauthn requires a zero AAGUID with fido-u2f "
          . "attestation, which the verification procedure does not; the "
          . "specification's own fido-u2f test vector has a non-zero one",
    },
);

my $python = $ENV{DIFFERENTIAL_PYTHON} // "python3";
my $script = "xt/differential/py_webauthn_verify.py";
{
    my $pid = eval {
        open3( my $in, my $out, undef, $python, "-c", "import webauthn" );
    };
    my $ok = $pid && do { waitpid( $pid, 0 ); $? == 0 };
    plan skip_all => "$python with py_webauthn is not available" unless $ok;
}

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

my $rp_id  = "auth.example.com";
my $origin = "https://auth.example.com";
my $rp     = Authen::WebAuthn->new( rp_id => $rp_id, origin => $origin );

my %keys = (
    ES256 =>
      sub { my $k = Crypt::PK::ECC->new; $k->generate_key("secp256r1"); $k },
    ES384 =>
      sub { my $k = Crypt::PK::ECC->new; $k->generate_key("secp384r1"); $k },
    ES512 =>
      sub { my $k = Crypt::PK::ECC->new; $k->generate_key("secp521r1"); $k },
    RS256 =>
      sub { my $k = Crypt::PK::RSA->new; $k->generate_key( 256, 65537 ); $k },
    PS256 =>
      sub { my $k = Crypt::PK::RSA->new; $k->generate_key( 256, 65537 ); $k },
    EdDSA => sub { my $k = Crypt::PK::Ed25519->new; $k->generate_key; $k },
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
                key           => $keys{$name}->()->export_key_pem("private"),
                ( $name eq "PS256" ? ( alg => -37 ) : () ),
                attestation_format => $format eq "fido-u2f" ? "fido-u2f"
                : $format =~ s/-.*//r,
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

srand(20261121);

sub corrupt {
    my ($bytes) = @_;
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
        $attestation_object = corrupt($attestation_object) if $variant;
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
            $response{$field} = corrupt( $response{$field} );
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
my $theirs = decode_json(`$python $script < $input`);
is( scalar @$theirs, scalar @cases, "py_webauthn verified every case" );

my ( $agree, %known, @disagree ) = (0);
CASE: for my $i ( 0 .. $#cases ) {
    my ( $ours, $other ) = ( $cases[$i]{ours}, $theirs->[$i] );
    if ( !!$ours->{ok} == !!$other->{ok} ) {
        $agree++;
        next;
    }
    for my $known (@KNOWN) {
        my ( $accepts, $refuses ) =
          $known->{accepts} eq "ours" ? ( $ours, $other ) : ( $other, $ours );
        my $pattern =
          $known->{ $known->{accepts} eq "ours" ? "theirs" : "ours" };
        if ( $accepts->{ok} and $refuses->{error} =~ $pattern ) {
            $known{ $known->{why} }++;
            next CASE;
        }
    }
    push @disagree, sprintf "%s: ours %s, py_webauthn %s",
      $cases[$i]{label},
      $ours->{ok}  ? "accepts" : "refuses ($ours->{error})",
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
if ( $ENV{DIFFERENTIAL_DUMP} ) {
    open my $dump, ">", $ENV{DIFFERENTIAL_DUMP}
      or die "$ENV{DIFFERENTIAL_DUMP}: $!";
    print $dump encode_json(
        [
            map {
                { %{ $cases[$_] }, theirs => $theirs->[$_] }
            } 0 .. $#cases
        ]
    );
}
diag($_) for @disagree;
ok( !@disagree, "Both libraries agree on every case" );

done_testing();
