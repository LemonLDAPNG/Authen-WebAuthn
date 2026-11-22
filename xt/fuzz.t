use Test::More;
use CBOR::XS;
use Crypt::OpenSSL::X509;
use B;
use JSON         qw(decode_json);
use JSON::PP     ();
use MIME::Base64 qw(encode_base64url decode_base64url);
use Time::HiRes  qw(time);
use Time::Local  qw(timegm);
use strict;
use warnings;

use Authen::WebAuthn;
use Authen::WebAuthn::Metadata;

# Mutation fuzzing of the parsers that read client-supplied bytes, seeded
# with the real-device responses and the test PKI. Each input must be
# accepted or refused with the module's own error: no Perl warning, no Perl
# error, nothing slow. Whatever CBOR the decoder accepts, CBOR::XS must read
# the same way.
#
#   FUZZ_SECONDS  seconds per target (default 10)
#   FUZZ_SEED     random seed (default: the time, printed)
#   FUZZ_TARGETS  comma-separated targets to run (default: all)
#   FUZZ_SAVE     a directory: each input is written there before it is
#                 tried, so one that crashes perl can be replayed

my $seconds = $ENV{FUZZ_SECONDS} // 10;
my $seed    = $ENV{FUZZ_SEED}    // time() ^ $$;
srand($seed);
diag("FUZZ_SEED=$seed");

# Errors a caller should never see
my $RAW_PERL_ERROR = qr/
    \b(?:HASH|ARRAY|CODE|SCALAR)\ ref\b
  | \bNot\ an?\ \w+\ reference\b
  | \bCan't\ (?:use|call|locate)\b
  | \buninitialized\b
  | \bDeep\ recursion\b
  | \bOut\ of\ memory\b
  | \bpanic\b
  | \boutside\ of\ string\b
  | \bIllegal\ division\b
/x;
my $SLOW = 1;    # seconds

sub slurp {
    my ($path) = @_;
    open my $fh, "<", $path or die "$path: $!";
    local $/;
    return <$fh>;
}

my $fixtures = decode_json( slurp("t/real-devices/fixtures.json") );
my %root =
  map { m{([^/]+)\.pem$}; ( $1 => slurp($_) ) }
  glob "t/real-devices/roots/*.pem";

sub fixture_time {
    my ($f) = @_;
    return $f->{time}
      ? timegm( 0, 0, 0, $f->{time}[2], $f->{time}[1] - 1, $f->{time}[0] )
      : undef;
}

sub register {
    my ( $f, %parts ) = @_;
    local $Authen::WebAuthn::SSLeayChainVerifier::verification_time =
      fixture_time($f);
    return Authen::WebAuthn->new(
        rp_id  => $f->{rp_id},
        origin => $f->{origins}
    )->validate_registration(
        challenge_b64               => $f->{challenge_b64},
        client_data_json_b64        => $f->{client_data_json_b64},
        attestation_object_b64      => $f->{attestation_object_b64},
        requested_uv                => "discouraged",
        trust_anchors               => [ map { $root{$_} } sort keys %root ],
        allow_untrusted_attestation => 1,
        %parts,
    );
}

sub authenticate {
    my ( $f, %parts ) = @_;
    return Authen::WebAuthn->new(
        rp_id  => $f->{rp_id},
        origin => $f->{origins}
    )->validate_assertion(
        (
            map { $_ => $f->{$_} }
              qw(challenge_b64 client_data_json_b64 authenticator_data_b64
              signature_b64 credential_id_b64 credential_pubkey_b64)
        ),
        stored_sign_count => 0,
        requested_uv      => "discouraged",
        %parts,
    );
}

# Seeds, taken from the fixtures as the module reads them
my ( %seeds, @registrations, @assertions, %pubkey );
for my $f (@$fixtures) {
    next unless $f->{expect} eq "accepted";
    if ( $f->{ceremony} eq "registration" ) {
        my $result = register($f);
        $pubkey{ $f->{name} } = $result->{credential_pubkey};
        push @registrations, $f;
        my $object = Authen::WebAuthn::_decode_cbor(
            decode_base64url( $f->{attestation_object_b64} ) );
        push @{ $seeds{cbor} },     encode_cbor_raw($object);
        push @{ $seeds{authdata} }, $object->{authData};
        push @{ $seeds{cose} },
          decode_base64url( $result->{credential_pubkey} );
        my $statement = $object->{attStmt};
        push @{ $seeds{tpm_pub_area} }, $statement->{pubArea}
          if $statement->{pubArea};

        for my $der ( @{ $statement->{x5c} || [] } ) {
            push @{ $seeds{certificate} }, $der;
            my $x509 = Authen::WebAuthn::_read_certificate($der);
            for (
                [ android_key_description => "1.3.6.1.4.1.11129.2.1.17" ],
                [ apple_nonce             => "1.2.840.113635.100.8.2" ],
              )
            {
                my ( $target, $oid ) = @$_;
                my $value =
                  Authen::WebAuthn::_certificate_extension( $x509, $oid );
                push @{ $seeds{$target} }, $value if defined $value;
            }
        }
    }
    else {
        $f = {
            %$f,
            credential_pubkey_b64 => $f->{credential_pubkey_b64}
              // $pubkey{ $f->{registration} }
        };
        push @assertions, $f;
        push @{ $seeds{authdata} },
          decode_base64url( $f->{authenticator_data_b64} );
    }
}
for my $path ( glob "t/pki/*.pem" ) {
    my $pem = slurp($path);
    next unless $pem =~ /BEGIN CERTIFICATE/;
    push @{ $seeds{certificate} },
      Crypt::OpenSSL::X509->new_from_string($pem)
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
}
$seeds{der} = [
    @{ $seeds{certificate} },
    @{ $seeds{android_key_description} },
    @{ $seeds{apple_nonce} }
];

# Metadata BLOBs from the test PKI, whole and as the payloads they sign
require "./t/mds.pl";
my @mds_entries = (
    mds_entry(),
    mds_entry(
        aaguid                               => undef,
        attestationCertificateKeyIdentifiers => ["0123456789abcdef"],
        statusReports                        => [
            { status => "FIDO_CERTIFIED_L1", effectiveDate => "2024-01-01" },
            {
                status      => "ATTESTATION_KEY_COMPROMISE",
                certificate =>
                  MIME::Base64::encode_base64( mds_der("root.pem"), "" ),
            },
        ],
    ),
);
my $mds_payload = {
    legalHeader => "Test metadata",
    no          => 7,
    nextUpdate  => "2100-01-01",
    entries     => \@mds_entries,
};
$seeds{metadata_blob} = [
    mds_blob( entries => \@mds_entries ),
    mds_blob( signer  => "mds-signer-rsa" )
];
$seeds{metadata_payload} = [ JSON::PP->new->canonical->encode($mds_payload) ];
my $mds_root = mds_pem("mds-root.pem");

# CBOR exactly as the module reads it, so the decoder sees real shapes
sub encode_cbor_raw {
    my ($value) = @_;
    my $head = sub {
        my ( $major, $n ) = @_;
        return pack( "C", $major << 5 | $n ) if $n < 24;
        return pack( "CC",  $major << 5 | 24, $n ) if $n < 2**8;
        return pack( "Cn",  $major << 5 | 25, $n ) if $n < 2**16;
        return pack( "CN",  $major << 5 | 26, $n ) if $n < 2**32;
        return pack( "CNN", $major << 5 | 27, int( $n / 2**32 ), $n % 2**32 );
    };
    return "\xf6" unless defined $value;
    if ( ref $value eq "HASH" ) {
        return $head->( 5, scalar keys %$value ) . join "", map {
                encode_cbor_raw( /^-?[0-9]+\z/ ? 0 + $_ : $_ )
              . encode_cbor_raw( $value->{$_} )
        } sort keys %$value;
    }
    if ( ref $value eq "ARRAY" ) {
        return $head->( 4, scalar @$value ) . join "",
          map { encode_cbor_raw($_) } @$value;
    }
    if ( Types::Serialiser::is_bool($value) ) {
        return $value ? "\xf5" : "\xf4";
    }
    if ( utf8::is_utf8($value) ) {
        my $bytes = $value;
        utf8::encode($bytes);
        return $head->( 3, length $bytes ) . $bytes;
    }
    if ( B::svref_2object( \$value )->FLAGS & ( B::SVf_IOK | B::SVf_NOK ) ) {
        return $value < 0 ? $head->( 1, -1 - $value ) : $head->( 0, $value );
    }
    return $head->( 2, length $value ) . $value;
}

# Bytes a parser treats specially: CBOR heads with long or indefinite
# lengths, tags, floats; DER long and indefinite lengths, high tag numbers
my @INTERESTING = map { chr } 0x00, 0x01, 0x7f, 0x80, 0x81, 0x82, 0x84,
  0xff, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x3b, 0x5b, 0x5f, 0x7b, 0x7f,
  0x9b, 0x9f, 0xbb, 0xbf, 0xc0, 0xd8, 0xd9, 0xf9, 0xfa, 0xfb, 0xff, 0x30,
  0x31, 0x04, 0x02, 0x03, 0xa0, 0xbf;
my @INTERESTING_RUNS = (
    "\xff" x 4,
    "\xff" x 8,
    "\x84\xff\xff\xff\xff",
    "\x9b" . "\xff" x 8,
    "\x5b\x00\x00\x00\x01\x00\x00\x00\x00",
    "\x81" x 32,
    "\x9f" x 32,
    "\xa1\x01" x 20,
    "\x30\x80",
    "\x1f\x81\x81\x81\x81\x01"
);

sub mutate {
    my ( $bytes, $pool ) = @_;
    for ( 1 .. 1 + int rand 4 ) {
        my $length = length $bytes;
        my $at     = int rand( $length + 1 );
        my $op     = int rand 9;
        if ( $op == 0 and $length ) {
            $at = int rand $length;
            substr( $bytes, $at, 1 ) ^= chr( 1 << int rand 8 );
        }
        elsif ( $op == 1 and $length ) {
            $at = int rand $length;
            substr( $bytes, $at, 1 ) = $INTERESTING[ rand @INTERESTING ];
        }
        elsif ( $op == 2 ) {
            substr( $bytes, $at, 0 ) = join "",
              map { chr rand 256 } 1 .. 1 + int rand 8;
        }
        elsif ( $op == 3 ) {
            substr( $bytes, $at, int rand( 1 + $length - $at ) ) = "";
        }
        elsif ( $op == 4 ) {
            my $chunk = substr( $bytes, $at, 1 + int rand 16 );
            substr( $bytes, $at, 0 ) = $chunk x ( 1 + int rand 4 );
        }
        elsif ( $op == 5 ) {
            $bytes = substr( $bytes, 0, $at );
        }
        elsif ( $op == 6 ) {
            my $other = $pool->[ rand @$pool ];
            my $from  = int rand( length($other) + 1 );
            substr( $bytes, $at, int rand 32 ) =
              substr( $other, $from, int rand 64 );
        }
        elsif ( $op == 7 ) {
            substr( $bytes, $at, int rand 9 ) =
              $INTERESTING_RUNS[ rand @INTERESTING_RUNS ];
        }
        elsif ( $op == 8 and $length >= 2 ) {
            $at = int rand( $length - 1 );
            substr( $bytes, $at, 2 ) = pack "n", int rand 65536;
        }
    }
    return $bytes;
}

# What CBOR::XS makes of the same bytes, in a form that can be compared:
# text and byte strings told apart, booleans and null spelled out
sub cbor_shape {
    my ($value) = @_;
    return ["null"] unless defined $value;
    return [ map { cbor_shape($_) } @$value ] if ref $value eq "ARRAY";
    return { map { $_ => cbor_shape( $value->{$_} ) } keys %$value }
      if ref $value eq "HASH";
    return [ "bool",   $value ? 1 : 0 ] if Types::Serialiser::is_bool($value);
    return [ "ref",    ref $value ]     if ref $value;
    return [ "text",   $value ]         if utf8::is_utf8($value);
    return [ "number", 0 + $value ]
      if B::svref_2object( \$value )->FLAGS & ( B::SVf_IOK | B::SVf_NOK );
    return [ "bytes", unpack "H*", $value ];
}

# Random CBOR, built with what the decoder must make of it: the value, in
# cbor_shape's form, or undef when it must be refused (and why)
sub generate_cbor {
    my ($depth) = @_;
    my @why;
    my $head = sub {
        my ( $major, $n ) = @_;
        my $width = rand;
        if ( $width < 0.05 ) {
            push @why, "indefinite length";
            return pack( "C", $major << 5 | 31 );
        }
        my $minimal =
            $n < 24    ? 0
          : $n < 2**8  ? 1
          : $n < 2**16 ? 2
          : $n < 2**32 ? 3
          :              4;
        my $size =
          $width < 0.85 ? $minimal : $minimal + int rand( 5 - $minimal );
        return pack( "C", $major << 5 | $n ) if $size == 0;
        return pack( "CC", $major << 5 | 24, $n ) if $size == 1;
        return pack( "Cn", $major << 5 | 25, $n ) if $size == 2;
        return pack( "CN", $major << 5 | 26, $n ) if $size == 3;
        push @why, "integer over 2**53" if $n >= 2**53;
        return pack( "CNN", $major << 5 | 27, int( $n / 2**32 ), $n % 2**32 );
    };
    my $number = sub {
        my $r = rand;
        return int rand 24    if $r < 0.4;
        return int rand 2**16 if $r < 0.7;
        return int rand 2**53 if $r < 0.95;
        return 2**53 + int rand 2**10;
    };
    my $text = sub {
        my @chars = map {
            my $r = rand;
                $r < 0.6  ? chr( 0x20 + int rand 0x5f )
              : $r < 0.8  ? chr( 0xa0 + int rand 0x700 )
              : $r < 0.95 ? chr( 0x4e00 + int rand 0x5000 )
              : chr( 0x10000 + int rand 0x1000 )
        } 1 .. int rand 12;
        return join "", @chars;
    };

    push @why, "nested too deeply" if $depth > 16;
    my ( $bytes, $shape );

    # Too deep already: only a scalar, so the item ends
    my $kind = $depth > 16 ? rand 0.47 : rand;
    if ( $kind < 0.15 ) {
        my $n = $number->();
        $bytes = $head->( 0, $n );
        $shape = [ "number", $n ];
    }
    elsif ( $kind < 0.25 ) {
        my $n = $number->();
        $bytes = $head->( 1, $n );
        $shape = [ "number", -1 - $n ];
    }
    elsif ( $kind < 0.35 ) {
        my $value = join "", map { chr rand 256 } 1 .. int rand 40;
        $bytes = $head->( 2, length $value ) . $value;
        $shape = [ "bytes", unpack "H*", $value ];
    }
    elsif ( $kind < 0.47 ) {
        my $value = $text->();
        my $utf8  = $value;
        utf8::encode($utf8);
        if ( rand() < 0.05 ) {
            $utf8 .=
              ( "\x80", "\xc0\xaf", "\xed\xa0\x80", "\xf8\x88\x80\x80\x80" )
              [ rand 4 ];
            push @why, "invalid UTF-8";
        }
        $bytes = $head->( 3, length $utf8 ) . $utf8;
        $shape = [ "text", $value ];
    }
    elsif ( $kind < 0.62 ) {
        my @items = map { generate_cbor( $depth + 1 ) } 1 .. int rand 5;
        $bytes = $head->( 4, scalar @items ) . join "", map { $_->[0] } @items;
        push @why, map { @{ $_->[2] } } @items;
        $shape = [ map { $_->[1] } @items ];
    }
    elsif ( $kind < 0.8 ) {
        my ( %map, @entries );
        for ( 1 .. int rand 5 ) {
            my ( $key_bytes, $key );
            my $r = rand;
            if ( $r < 0.5 ) {
                my $n        = int rand 30;
                my $negative = rand() < 0.3;
                $key_bytes = $head->( $negative ? 1 : 0, $n );
                $key       = $negative ? -1 - $n : $n;
            }
            elsif ( $r < 0.9 ) {
                $key = $text->();
                my $utf8 = $key;
                utf8::encode($utf8);
                $key_bytes = $head->( 3, length $utf8 ) . $utf8;
                push @why, "text key that reads as an integer"
                  if $key =~ /^-?[0-9]+\z/;
            }
            elsif ( $r < 0.95 ) {
                $key       = int rand 10;
                $key_bytes = $head->( 3, length $key ) . $key;
                push @why, "text key that reads as an integer";
            }
            else {
                $key       = "bytes";
                $key_bytes = $head->( 2, 5 ) . "bytes";
                push @why, "byte string key";
            }
            push @why, "duplicate key" if exists $map{$key};
            my $value = generate_cbor( $depth + 1 );
            push @why, @{ $value->[2] };
            $map{$key} = $value->[1];
            push @entries, $key_bytes . $value->[0];
        }
        $bytes = $head->( 5, scalar @entries ) . join "", @entries;
        $shape = \%map;
    }
    elsif ( $kind < 0.9 ) {
        my $r = int rand 3;
        $bytes = ( "\xf4", "\xf5", "\xf6" )[$r];
        $shape = $r == 2 ? ["null"] : [ "bool", $r ];
    }
    else {
        my $r = int rand 5;
        $bytes = (
            "\xf7",              "\xf9\x3c\x00",
            "\xfb" . "\x40" x 8, "\xe0",
            "\xc1\x1a\x00\x00\x00\x00"
        )[$r];
        push @why, ( "undefined", "float", "float", "simple value", "tag" )[$r];
    }
    return [ $bytes, $shape, \@why ];
}

my %targets = (
    cbor_generated => sub {
        my ( $bytes, $context ) = @_;
        my ( $shape, $why )     = @$context;
        my $value;
        my $ok = eval { $value = Authen::WebAuthn::_decode_cbor($bytes); 1 };
        if (@$why) {
            die "Accepts CBOR it should refuse (@$why)\n" if $ok;
            die $@;
        }
        die "Refuses valid CBOR: $@" unless $ok;
        my ( $ours, $expected ) =
          map { JSON::PP->new->canonical->encode($_) } cbor_shape($value),
          $shape;
        die "Decodes CBOR differently:\n  $ours\n  $expected\n"
          if $ours ne $expected;
    },
    cbor => sub {
        my $value = Authen::WebAuthn::_decode_cbor( $_[0] );
        my $xs    = eval { CBOR::XS->new->decode( $_[0] ) };
        die "CBOR::XS refuses what the decoder accepts: $@" if $@;
        my ( $ours, $theirs ) =
          map { JSON::PP->new->canonical->encode( cbor_shape($_) ) } $value,
          $xs;
        die "CBOR::XS reads it differently:\n  $ours\n  $theirs"
          if $ours ne $theirs;
    },
    cose => sub {
        Authen::WebAuthn::getPubKeyVerifier( $_[0] );
    },
    authdata => sub {
        Authen::WebAuthn::getAuthData( $_[0] );
    },
    der => sub {
        my @pending = ( $_[0] );
        my $steps   = 0;
        while ( defined( my $der = shift @pending ) ) {
            die "Too many DER values" if ++$steps > 100_000;
            for ( Authen::WebAuthn::_der_read_all($der) ) {
                push @pending, $_->[2] if $_->[0] & 0x20;
            }
        }
    },
    certificate => sub {
        my $x509 = Authen::WebAuthn::_read_certificate( $_[0] );
        eval { Authen::WebAuthn::attest_packed_check_cert_requirements($x509) };
        eval { Authen::WebAuthn::_tpm_check_cert_requirements($x509) };
        Authen::WebAuthn::_certificate_extension( $x509, $_ )
          for "1.3.6.1.4.1.11129.2.1.17", "1.2.840.113635.100.8.2",
          "1.3.6.1.4.1.45724.1.1.4";
    },
    android_key_description => sub {
        Authen::WebAuthn::_android_key_description( $_[0] );
    },
    apple_nonce => sub {
        Authen::WebAuthn::_apple_nonce( $_[0] );
    },
    tpm_pub_area => sub {
        Authen::WebAuthn::_tpm_public_area( $_[0] );
    },
    metadata_blob => sub {
        Authen::WebAuthn::Metadata->new(
            blob => $_[0],
            root => $mds_root,
            crls => mds_crls()
        );
    },

    # Signed again, so the payload reaches the parser behind the signature
    metadata_payload => sub {
        my $md = Authen::WebAuthn::Metadata->new(
            blob => mds_blob( payload_json => $_[0] ),
            root => $mds_root,
        );
        $md->entry( aaguid         => "01020304-0506-0708-090a-0b0c0d0e0f10" );
        $md->entry( key_identifier => "0123456789abcdef" );
    },
    registration => sub {
        my ( $f, $part, $bytes ) = @{ $_[1] };
        register( $f, $part => encode_base64url($bytes) );
    },
    assertion => sub {
        my ( $f, $part, $bytes ) = @{ $_[1] };
        authenticate( $f, $part => encode_base64url($bytes) );
    },
);

# The ceremonies mutate one part of a real response at a time
my %parts = (
    registration => [
        \@registrations,

        # The attestation object twice as often as the client data
        [
            qw(attestation_object_b64 attestation_object_b64
              client_data_json_b64)
        ]
    ],
    assertion => [
        \@assertions,
        [
            qw(authenticator_data_b64 signature_b64 client_data_json_b64
              credential_pubkey_b64)
        ]
    ],
);

my @run =
  $ENV{FUZZ_TARGETS}
  ? split /,/, $ENV{FUZZ_TARGETS}
  : sort keys %targets;
for my $target (@run) {
    my $code = $targets{$target} or BAIL_OUT("No target $target");
    my ( $tries, $refused, %findings ) = ( 0, 0 );
    my $slowest = 0;
    my $until   = time + $seconds;
    while ( time < $until ) {
        my ( $input, $context );
        if ( my $ceremony = $parts{$target} ) {
            my ( $fixtures, $names ) = @$ceremony;
            my $f    = $fixtures->[ rand @$fixtures ];
            my $part = $names->[ rand @$names ];
            my @pool = map { decode_base64url( $_->{$part} ) } @$fixtures;
            $input   = mutate( decode_base64url( $f->{$part} ), \@pool );
            $context = [ $f, $part, $input ];
        }
        elsif ( $target eq "cbor_generated" ) {

            # Sometimes deep inside one-element arrays, to reach the limit
            my $wrap      = rand() < 0.1 ? int rand 19 : 0;
            my $generated = generate_cbor($wrap);
            my @why       = @{ $generated->[2] };
            $input = "\x81" x $wrap . $generated->[0];
            $generated->[1] = [ $generated->[1] ] for 1 .. $wrap;
            if ( rand() < 0.05 and length $input > 1 ) {
                $input = substr( $input, 0, -1 );
                push @why, "truncated";
            }
            elsif ( rand() < 0.05 ) {
                $input .= "\x00";
                push @why, "trailing bytes";
            }
            $context = [ $generated->[1], \@why ];
        }
        else {
            my $pool = $seeds{$target};
            $input = mutate( $pool->[ rand @$pool ], $pool );
        }
        if ( $ENV{FUZZ_SAVE} ) {
            open my $fh, ">", "$ENV{FUZZ_SAVE}/$target" or die $!;
            binmode $fh;
            print $fh $parts{$target}
              ? "$context->[0]{name} $context->[1]\n"
              : "",
              $input;
        }

        my @warnings;
        local $SIG{__WARN__} = sub { push @warnings, @_ };
        my $start = time;
        my $ok    = eval {
            local $SIG{ALRM} = sub { die "Timed out\n" };
            alarm 10;
            $code->( $input, $context );
            alarm 0;
            1;
        };
        alarm 0;
        my $took = time - $start;
        $tries++;
        $slowest = $took if $took > $slowest;
        my $error = $ok ? "" : $@;
        $refused++ unless $ok;

        my $problem =
            @warnings                 ? "Warning: $warnings[0]"
          : $error =~ $RAW_PERL_ERROR ? "Perl error: $error"
          : $error =~
          /^(?:CBOR::XS|Too many|Timed out|Accepts|Refuses|Decodes)/ ? $error
          : $took > $SLOW ? sprintf( "Slow (%.1f s): %s", $took, $error )
          :                 "";
        next unless $problem;
        ( my $kind = $problem ) =~ s/ at \S+ line \d+.*//s;
        $kind =~ s/\d+/N/g;
        $findings{$kind} //= [ $problem, $input, $context ];
    }

    ok( !%findings,
        "$target: $tries inputs, $refused refused, slowest "
          . sprintf( "%.3f s", $slowest ) );
    for my $kind ( sort keys %findings ) {
        my ( $problem, $input, $context ) = @{ $findings{$kind} };
        diag(
                "  $problem"
              . "    input: "
              . unpack( "H*", substr( $input, 0, 400 ) )
              . (
                $parts{$target}
                ? "\n    fixture: $context->[0]{name} $context->[1]"
                : ""
              )
        );
    }
}

done_testing();
