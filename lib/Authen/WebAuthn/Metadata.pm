package Authen::WebAuthn::Metadata;

use strict;
use warnings;

# VERSION
use Carp;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use HTTP::Tiny;
use JSON qw(decode_json);
use MIME::Base64 3.11 qw(decode_base64 decode_base64url encode_base64);
use Net::SSLeay;
use Time::Local qw(timegm);
use Authen::WebAuthn::SSLeayChainVerifier;

our $DEFAULT_URL = "https://mds3.fidoalliance.org/";

# GlobalSign Root R46, which FIDO's BLOB chains to
# (https://fidoalliance.org/metadata/), from
# https://secure.globalsign.com/cacert/rootr46.crt: SHA-256 fingerprint
# 4F:A3:12:6D:8D:3A:11:D1:C4:85:5A:4F:80:7C:BA:D6:CF:91:9D:3A:5A:88:B0:3B:EA:2C:63:72:D9:3C:40:C9
our $DEFAULT_ROOT = <<'PEM';
-----BEGIN CERTIFICATE-----
MIIFWjCCA0KgAwIBAgISEdK7udcjGJ5AXwqdLdDfJWfRMA0GCSqGSIb3DQEBDAUA
MEYxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRwwGgYD
VQQDExNHbG9iYWxTaWduIFJvb3QgUjQ2MB4XDTE5MDMyMDAwMDAwMFoXDTQ2MDMy
MDAwMDAwMFowRjELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYt
c2ExHDAaBgNVBAMTE0dsb2JhbFNpZ24gUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCsrHQy6LNl5brtQyYdpokNRbopiLKkHWPd08EsCVeJ
OaFV6Wc0dwxu5FUdUiXSE2te4R2pt32JMl8Nnp8semNgQB+msLZ4j5lUlghYruQG
vGIFAha/r6gjA7aUD7xubMLL1aa7DOn2wQL7Id5m3RerdELv8HQvJfTqa1VbkNud
316HCkD7rRlr+/fKYIje2sGP1q7Vf9Q8g+7XFkyDRTNrJ9CG0Bwta/OrffGFqfUo
0q3v84RLHIf8E6M6cqJaESvWJ3En7YEtbWaBkoe0G1h6zD8K+kZPTXhc+CtI4wSE
y132tGqzZfxCnlEmIyDLPRT5ge1lFgBPGmSXZgjPjHvjK8Cd+RTyG/FWaha/LIWF
zXg4mutCagI0GIMXTpRW+LaCtfOW3T3zvn8gdz57GSNrLNRyc0NXfeD412lPFzYE
+cCQYDdF3uYM2HSNrpyibXRdQr4G9dlkbgIQrImwTDsHTUB+JMWKmIJ5jqSngiCN
I/onccnfxkF0oE32kRbcRoxfKWMxWXEM2G/CtjJ9++ZdU6Z+Ffy7dXxd7Pj2Fxzs
x2sZy/N78CsHpdlseVR2bJ0cpm4O6XkMqCNqo98bMDGfsVR7/mrLZqrcZdCinkqa
ByFrgY/bxFn63iLABJzjqls2k+g9vXqhnQt2sQvHnf3PmKgGwvgqo6GDoLclcqUC
4wIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQUA1yrc4GHqMywptWU4jaWSf8FmSwwDQYJKoZIhvcNAQEMBQADggIBAHx4
7PYCLLtbfpIrXTncvtgdokIzTfnvpCo7RGkerNlFo048p9gkUbJUHJNOxO97k4Vg
JuoJSOD1u8fpaNK7ajFxzHmuEajwmf3lH7wvqMxX63bEIaZHU1VNaL8FpO7XJqti
2kM3S+LGteWygxk6x9PbTZ4IevPuzz5i+6zoYMzRx6Fcg0XERczzF2sUyQQCPtIk
pnnpHs6i58FZFZ8d4kuaPp92CC1r2LpXFNqD6v6MVenQTqnMdzGxRBF6XLE+0xRF
FRhiJBPSy03OXIPBNvIQtQ6IbbjhVp+J3pZmOUdkLG5NrmJ7v2B0GbhWrJKsFjLt
rWhV/pi60zTe9Mlhww6G9kuEYO4Ne7UyWHmRVSyBQ7N0H3qqJZ4d16GLuc1CLgSk
ZoNNiTW2bKg2SnkheCLQQrzRQDGQob4Ez8pn7fXwgNNgyYMqIgXQBztSvwyeqiv5
u+YfjyW6hY0XHgL+XVAEV8/+LbzvXMAaq7afJMbfc2hIkCwU9D9SGuTSyxTDYWnP
4vkYxboznxSjBF25cfe1lNj2M8FawTSLfJvdkzrnE6JwYZ+vj+vYxXX4M2bUdGc6
N3ec592kD3ZDZopD8p/7DEJ4Y9HiD2971KE9dJeFt0g5QdYg/NA6s/rob8SKunE3
vouXsXgxT7PntgMTzlSdriVZzH81Xwj3QEUxeCp6
-----END CERTIFICATE-----
PEM

# AuthenticatorStatus values (MDS 3.1, section 3.1.4); others are ignored
my %KNOWN_STATUS = map { $_ => 1 } qw(
  NOT_FIDO_CERTIFIED FIDO_CERTIFIED USER_VERIFICATION_BYPASS
  ATTESTATION_KEY_COMPROMISE USER_KEY_REMOTE_COMPROMISE
  USER_KEY_PHYSICAL_COMPROMISE UPDATE_AVAILABLE REVOKED
  SELF_ASSERTION_SUBMITTED FIDO_CERTIFIED_L1 FIDO_CERTIFIED_L1plus
  FIDO_CERTIFIED_L2 FIDO_CERTIFIED_L2plus FIDO_CERTIFIED_L3
  FIDO_CERTIFIED_L3plus FIPS140_CERTIFIED_L1 FIPS140_CERTIFIED_L2
  FIPS140_CERTIFIED_L3 FIPS140_CERTIFIED_L4
);

my %ALG = (
    ES256 => { class => "Crypt::PK::ECC", curve => "secp256r1" },
    RS256 => { class => "Crypt::PK::RSA" },
);

my $BASE64 = qr{\A[A-Za-z0-9+/]+={0,2}\z};
my $UUID = qr/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/;

sub new {
    my ( $class, %args ) = @_;

    my $blob = $args{blob};
    croak "Missing metadata BLOB" unless defined $blob and !ref $blob;
    my $roots = $args{root} // $DEFAULT_ROOT;
    $roots = [$roots] unless ref $roots;
    croak "Missing root certificate for the metadata BLOB"
      unless ref $roots eq "ARRAY" and @$roots;
    croak "crls must be an ARRAY reference"
      if defined $args{crls} and ref $args{crls} ne "ARRAY";

    my @parts = split /\./, $blob, -1;
    croak "Metadata BLOB is not a JWT"
      unless @parts == 3 and !grep { !/\A[A-Za-z0-9_-]+\z/ } @parts;
    my $header = _decode_json_object( decode_base64url( $parts[0] ), "header" );
    my $payload =
      _decode_json_object( decode_base64url( $parts[1] ), "payload" );
    my $signature = decode_base64url( $parts[2] );

    my $alg = $ALG{ $header->{alg} // "" }
      or croak "Unsupported metadata BLOB algorithm "
      . ( $header->{alg} // "(none)" );
    croak "Metadata BLOB certificates by URL (x5u) are not supported"
      if exists $header->{x5u};

    # Without x5c, the root itself signs (MDS 3.1, section 3.2)
    my @chain = _x5c($header);
    my $crls  = $args{crls} && [ map { _der_crl($_) } @{ $args{crls} } ];
    if (@chain) {
        my $result =
          Authen::WebAuthn::SSLeayChainVerifier::verify_chain( $roots,
            $chain[0], [ @chain[ 1 .. $#chain ] ], $crls );
        croak "Cannot verify the metadata BLOB's certificates: "
          . $result->{message}
          unless $result->{result};
    }

    my $signer =
      @chain
      ? _certificate( $chain[0],   Crypt::OpenSSL::X509::FORMAT_ASN1 )
      : _certificate( $roots->[0], Crypt::OpenSSL::X509::FORMAT_PEM );
    my $key = eval { $alg->{class}->new( \$signer->pubkey ) };
    croak "Metadata BLOB key does not match its algorithm $header->{alg}"
      unless $key
      and ( !$alg->{curve}
        or ( $key->key2hash->{curve_name} // "" ) eq $alg->{curve} );
    my $tbs = "$parts[0].$parts[1]";
    my $valid =
        $alg->{curve}
      ? $key->verify_message_rfc7518( $signature, $tbs, "SHA256" )
      : $key->verify_message( $signature, $tbs, "SHA256", "v1.5" );
    croak "Invalid metadata BLOB signature" unless $valid;

    my $no = $payload->{no};
    croak "Invalid metadata BLOB serial number"
      unless defined $no
      and !ref $no
      and $no =~ /\A[0-9]+\z/;
    croak "Metadata BLOB $no is not newer than $args{previous_no}"
      if defined $args{previous_no} and $no <= $args{previous_no};

    my $next_update = $payload->{nextUpdate} // "";
    my ( $year, $month, $day ) =
      $next_update =~ /\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/;
    my $expires =
      defined $year
      && eval { timegm( 0, 0, 0, $day, $month - 1, $year ) + 86400 }
      or croak "Invalid metadata BLOB nextUpdate";

    my $entries = $payload->{entries};
    croak "Invalid metadata BLOB entries" unless ref $entries eq "ARRAY";

    my $self = bless {
        blob        => $blob,
        no          => $no + 0,
        next_update => $next_update,
        expires     => $expires,
        crl_checked => @chain && $crls ? 1 : 0,
        legal       => $payload->{legalHeader},
        by_aaguid   => {},
        by_key_id   => {},
    }, $class;

    for my $i ( 0 .. $#$entries ) {
        my $entry = eval { _entry( $entries->[$i] ) }
          or croak "Invalid metadata BLOB entry $i: $@";
        $self->{by_aaguid}->{ $entry->{aaguid} } = $entry
          if defined $entry->{aaguid};
        $self->{by_key_id}->{$_} = $entry
          for @{ $entry->{attestation_certificate_key_identifiers} };
    }
    return $self;
}

sub blob        { $_[0]->{blob} }
sub no          { $_[0]->{no} }
sub next_update { $_[0]->{next_update} }
sub expires     { $_[0]->{expires} }
sub crl_checked { $_[0]->{crl_checked} }

sub check_freshness {
    my ( $self, %args ) = @_;
    my $grace = $args{grace_days} // 0;
    croak "metadata_grace_days must be a number of days"
      unless $grace =~ /\A[0-9]+\z/;
    croak
      "Metadata BLOB $self->{no} is out of date: its next update was due by "
      . $self->{next_update}
      if ( $args{now} // time ) >= $self->{expires} + $grace * 86400;
    return 1;
}

sub entry {
    my ( $self, $by, $value ) = @_;
    croak "entry takes aaguid or key_identifier"
      unless defined $by
      and ( $by eq "aaguid" or $by eq "key_identifier" );
    return unless defined $value;
    my $index = $by eq "aaguid" ? "by_aaguid" : "by_key_id";
    return $self->{$index}->{ lc $value };
}

sub fetch {
    my ( $class, %args ) = @_;

    my $url  = $args{url}  // $DEFAULT_URL;
    my $http = $args{http} // do {
        HTTP::Tiny->new(
            agent      => "Authen-WebAuthn/" . ( $class->VERSION // "dev" ),
            timeout    => 60,
            verify_SSL => 1,    # the default only from HTTP::Tiny 0.083
        );
    };

    my $blob = _get( $http, $url );
    $blob =~ s/\s+\z//;

    # The CRLs for each certificate the BLOB's signature chains through
    my $header = eval {
        _decode_json_object( decode_base64url( ( split /\./, $blob )[0] ),
            "header" );
    } or croak "Metadata BLOB from $url is not a JWT";
    my ( @crls, %seen );
    for my $der ( _x5c($header) ) {
        for my $crl_url ( _crl_distribution_points($der) ) {
            push @crls, _get( $http, $crl_url ) unless $seen{$crl_url}++;
        }
    }

    return $class->new(
        blob        => $blob,
        root        => $args{root},
        crls        => \@crls,
        previous_no => $args{previous_no},
    );
}

sub _get {
    my ( $http, $url ) = @_;
    my $response = $http->get($url);
    croak "Cannot download $url: $response->{status} $response->{reason}"
      . ( $response->{status} == 599 ? ": $response->{content}" : "" )
      unless $response->{success};
    return $response->{content};
}

sub _decode_json_object {
    my ( $json, $part ) = @_;
    my $value = eval { decode_json($json) };
    croak "Metadata BLOB $part is not a JSON object"
      unless ref $value eq "HASH";
    return $value;
}

sub _x5c {
    my ($header) = @_;
    return unless exists $header->{x5c};
    my $x5c = $header->{x5c};
    croak "Invalid metadata BLOB certificate chain"
      unless ref $x5c eq "ARRAY"
      and @$x5c
      and _strings( $x5c, $BASE64 );
    return map { decode_base64($_) } @$x5c;
}

# Whether every element of a list is a string matching a pattern
sub _strings {
    my ( $list, $pattern ) = @_;
    return !grep { ref or !defined or !/$pattern/ } @$list;
}

sub _certificate {
    my ( $data, $format ) = @_;
    my $x509 = eval { Crypt::OpenSSL::X509->new_from_string( $data, $format ) };
    Net::SSLeay::ERR_clear_error();
    croak "Cannot read metadata BLOB certificate" unless $x509;
    return $x509;
}

# CRLs come from distribution points as DER or, sometimes, PEM
sub _der_crl {
    my ($crl) = @_;
    croak "CRL must be a string" if ref $crl or !defined $crl;
    if ( $crl =~ /-----BEGIN X509 CRL-----(.*?)-----END X509 CRL-----/s ) {
        return decode_base64($1);
    }
    return $crl;
}

sub _crl_distribution_points {
    my ($der) = @_;
    my $x509  = Authen::WebAuthn::SSLeayChainVerifier::getX509($der);
    my @urls  = Net::SSLeay::P_X509_get_crl_distribution_points($x509);
    Net::SSLeay::X509_free($x509);
    return grep { m{\Ahttps?://}i } @urls;
}

sub _entry {
    my ($raw) = @_;
    die "not an object\n" unless ref $raw eq "HASH";

    my $statement = $raw->{metadataStatement};
    die "no metadataStatement\n" unless ref $statement eq "HASH";

    my $aaguid = $raw->{aaguid} // $statement->{aaguid};
    if ( defined $aaguid ) {
        $aaguid = lc $aaguid;
        die "invalid aaguid\n" unless $aaguid =~ $UUID;
    }

    my $key_ids = $raw->{attestationCertificateKeyIdentifiers}
      // $statement->{attestationCertificateKeyIdentifiers} // [];
    die "invalid attestationCertificateKeyIdentifiers\n"
      unless ref $key_ids eq "ARRAY"
      and _strings( $key_ids, qr/\A[0-9a-fA-F]+\z/ );

    my $reports = $raw->{statusReports} // [];
    die "invalid statusReports\n"
      unless ref $reports eq "ARRAY"
      and !grep { ref ne "HASH" or !defined $_->{status} or ref $_->{status} }
      @$reports;

    # The latest report is the current status (MDS 3.1, section 3.1.1)
    my ($current) = grep { $KNOWN_STATUS{ $_->{status} } } reverse @$reports;

    my $roots = $statement->{attestationRootCertificates} // [];
    die "invalid attestationRootCertificates\n"
      unless ref $roots eq "ARRAY" and _strings( $roots, $BASE64 );

    my $types = $statement->{attestationTypes} // [];
    die "invalid attestationTypes\n"
      unless ref $types eq "ARRAY" and _strings( $types, qr/^/ );

    return {
        aaguid                                  => $aaguid,
        attestation_certificate_key_identifiers => [ map { lc } @$key_ids ],
        description                             => $statement->{description},
        statement                               => $statement,
        status_reports                          => $reports,
        status            => $current ? $current->{status} : undef,
        status_report     => $current,
        attestation_types => $types,
        attestation_roots => [
            map {
                    "-----BEGIN CERTIFICATE-----\n"
                  . encode_base64( decode_base64($_) )
                  . "-----END CERTIFICATE-----\n"
            } @$roots
        ],
    };
}

1;

__END__

=head1 NAME

Authen::WebAuthn::Metadata - Read the FIDO Metadata Service

=head1 SYNOPSIS

    use Authen::WebAuthn::Metadata;

    # Download FIDO's BLOB and verify it, with the CRLs of its certificates
    my $metadata = Authen::WebAuthn::Metadata->fetch;

    # Keep $metadata->blob, and read it again later without the network
    $metadata = Authen::WebAuthn::Metadata->new( blob => $saved_blob );

    my $result = $webauthn_rp->validate_registration(
        ...,
        metadata => $metadata,
    );

=head1 DESCRIPTION

The L<FIDO Metadata Service|https://fidoalliance.org/metadata/> publishes a
signed list, the BLOB, of the authenticator models FIDO knows: the roots
their attestation chains to, and their status, such as whether a model's
attestation key has been compromised.

This module verifies a BLOB and answers questions about it.
L<Authen::WebAuthn/validate_registration> takes the resulting object as its
C<metadata> parameter.

Only C<fetch> uses the network. You decide how often to call it, typically
daily or at least before the BLOB's C<next_update> date, and where to keep the
BLOB between calls.

Retrieving and using the FIDO BLOB means accepting FIDO's
L<metadata terms|https://fidoalliance.org/metadata/metadata-legal-terms/>.

=head1 METHODS

=head2 new

    my $metadata = Authen::WebAuthn::Metadata->new(
        blob        => $blob,
        root        => $root_pem,
        crls        => [ $crl, ... ],
        previous_no => $no,
    );

Verifies a BLOB and returns an object, or croaks saying why the BLOB was
refused.

=over 4

=item blob

The BLOB, a JSON Web Token, as downloaded.

=item root

The PEM certificate the BLOB's signing certificates chain to, or an arrayref
of them. By default, GlobalSign Root R46, the root of FIDO's production BLOB,
which this module includes.

=item crls

Optional: the CRLs, DER or PEM, of every certificate in the BLOB's chain.
When given, a certificate without a CRL, or revoked by one, is refused, and
C<crl_checked> is true.

=item previous_no

Optional: the serial number of the last BLOB you accepted. A BLOB whose number
is not higher is refused.

=back

=head2 fetch

    my $metadata = Authen::WebAuthn::Metadata->fetch(
        url         => "https://mds3.fidoalliance.org/",
        root        => $root_pem,
        previous_no => $no,
        http        => HTTP::Tiny->new(...),
    );

Downloads the BLOB from C<url> (FIDO's by default), then the CRL of every
certificate it chains through, and passes them to C<new>; C<root> and
C<previous_no> are as for C<new>. HTTPS needs L<IO::Socket::SSL>.

FIDO answers downloads repeated within minutes with "429 Too Many Requests",
and suggests a monthly download. The BLOB is about 11 MB; reading it takes a
fraction of a second with L<JSON::XS>, and some seconds without.

=head2 entry

    my $entry = $metadata->entry( aaguid => $aaguid );
    my $entry = $metadata->entry( key_identifier => $hex );

The entry for an authenticator model, by AAGUID, or for U2F authenticators by
the key identifier of the attestation certificate (RFC 5280's method 1, in
hexadecimal). Returns undef for a model the BLOB does not list.

An entry is a hashref with C<aaguid>, C<description>, C<status> (the current
status, from the latest status report whose status is known),
C<status_report>, C<status_reports>, C<attestation_types>,
C<attestation_roots> (PEM certificates) and C<statement>, the metadata
statement as FIDO publishes it.

=head2 check_freshness

    $metadata->check_freshness( grace_days => 7 );

Croaks if the BLOB is past its C<next_update> date by more than
C<grace_days> (0 by default). C<now> gives the time to check at, in epoch
seconds. C<validate_registration> calls it.

=head2 blob, no, next_update, expires, crl_checked

The BLOB as given, its serial number, its C<nextUpdate> date, the time (epoch
seconds) at the end of that date, and whether its certificates were checked
against CRLs.

=cut
