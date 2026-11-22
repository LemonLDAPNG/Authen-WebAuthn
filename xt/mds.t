use Test::More;
use JSON        qw(decode_json);
use Time::Local qw(timegm);
use strict;
use warnings;

use Authen::WebAuthn;
use Authen::WebAuthn::Metadata;

# Downloads FIDO's metadata BLOB, with the CRLs of its chain, and registers
# the real-device fixtures (t/24-Real-devices.t) with the roots it lists
# instead of t/real-devices/roots.
#
# Retrieving the BLOB accepts FIDO's metadata terms
# (https://fidoalliance.org/metadata/metadata-legal-terms/), so it runs only
# when asked:
#
#   MDS_FETCH=1 prove -l xt/mds.t
#
# MDS_ROOT names the PEM file of the BLOB's root, GlobalSign Root R46 for
# FIDO's production BLOB; MDS_URL another BLOB.

plan skip_all => "set MDS_FETCH=1 to download FIDO's metadata BLOB"
  unless $ENV{MDS_FETCH};
plan skip_all => "set MDS_ROOT to the BLOB's root certificate (PEM)"
  unless $ENV{MDS_ROOT};

sub slurp {
    my ($path) = @_;
    open my $fh, "<", $path or die "$path: $!";
    local $/;
    return <$fh>;
}

my $md = Authen::WebAuthn::Metadata->fetch(
    root => slurp( $ENV{MDS_ROOT} ),
    ( $ENV{MDS_URL} ? ( url => $ENV{MDS_URL} ) : () ),
);
ok( $md->crl_checked, "BLOB " . $md->no . " verified, with CRLs" );
diag( "next update " . $md->next_update );

my $fixtures = decode_json( slurp("t/real-devices/fixtures.json") );
my ( %listed, %unlisted );
for my $f (@$fixtures) {
    next
      unless $f->{ceremony} eq "registration"
      and $f->{expect} eq "accepted"
      and ( $f->{attestation_type} // "" ) =~ /^(?:Basic|AttCA|AnonCA)$/;

    my $rp = Authen::WebAuthn->new(
        rp_id  => $f->{rp_id},
        origin => $f->{origins},
    );
    local $Authen::WebAuthn::SSLeayChainVerifier::verification_time =
      $f->{time}
      ? timegm( 0, 0, 0, $f->{time}[2], $f->{time}[1] - 1, $f->{time}[0] )
      : undef;

    # Statuses are reported, not refused: the chain is what is tested
    my $result = eval {
        $rp->validate_registration(
            map( { $_ => $f->{$_} }
                qw(challenge_b64 client_data_json_b64 attestation_object_b64) ),
            requested_uv         => "discouraged",
            metadata             => $md,
            refused_statuses     => [],
            allow_stale_metadata => 1,
        );
    };
    my $name = "$f->{from}: $f->{name}";
    if ( $result && $result->{metadata} ) {
        pass("$name chains to the roots of $result->{metadata}{description}");
        diag("... whose status is $result->{metadata}{status}")
          if ( $result->{metadata}{status} // "" ) !~ /^FIDO_CERTIFIED/;
        $listed{$name} = 1;
    }
    elsif ( $@ =~ /Could not validate attestation trust/
        and !$md->entry( aaguid => _aaguid($f) ) )
    {
        $unlisted{$name} = 1;
    }
    else {
        fail("$name: $@");
    }
}
diag( scalar( keys %listed ) . " fixtures listed in the BLOB, "
      . scalar( keys %unlisted ) . " not listed:" );
diag("  $_") for sort keys %unlisted;

# The AAGUID from the authenticator data inside the attestation object
sub _aaguid {
    my ($f) = @_;
    my $object = Authen::WebAuthn::_decode_cbor(
        MIME::Base64::decode_base64url( $f->{attestation_object_b64} ) );
    return Authen::WebAuthn::getAuthData( $object->{authData} )
      ->{attestedCredentialData}{aaguid};
}

done_testing();
