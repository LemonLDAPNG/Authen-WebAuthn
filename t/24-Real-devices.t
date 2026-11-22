use Test::More;
use JSON        qw(decode_json);
use Time::Local qw(timegm);
use strict;

use Authen::WebAuthn;

# Responses from real authenticators, as two other libraries test with
# them; t/real-devices/README says where each comes from

my $fixtures = do {
    open my $fh, "<", "t/real-devices/fixtures.json"
      or die "fixtures.json: $!";
    local $/;
    decode_json(<$fh>);
};

my %root;
for my $path ( glob "t/real-devices/roots/*.pem" ) {
    my ($name) = $path =~ m{([^/]+)\.pem$};
    open my $fh, "<", $path or die "$path: $!";
    local $/;
    $root{$name} = <$fh>;
}

my %credential_pubkey;

for my $f (@$fixtures) {
    my $rp = Authen::WebAuthn->new(
        rp_id  => $f->{rp_id},
        origin => $f->{origins},
    );
    local $Authen::WebAuthn::SSLeayChainVerifier::verification_time =
      $f->{time}
      ? timegm( 0, 0, 0, $f->{time}[2], $f->{time}[1] - 1, $f->{time}[0] )
      : undef;

    my $result;
    if ( $f->{ceremony} eq "registration" ) {
        $result = eval {
            $rp->validate_registration(
                map( { $_ => $f->{$_} }
                    qw(challenge_b64 client_data_json_b64 attestation_object_b64)
                ),
                requested_uv  => "discouraged",
                trust_anchors => [
                    map { $root{$_} // die "No root named $_" }
                      @{ $f->{trust_anchors} || [ sort keys %root ] }
                ],
                allow_untrusted_attestation => $f->{allow_untrusted_attestation}
                  // 0,
            );
        };
        $credential_pubkey{ $f->{name} } = $result->{credential_pubkey}
          if $result;
    }
    else {
        $result = eval {
            $rp->validate_assertion(
                map( { $_ => $f->{$_} }
                    qw(challenge_b64 client_data_json_b64 authenticator_data_b64
                      signature_b64 credential_id_b64) ),
                credential_pubkey_b64 => $f->{credential_pubkey_b64}
                  // $credential_pubkey{ $f->{registration} },
                stored_sign_count => $f->{stored_sign_count},
                requested_uv      => $f->{requested_uv} // "discouraged",
            );
        };
    }

    my $name = "$f->{from}: $f->{name}";
    if ( $f->{expect} eq "accepted" ) {
        ok( $result, "$name is accepted" ) or diag($@);
        if ( defined $f->{attestation_type} ) {
            is(
                $result->{attestation_result}->{type},
                $f->{attestation_type},
                "... as $f->{attestation_type}"
            );
        }
        if ( defined $f->{signature_count} ) {
            is( $result->{signature_count},
                $f->{signature_count}, "... with its signature count" );
        }
    }
    else {
        ok( !$result, "$name is refused" );
        like( $@, qr/^\Q$f->{error}\E/, "... with the expected message" );
    }
}

done_testing();
