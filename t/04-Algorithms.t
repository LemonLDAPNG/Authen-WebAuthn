use Test::More;
use Crypt::PK::RSA;
use strict;

use Authen::WebAuthn;

# COSE_Key for an RSA public key (RFC 8230): kty RSA (3), alg, n, e
sub rsa_cose_key {
    my ( $key, $alg ) = @_;

    my $hash = $key->key2hash;
    my $n    = pack( "H*", $hash->{N} );
    my $e    = pack( "H*", $hash->{e} );

    my $cose_alg = {
        -257 => "\x39\x01\x00",
        -37  => "\x38\x24",
    }->{$alg};

    return "\xa4" .                                       # Map of 4 items
      "\x01\x03" .                                        # kty => RSA
      "\x03" . $cose_alg .                                # alg
      "\x20" . "\x59" . pack( "n", length($n) ) . $n .    # n as a bstr
      "\x21" . pack( "C", 0x40 + length($e) ) . $e        # e as a bstr
      ;
}

my $key = Crypt::PK::RSA->new;
$key->generate_key( 256, 65537 );
my $message = "authenticator data and client data hash";

subtest "RS256" => sub {
    my $verifier =
      Authen::WebAuthn::getPubKeyVerifier( rsa_cose_key( $key, -257 ) );

    ok(
        $verifier->(
            $key->sign_message( $message, "SHA256", "v1.5" ), $message
        ),
        "PKCS#1 v1.5 signature is valid"
    );
    ok( !$verifier->( $key->sign_message( "other", "SHA256", "v1.5" ), $message ),
        "Signature of another message is not" );
};

# RFC 8230, section 2: the salt is as long as the hash output
subtest "PS256" => sub {
    my $verifier =
      Authen::WebAuthn::getPubKeyVerifier( rsa_cose_key( $key, -37 ) );

    ok(
        $verifier->(
            $key->sign_message( $message, "SHA256", "pss", 32 ), $message
        ),
        "PSS signature with a 32 byte salt is valid"
    );
    ok(
        !$verifier->(
            $key->sign_message( $message, "SHA256", "pss", 12 ), $message
        ),
        "PSS signature with another salt length is not"
    );
    ok(
        !$verifier->(
            $key->sign_message( "other", "SHA256", "pss", 32 ), $message
        ),
        "Signature of another message is not"
    );
};

done_testing();
