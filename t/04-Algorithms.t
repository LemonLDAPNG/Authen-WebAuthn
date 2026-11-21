use Test::More;
use Crypt::PK::ECC;
use Crypt::PK::Ed25519;
use Crypt::PK::RSA;
use strict;

use Authen::WebAuthn;

# Just enough CBOR to write a COSE_Key by hand
sub cbor_int {
    my ($n) = @_;
    my ( $major, $value ) = $n < 0 ? ( 0x20, -1 - $n ) : ( 0x00, $n );
    return pack( "C",  $major + $value ) if $value < 24;
    return pack( "CC", $major + 24, $value ) if $value < 256;
    return pack( "Cn", $major + 25, $value );
}

sub cbor_bstr {
    my ($bytes) = @_;
    my $length = length($bytes);
    return pack( "C",  0x40 + $length ) . $bytes if $length < 24;
    return pack( "CC", 0x58, $length ) . $bytes if $length < 256;
    return pack( "Cn", 0x59, $length ) . $bytes;
}

sub cose_key {
    my (@pairs) = @_;
    my $cose = pack( "C", 0xa0 + @pairs / 2 );
    while ( my ( $label, $value ) = splice( @pairs, 0, 2 ) ) {
        $cose .= cbor_int($label) . $value;
    }
    return $cose;
}

sub rsa_cose_key {
    my ( $key, $alg ) = @_;
    my $hash = $key->key2hash;
    return cose_key(
        1  => cbor_int(3),      # kty RSA
        3  => cbor_int($alg),
        -1 => cbor_bstr( pack( "H*", $hash->{N} ) ),
        -2 => cbor_bstr( pack( "H*", $hash->{e} ) ),
    );
}

sub ecc_cose_key {
    my ( $key, $alg, $curve, $size ) = @_;
    my $hash = $key->key2hash;
    return cose_key(
        1  => cbor_int(2),        # kty EC2
        3  => cbor_int($alg),
        -1 => cbor_int($curve),
        -2 => cbor_bstr(
            pack( "H*", sprintf( "%0*s", $size * 2, $hash->{pub_x} ) )
        ),
        -3 => cbor_bstr(
            pack( "H*", sprintf( "%0*s", $size * 2, $hash->{pub_y} ) )
        ),
    );
}

my $message = "authenticator data and client data hash";

my $rsa = Crypt::PK::RSA->new;
$rsa->generate_key( 256, 65537 );

subtest "RS256" => sub {
    my $verifier =
      Authen::WebAuthn::getPubKeyVerifier( rsa_cose_key( $rsa, -257 ) );

    ok(
        $verifier->(
            $rsa->sign_message( $message, "SHA256", "v1.5" ), $message
        ),
        "PKCS#1 v1.5 signature is valid"
    );
    ok(
        !$verifier->(
            $rsa->sign_message( "other", "SHA256", "v1.5" ), $message
        ),
        "Signature of another message is not"
    );
};

# RFC 8230, section 2: the salt is as long as the hash output
subtest "PS256" => sub {
    my $verifier =
      Authen::WebAuthn::getPubKeyVerifier( rsa_cose_key( $rsa, -37 ) );

    ok(
        $verifier->(
            $rsa->sign_message( $message, "SHA256", "pss", 32 ), $message
        ),
        "PSS signature with a 32 byte salt is valid"
    );
    ok(
        !$verifier->(
            $rsa->sign_message( $message, "SHA256", "pss", 12 ), $message
        ),
        "PSS signature with another salt length is not"
    );
    ok(
        !$verifier->(
            $rsa->sign_message( "other", "SHA256", "pss", 32 ), $message
        ),
        "Signature of another message is not"
    );
};

my @ecdsa = (
    [ "ES256", -7,  1, "secp256r1", 32, "SHA256" ],
    [ "ES384", -35, 2, "secp384r1", 48, "SHA384" ],
    [ "ES512", -36, 3, "secp521r1", 66, "SHA512" ],
);

for my $case (@ecdsa) {
    my ( $name, $alg, $curve, $curve_name, $size, $hash ) = @$case;

    subtest $name => sub {
        my $key = Crypt::PK::ECC->new;
        $key->generate_key($curve_name);

        my $verifier = Authen::WebAuthn::getPubKeyVerifier(
            ecc_cose_key( $key, $alg, $curve, $size ) );

        ok( $verifier->( $key->sign_message( $message, $hash ), $message ),
            "Signature is valid" );
        ok( !$verifier->( $key->sign_message( "other", $hash ), $message ),
            "Signature of another message is not" );
    };
}

subtest "An algorithm is tied to its curve" => sub {
    my $key = Crypt::PK::ECC->new;
    $key->generate_key("secp384r1");

    eval {
        Authen::WebAuthn::getPubKeyVerifier( ecc_cose_key( $key, -7, 2, 48 ) );
    };
    like(
        $@,
        qr/Curve 2 cannot be used with algorithm -7/,
        "ES256 with a P-384 key is refused"
    );
};

subtest "EdDSA" => sub {
    my $key = Crypt::PK::Ed25519->new;
    $key->generate_key;

    my $cose = cose_key(
        1  => cbor_int( 1),                                  # kty OKP
        3  => cbor_int(-8),
        -1 => cbor_int( 6),                                  # Ed25519
        -2 => cbor_bstr( $key->export_key_raw("public") ),
    );
    my $verifier = Authen::WebAuthn::getPubKeyVerifier($cose);

    ok( $verifier->( $key->sign_message($message), $message ),
        "Signature is valid" );
    ok( !$verifier->( $key->sign_message("other"), $message ),
        "Signature of another message is not" );

    my $other_curve = cose_key(
        1  => cbor_int( 1),
        3  => cbor_int(-8),
        -1 => cbor_int( 7),                                  # Ed448
        -2 => cbor_bstr( $key->export_key_raw("public") ),
    );
    eval { Authen::WebAuthn::getPubKeyVerifier($other_curve) };
    like(
        $@,
        qr/Curve 7 cannot be used with algorithm -8/,
        "Another curve is refused"
    );
};

done_testing();
