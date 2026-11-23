use Test::More;
use MIME::Base64 qw(encode_base64 encode_base64url decode_base64url);
use CBOR::XS;
use strict;
use warnings;

use Authen::WebAuthn;

# CryptX takes time quadratic in the size of an RSA key to import it, so
# oversized keys must be refused before they are decoded.

my $big_e = "\x01" . ( "\x00" x 499_998 ) . "\x01";    # 500 KB exponent

# COSE RS256 key, with integer map keys as COSE requires
sub cose_rsa {
    my ( $n, $e ) = @_;
    my $bstr = sub {
        my $l = length $_[0];
        return (
              $l < 24    ? chr( 0x40 + $l )
            : $l < 256   ? "\x58" . chr($l)
            : $l < 65536 ? "\x59" . pack( 'n', $l )
            :              "\x5a" . pack( 'N', $l )
        ) . $_[0];
    };
    return
        "\xa4\x01\x03\x03\x39\x01\x00" . "\x20"
      . $bstr->($n) . "\x21"
      . $bstr->($e);
}

sub der_len {
    my ($l) = @_;
    return chr($l) if $l < 128;
    my $b = "";
    while ($l) { $b = chr( $l & 255 ) . $b; $l >>= 8 }
    return chr( 0x80 | length $b ) . $b;
}
sub der_uint { my ($v) = @_; return ord($v) & 0x80 ? "\x00$v" : $v }
sub tlv { my ( $t, $v ) = @_; return chr($t) . der_len( length $v ) . $v }

# PEM SubjectPublicKeyInfo of an RSA key
sub rsa_pem {
    my ( $n, $e ) = @_;
    my $rsa = tlv( 0x30, tlv( 2, der_uint($n) ) . tlv( 2, der_uint($e) ) );
    my $alg = tlv( 0x30,
        tlv( 6, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" ) . tlv( 5, "" ) );
    return
        "-----BEGIN PUBLIC KEY-----\n"
      . encode_base64( tlv( 0x30, $alg . tlv( 3, "\x00" . $rsa ) ) )
      . "-----END PUBLIC KEY-----\n";
}

subtest "COSE keys" => sub {
    my $verifier = \&Authen::WebAuthn::getPubKeyVerifier;

    my $largest = cose_rsa( "\xff" x 512, "\xff" x 32 );
    is( length($largest), 558, "4096 bits, 256-bit exponent: 558 bytes" );
    ok( $verifier->($largest), "Accepted" );

    eval { $verifier->( cose_rsa( "\xff" x 256, $big_e ) ) };
    like( $@, qr/Public key is too long/, "500 KB exponent" );

    eval { $verifier->( cose_rsa( "\xff" x 500_000, "\x01\x00\x01" ) ) };
    like( $@, qr/Public key is too long/, "500 KB modulus" );
};

subtest "PEM keys" => sub {
    my $verifier = \&Authen::WebAuthn::getPEMPubKeyVerifier;

    my $largest = rsa_pem( "\xff" x 512, "\xff" x 32 );
    cmp_ok(
        length($largest), '<=',
        $Authen::WebAuthn::MAX_PEM_KEY_LENGTH,
        "4096 bits, 256-bit exponent: under the limit"
    );
    ok( $verifier->( $largest, -257 ), "Accepted" );

    eval { $verifier->( rsa_pem( "\xff" x 256, $big_e ), -257 ) };
    like( $@, qr/Public key is too long/, "500 KB exponent" );
};

subtest "Packed self attestation with an oversized key" => sub {

    # Registration from t/02-Attestation-tests.t
    my $webauthn = Authen::WebAuthn->new(
        origin => "http://localhost:5000",
        rp_id  => "localhost",
    );
    my %response = (
        challenge_b64 =>
"TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw",
        requested_uv           => "required",
        attestation_object_b64 =>
"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
        client_data_json_b64 =>
"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
    );

    my $attestation_object =
      decode_cbor( decode_base64url( $response{attestation_object_b64} ) );

    # Replace the credential public key with an RS256 key whose exponent
    # is 500 KB, and claim packed self attestation
    my $auth_data      = $attestation_object->{authData};
    my $cred_id_length = unpack( 'n', substr( $auth_data, 53, 2 ) );
    $attestation_object->{authData} =
      substr( $auth_data, 0, 55 + $cred_id_length )
      . cose_rsa( "\xff" x 256, $big_e );
    $attestation_object->{fmt}     = "packed";
    $attestation_object->{attStmt} = { alg => -257, sig => "x" };

    eval {
        $webauthn->validate_registration( %response,
            attestation_object_b64 =>
              encode_base64url( encode_cbor($attestation_object) ) );
    };
    like( $@, qr/Public key is too long/, "Refused" );
};

done_testing();
