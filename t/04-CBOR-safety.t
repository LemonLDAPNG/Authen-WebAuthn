use Test::More;
use MIME::Base64 qw(encode_base64url decode_base64url);
use CBOR::XS;
use strict;
use warnings;

use Authen::WebAuthn;

# Without new_safe, CBOR::XS decodes tag 26 by calling THAW on whichever
# loaded class the input names. Client-supplied CBOR must not do that.

my $thaw_called = 0;

package My::Thawed;
sub THAW { $thaw_called++; return bless {}, shift }

package main;

# A Perl object (tag 26) of class My::Thawed
my $object = "\xd8\x1a\x82" . "\x6aMy::Thawed" . "\x00";

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

ok( $webauthn->validate_registration(%response), "Unmodified response" );

subtest "Perl object in the attestation object" => sub {

    # The malformed attestation object makes the module warn
    local $SIG{__WARN__} = sub { };
    eval {
        $webauthn->validate_registration( %response,
            attestation_object_b64 =>
              encode_base64url( "\xa1\x63fmt" . $object ) );
    };
    ok( $@, "Refused" );
    is( $thaw_called, 0, "THAW was not called" );
};

subtest "Perl object in the authenticator extensions" => sub {
    my $attestation_object =
      decode_cbor( decode_base64url( $response{attestation_object_b64} ) );

    # Set the ED flag and append the extensions
    my $auth_data = $attestation_object->{authData};
    substr( $auth_data, 32, 1 ) =
      chr( ord( substr( $auth_data, 32, 1 ) ) | 0x80 );
    $attestation_object->{authData} = $auth_data . "\xa1\x01" . $object;

    # Extensions are not checked: the tag is left as an inert
    # CBOR::XS::Tagged value
    eval {
        $webauthn->validate_registration( %response,
            attestation_object_b64 =>
              encode_base64url( encode_cbor($attestation_object) ) );
    };
    is( $thaw_called, 0, "THAW was not called" );
};

done_testing();
