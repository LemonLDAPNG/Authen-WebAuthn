use Test::More;
use MIME::Base64 qw(encode_base64url);
use CBOR::XS;
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

# A value tagged as a Perl object (CBOR tag 26) asks the decoder to call
# THAW on the class it names. Nothing sent by a client may get that far,
# nor any other tag.
my $thawed = 0;
{

    package Local::Thawed;
    sub THAW { $thawed++; return bless {}, shift }
}
my $tagged = CBOR::XS::tag( 26, [ "Local::Thawed", "x" ] );

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $ecdsa_key = <<ENDKEY;
-----BEGIN EC PRIVATE KEY-----
MIIBUQIBAQQgWEGujn2kkOVckTIKhIJDSqH99bxydPGloXvbeaq9swiggeMwgeAC
AQEwLAYHKoZIzj0BAQIhAP////8AAAABAAAAAAAAAAAAAAAA////////////////
MEQEIP////8AAAABAAAAAAAAAAAAAAAA///////////////8BCBaxjXYqjqT57Pr
vVV2mIa8ZR0GsMxTsPY7zjw+J9JgSwRBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLesz
oPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////
AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAaFEA0IABM/oQXEUzjPwEhM4
gWmIbCuOXc4Ja8jPDKxbQaZckal7/9a693/nkf7flk1S9AV2tjrtJPF6kg8TCGbF
KoeD9Wc=
-----END EC PRIVATE KEY-----
ENDKEY

my $authenticator = Authen::WebAuthn::Test->new(
    origin        => "http://auth.example.com",
    rp_id         => "auth.example.com",
    credential_id => "lZYltP9MtoRNuXK8f8tWf",
    aaguid        => "00000000-0000-0000-0000-000000000000",
    key           => $ecdsa_key,
);

is( ref( CBOR::XS::decode_cbor( CBOR::XS::encode_cbor($tagged) ) ),
    "Local::Thawed", "A plain decoder does call THAW" );
$thawed = 0;

subtest "Attestation statement" => sub {
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );

    my $object =
      CBOR::XS::decode_cbor( $credential->{response}->{attestationObject} );
    $object->{attStmt} = { x => $tagged };
    my $attestation_object = CBOR::XS->new->text_keys(1)->encode($object);

    eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 => encode_base64url($attestation_object),
        );
    };
    is( $thawed, 0, "THAW was not called" );
};

subtest "Extensions in a registration" => sub {
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } },
        {
            response => {
                attestationObject => {
                    authData => {
                        flags      => { edIncluded => 1 },
                        extensions => $tagged,
                    }
                }
            }
        }
    );

    eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
        );
    };
    is( $thawed, 0, "THAW was not called" );
};

# Authenticator data is decoded before the signature is checked
subtest "Extensions in an assertion" => sub {
    my $registration = $rp->validate_registration(
        challenge_b64 => "abc",
        do {
            my $credential = $authenticator->get_credential_response(
                { request => { challenge => "abc" } } );
            (
                client_data_json_b64 =>
                  encode_base64url( $credential->{response}->{clientDataJSON} ),
                attestation_object_b64 => encode_base64url(
                    $credential->{response}->{attestationObject}
                ),
            );
        },
    );

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } },
        {
            response => {
                authenticatorData => {
                    flags      => { edIncluded => 1 },
                    extensions => $tagged,
                }
            }
        }
    );

    eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 => $registration->{credential_pubkey},
            stored_sign_count     => 0,
            client_data_json_b64  =>
              encode_base64url( $assertion->{response}->{clientDataJSON} ),
            authenticator_data_b64 =>
              encode_base64url( $assertion->{response}->{authenticatorData} ),
            signature_b64 =>
              encode_base64url( $assertion->{response}->{signature} ),
        );
    };
    is( $thawed, 0, "THAW was not called" );

    # CBOR::XS expands string references whatever its options say, so a few
    # bytes can become gigabytes: here 3 bytes each, for 1,000 copies of 1 KB
    my $references = CBOR::XS::tag( 256,
        [ "x" x 1000, map { CBOR::XS::tag( 25, 0 ) } 1 .. 1000 ] );
    $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } },
        {
            response => {
                authenticatorData => {
                    flags      => { edIncluded => 1 },
                    extensions => $references,
                }
            }
        }
    );
    ok(
        !eval {
            $rp->validate_assertion(
                challenge_b64         => "def",
                credential_pubkey_b64 => $registration->{credential_pubkey},
                stored_sign_count     => 0,
                client_data_json_b64  =>
                  encode_base64url( $assertion->{response}->{clientDataJSON} ),
                authenticator_data_b64 => encode_base64url(
                    $assertion->{response}->{authenticatorData}
                ),
                signature_b64 =>
                  encode_base64url( $assertion->{response}->{signature} ),
            );
        },
        "String references are refused"
    );
    like( $@, qr/Unexpected CBOR tag 256/, "... as a tag" );
};

subtest "Decoder" => sub {
    my $decode = sub { Authen::WebAuthn::_decode_cbor( pack "H*", shift ) };

    is_deeply(
        $decode->("a3010220036166426279"),
        { 1 => 2, -1 => 3, f => "by" },
        "Integer and text keys, a byte string"
    );
    is_deeply(
        $decode->("83f4f5f6"),
        [ Types::Serialiser::false, Types::Serialiser::true, undef ],
        "false, true and null"
    );
    is( $decode->("1b001fffffffffffff"),
        "9007199254740991", "A 64-bit integer" );
    my $text = $decode->("6141");
    ok( utf8::is_utf8($text), "A text string is marked as text" );
    is( $decode->("62c3a9"), "\x{e9}", "... and decoded from UTF-8" );

    my @refused = (
        [ "d9d9f7a0",   qr/Unexpected CBOR tag 55799/, "Self-describe tag" ],
        [ "d95652a0",   qr/Unexpected CBOR tag 22098/, "Indirection tag" ],
        [ "f93c00",     qr/simple value or float/,     "A float" ],
        [ "f7",         qr/simple value or float/,     "undefined" ],
        [ "bf01ff",     qr/Indefinite-length/,         "An indefinite map" ],
        [ "5f4100ff",   qr/Indefinite-length/, "An indefinite byte string" ],
        [ "a201020103", qr/Duplicate CBOR map key 1/, "A duplicate key" ],
        [ "a1613301",   qr/Unsupported CBOR map key/, "A text key \"3\"" ],
        [ "a1413301",   qr/Unsupported CBOR map key/, "A byte string key" ],
        [ "a1f501",     qr/Unsupported CBOR map key/, "A boolean key" ],
        [ "a1800101",   qr/Unsupported CBOR map key/, "An array key" ],
        [ "61ff",       qr/not valid UTF-8/,          "Invalid UTF-8" ],
        [
            "1b0020000000000000",
            qr/integer is too large/,
            "An integer of 2**53"
        ],
        [ "0100",         qr/Trailing bytes/, "Trailing bytes" ],
        [ "43aabb",       qr/truncated/,      "A short byte string" ],
        [ "9a7fffffff00", qr/truncated/,      "An array longer than the data" ],
        [ "19",           qr/truncated/,      "A short argument" ],
        [ "81" x 17 . "00", qr/nested too deeply/, "Deep nesting" ],
    );

    for my $case (@refused) {
        my ( $hex, $message, $name ) = @$case;
        ok( !eval { $decode->($hex); 1 }, $name );
        like( $@, $message, "... with the expected message" );
    }
    ok( eval { $decode->( "81" x 16 . "00" ); 1 }, "Nesting at the limit" );
};

# COSE labels and the values compared as strings must be CBOR integers
subtest "COSE key types" => sub {
    my $x   = "\x01" x 32;
    my $key = sub {
        my (%changed) = @_;
        my %cose = ( 1 => "\x02", 3 => "\x26", -1 => "\x01" );
        $cose{$_} = $changed{$_} for keys %changed;
        my @labels = ( 1, 3, -1 );
        return pack( "C", 0xa5 )
          . join( "",
            map { Authen::WebAuthn::Test::_cbor_int($_) . $cose{$_} } @labels )
          . "\x21"
          . "\x58\x20"
          . $x . "\x22"
          . "\x58\x20"
          . $x;
    };
    ok( eval { Authen::WebAuthn::_decode_cose_key( $key->() ); 1 },
        "Integer kty, alg and crv" )
      or diag($@);
    for my $case (
        [  3, "\x62-7",   "alg as text" ],
        [  3, "\x42-7",   "alg as bytes" ],
        [  1, "\x412",    "kty as bytes" ],
        [ -1, "\x41\x31", "crv as bytes" ],
      )
    {
        my ( $label, $value, $name ) = @$case;
        ok(
            !eval {
                Authen::WebAuthn::_decode_cose_key(
                    $key->( $label => $value ) );
                1;
            },
            "Refused: $name"
        );
        like(
            $@,
            qr/member $label is not an integer/,
            "... with the expected message"
        );
    }
};

done_testing();
