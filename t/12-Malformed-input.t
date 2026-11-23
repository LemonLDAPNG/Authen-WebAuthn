use Test::More;
use MIME::Base64 qw(encode_base64url);
use CBOR::XS;
use JSON;
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

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

sub register {
    my ( $options, $override ) = @_;

    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } }, $override );

    return eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
            %{ $options || {} },
        );
    };
}

sub authenticate {
    my ( $override, %options ) = @_;

    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => "def" } }, $override );

    return eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 =>
              encode_base64url( $authenticator->encode_cosekey ),
            stored_sign_count    => 0,
            client_data_json_b64 =>
              encode_base64url( $assertion->{response}->{clientDataJSON} ),
            authenticator_data_b64 =>
              encode_base64url( $assertion->{response}->{authenticatorData} ),
            signature_b64 =>
              encode_base64url( $assertion->{response}->{signature} ),
            %options,
        );
    };
}

# Errors a caller should never see: Perl's own, from data of the wrong shape
my $RAW_PERL_ERROR = qr/
    \b(?:HASH|ARRAY|CODE|SCALAR)\ ref\b
  | \bNot\ an?\ \w+\ reference\b
  | \bCan't\ (?:use|call|locate)\b
  | \buninitialized\b
/x;

my @warnings;
$SIG{__WARN__} = sub { push @warnings, @_ };

my $registration = $authenticator->get_credential_response(
    { request => { challenge => "abc" } } )->{response};
my $assertion = $authenticator->get_assertion_response(
    { request => { challenge => "def" } } );

sub register_raw {
    my (%parts) = @_;
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 => encode_base64url(
                $parts{client_data} // $registration->{clientDataJSON}
            ),
            attestation_object_b64 => encode_base64url(
                $parts{attestation_object} // $registration->{attestationObject}
            ),
        );
    };
}

sub authenticate_raw {
    my (%parts) = @_;
    return scalar eval {
        $rp->validate_assertion(
            challenge_b64         => "def",
            credential_pubkey_b64 =>
              encode_base64url( $authenticator->encode_cosekey ),
            stored_sign_count    => 0,
            client_data_json_b64 => encode_base64url(
                $parts{client_data} // $assertion->{response}->{clientDataJSON}
            ),
            authenticator_data_b64 => encode_base64url(
                $parts{authenticator_data}
                  // $assertion->{response}->{authenticatorData}
            ),
            signature_b64 =>
              encode_base64url( $assertion->{response}->{signature} ),
        );
    };
}

sub refused {
    my ( $result, $error, $message, $name ) = @_;
    ok( !$result, $name );
    like( $error, $message, "... with the expected message" );
}

subtest "Values of the wrong type" => sub {
    my $map   = sub { CBOR::XS->new->text_keys(1)->encode(shift) };
    my $valid = CBOR::XS::decode_cbor( $registration->{attestationObject} );

    refused(
        register_raw( attestation_object => $map->( [ 1, 2 ] ) ),
        $@,
        qr/Attestation object is not a map/,
        "Attestation object"
    );
    refused(
        register_raw(
            attestation_object => $map->( { %$valid, attStmt => "x" } )
        ),
        $@,
        qr/Attestation statement is not a map/,
        "Attestation statement"
    );
    refused(
        register_raw(
            attestation_object => $map->( { %$valid, authData => [] } )
        ),
        $@,
        qr/Authenticator data is not a byte string/,
        "Authenticator data"
    );
    refused(
        register_raw(
            attestation_object => $map->( { %$valid, fmt => undef } )
        ),
        $@,
        qr/Attestation statement format is missing/,
        "Attestation statement format"
    );
    refused(
        authenticate_raw( client_data => "[]" ),
        $@, qr/Client data is not a JSON object/,
        "Client data"
    );
    refused(
        authenticate_raw(
            client_data => encode_json( { type => ["webauthn.get"] } )
        ),
        $@,
        qr/Client data member type is not a string/,
        "Client data member"
    );
    my $text_auth_data = $valid->{authData};
    utf8::upgrade($text_auth_data);    # CBOR::XS encodes it as text
    refused(
        register_raw(
            attestation_object =>
              $map->( { %$valid, authData => $text_auth_data } )
        ),
        $@,
        qr/Authenticator data is not a byte string/,
        "Authenticator data that is a text string"
    );
    my $bytes_fmt = $valid->{fmt};
    utf8::downgrade($bytes_fmt);
    refused(
        register_raw(
            attestation_object => $map->( { %$valid, fmt => $bytes_fmt } )
        ),
        $@,
        qr/Attestation statement format is not a text string/,
        "An attestation statement format that is a byte string"
    );
    refused(
        register_raw( attestation_object => pack( "H*", "bfeb" ) ),
        $@,
        qr/Indefinite-length or reserved CBOR item/,
        "Malformed map"
    );

    # The credential ID length, after the 37 byte header and 16 byte AAGUID,
    # claims more bytes than there are
    my $auth_data = $valid->{authData};
    substr( $auth_data, 53, 2 ) = pack( "n", 1000 );
    refused(
        register_raw(
            attestation_object => $map->( { %$valid, authData => $auth_data } )
        ),
        $@,
        qr/Attested credential data is truncated/,
        "A credential ID longer than the data"
    );
};

# Random corruption of real responses, with a fixed seed
subtest "Corrupted responses" => sub {
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

    my ( @raw_errors, $altered_accepted );
    for ( 1 .. 500 ) {
        register_raw(
            attestation_object => corrupt( $registration->{attestationObject} )
        );
        push @raw_errors, $@ if $@ =~ $RAW_PERL_ERROR;

        my $data   = corrupt( $assertion->{response}->{authenticatorData} );
        my $result = authenticate_raw( authenticator_data => $data );
        push @raw_errors, $@ if $@ =~ $RAW_PERL_ERROR;
        $altered_accepted++
          if $result
          and $data ne $assertion->{response}->{authenticatorData};
    }

    is_deeply( \@raw_errors, [], "Every refusal has its own message" );
    ok( !$altered_accepted, "No altered authenticator data is accepted" );
};

is_deeply( \@warnings, [], "No warnings" );

done_testing();
