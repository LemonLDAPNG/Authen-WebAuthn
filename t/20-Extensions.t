use Test::More;
use MIME::Base64 qw(encode_base64url);
use Digest::SHA  qw(sha256);
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

    return scalar eval {
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

    return scalar eval {
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

# Authenticator extension outputs, as an authenticator puts them in the
# authenticator data
sub registration_extensions {
    my (%outputs) = @_;
    return {
        response => {
            attestationObject => {
                authData =>
                  { flags => { edIncluded => 1 }, extensions => {%outputs} }
            }
        }
    };
}

sub assertion_extensions {
    my (%outputs) = @_;
    return {
        response => {
            authenticatorData =>
              { flags => { edIncluded => 1 }, extensions => {%outputs} }
        }
    };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Registration, client extension outputs" => sub {
    my $result = register();
    is_deeply( $result->{extension_results}, {}, "None by default" );
    ok( !exists $result->{discoverable}, "Nothing said about discoverability" );

    $result = register(
        { extension_results => { credProps => { rk => JSON::true } } } );
    is( $result->{discoverable}, 1, "credProps says discoverable" );
    is_deeply(
        $result->{extension_results},
        { credProps => { rk => JSON::true } },
        "... and is returned"
    );
    is(
        register(
            { extension_results => { credProps => { rk => JSON::false } } }
        )->{discoverable},
        0,
        "credProps says not discoverable"
    );

    $result = register(
        {
            requested_extensions => { credProps => JSON::true },
            extension_results    => {
                credProps => { rk      => JSON::true },
                prf       => { enabled => JSON::true },
            },
        }
    );
    is_deeply( [ keys %{ $result->{extension_results} } ],
        ["credProps"], "An output that was not requested is ignored" );
    refused(
        register(
            {
                requested_extensions => { credProps => JSON::true },
                extension_results    => { prf       => { enabled => 1 } },
                allow_unsolicited_extensions => 0,
            }
        ),
        qr/Client extension output prf was not requested/,
        "... or refused, if the caller says so"
    );

    refused(
        register( { extension_results => { credProps => { rk => "yes" } } } ),
        qr/Client extension output credProps.rk is not a valid boolean/,
        "A credProps.rk that is not a boolean"
    );
    refused(
        register(
            {
                extension_results =>
                  { prf => { results => { first => "not base64url!" } } }
            }
        ),
        qr/Client extension output prf.results.first is not a valid base64url/,
        "PRF results that are not base64url"
    );
    refused(
        register( { extension_results => { credProps => "x" } } ),
        qr/Client extension output credProps is not a map/,
        "An output that is not a map"
    );
    refused(
        register( { extension_results => ["credProps"] } ),
        qr/Client extension results is not a map/,
        "Client extension results that are not a map"
    );
    refused(
        register( { requested_extensions => ["credProps"] } ),
        qr/requested_extensions is not a map/,
        "Requested extensions that are not a map"
    );

    ok(
        register( { extension_results => { exampleExtension => [ 1, 2 ] } } ),
        "An extension this module does not know is passed through"
    );
};

subtest "Registration, authenticator extension outputs" => sub {
    my $result = register(
        undef,
        registration_extensions(
            credProtect   => 2,
            "hmac-secret" => Types::Serialiser::true,
            minPinLength  => 4,
        )
    );
    ok( $result, "credProtect, hmac-secret and minPinLength" ) or diag($@);
    is( $result && $result->{authenticator_extensions}->{credProtect},
        2, "... are returned" );

    refused(
        register( undef, registration_extensions( credProtect => 5 ) ),
qr/Authenticator extension output credProtect is not a valid credProtect/,
        "A credProtect policy that does not exist"
    );
    refused(
        register( undef, registration_extensions( minPinLength => "four" ) ),
        qr/Authenticator extension output minPinLength is not a valid count/,
        "A minPinLength that is not a number"
    );

    $result = register(
        { requested_extensions => { credentialProtectionPolicy => "x" } },
        registration_extensions( credProtect => 3, minPinLength => 4 )
    );
    is_deeply(
        $result->{authenticator_extensions},
        { credProtect => 3 },
        "The authenticator extension a client extension asks for is kept, "
          . "an unsolicited one dropped"
    );
    refused(
        register(
            {
                requested_extensions => { credentialProtectionPolicy => "x" },
                allow_unsolicited_extensions => 0,
            },
            registration_extensions( minPinLength => 4 )
        ),
        qr/Authenticator extension output minPinLength was not requested/,
        "... or refused, if the caller says so"
    );
};

subtest "Authentication" => sub {
    my $result = authenticate(
        assertion_extensions( "hmac-secret" => "\x01" x 32 ),
        extension_results => {
            prf       => { results => { first => "AQID" } },
            largeBlob => { blob    => "AQID", written => JSON::false },
        },
    );
    ok( $result, "prf, largeBlob and hmac-secret" ) or diag($@);
    is_deeply(
        $result && $result->{extension_results}->{prf},
        { results => { first => "AQID" } },
        "... are returned"
    );

    refused(
        authenticate(
            undef, extension_results => { largeBlob => { written => "yes" } }
        ),
        qr/Client extension output largeBlob.written is not a valid boolean/,
        "A largeBlob.written that is not a boolean"
    );
    refused(
        authenticate( assertion_extensions( "hmac-secret" => [] ) ),
        qr/Authenticator extension output hmac-secret is not a valid bytes/,
        "An hmac-secret that is not bytes"
    );
};

subtest "AppID extension" => sub {
    my $appid = "https://auth.example.com/u2f-facets.json";
    my $u2f =
      { response => { authenticatorData => { rpIdHash => sha256($appid) } } };

    ok(
        authenticate(
            $u2f,
            requested_extensions => { appid => $appid },
            extension_results    => { appid => JSON::true },
        ),
        "The AppID is taken from the requested extensions"
    ) or diag($@);

    ok(
        authenticate(
            undef,
            requested_extensions => { credProps => JSON::true },
            extension_results    => { appid     => JSON::true },
        ),
        "An appid output that was not requested is ignored"
    ) or diag($@);
    refused(
        authenticate(
            $u2f,
            requested_extensions => { credProps => JSON::true },
            extension_results    => { appid     => JSON::true },
        ),
        qr/RP ID hash/,
        "... so the RP ID is expected, not the AppID"
    );
};

done_testing();
