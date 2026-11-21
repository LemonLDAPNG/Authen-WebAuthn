use Test::More;
use MIME::Base64 'encode_base64url';
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Test;

use lib ".";
require 't/certs.pl';
require 't/responses.pl';

# Simulate a unix date where the test certificates are still valid
$Authen::WebAuthn::SSLeayChainVerifier::verification_time = 1698765432;

my $webauthn = Authen::WebAuthn->new(
    origin => "http://localhost:5000",
    rp_id  => "localhost",
);
my $reg;

$reg = $webauthn->validate_registration(
    %main::u2f_attestation_response,
    trust_anchors => [$main::yubico_u2f_root],
);

is( $reg->{attestation_result}->{success}, 1, "Yubico U2F attestation" );

done_testing();
