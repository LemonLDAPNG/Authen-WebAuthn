use Test::More;
use MIME::Base64 qw/decode_base64url decode_base64/;
use strict;

use Authen::WebAuthn::SSLeayChainVerifier;

# Simulate a unix date where the test certificates are still valid
$Authen::WebAuthn::SSLeayChainVerifier::verification_time = 1698765432;

use lib ".";
require 't/certs.pl';

my $cert = decode_base64(
    "MIICmjCCAYICAQEwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UEAwwMSW50ZXJtZWRp
YXRlMB4XDTE5MDQxNzE1MTY1M1oXDTI5MDQxNDE1MTY1M1owDzENMAsGA1UEAwwE
TGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOa0eYS3XsiXadYF
53ZTfaNhbbkpCWnFddFQ/c3Z7QToJ6DkTiqDNTpHodvrG+CFDVuO0RJONQDf4jH6
6B6ityFYWc4RkAPqfat0k7NZpj5dVWp9uDgmEWABmf0KE9WqzYDbtTljlS1POHI9
UFCdF3/T0UbGtdKSzzo/STJf8vLOTf5YJQZHImvZeQbCgXtBN8hdLtfdU5FQYbaK
cGyDvW6mBg1ZxYgJx+hE9NNeAsAWp2rAXGZIatQ98KNmwY5VH6cBX4ggasQucUUI
Bg5ih7fvWP2k0FyaiIsme9nWLsbuNg3s3tMahuRO1rE0Z0Vj/5JBUmT6J27ZBKGZ
Rn7C2x8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAgleJwB7rE7w+B4jlRqP72kkR
XL7MZSV2vr+CTS4t+iLlbHweApiEJmQ3szY69d/gtdznSacp8CHOGihRazRsudn2
G6QHbjXNBs16KnEEnHiIbk0YrnAa0xxrKvxOHPX+lfvYEcN2QqVtiFF0IsTqck8I
vMYYe5zf4RDd2S1q31l67LoFSmFhrAqPbDITrx8tMhyAEW6zNxNkCaM/+8Bu94E3
Ec7QDmpbE4Qz80qzmCmpv7NBnvrn0uYO1IkPrq2XetbhWHoliYImeS2OojdnPVbx
sP1q5i9FYnnvFA8xl4TORjqtIajX6bXVkWZBXkbtDGKLnxzJ+vPagxwEzOphmA==
"
);

my $chain = [
    decode_base64(
        "MIICIjCCAYugAwIBAgIDEjRWMA0GCSqGSIb3DQEBBQUAMCsxCzAJBgNVBAYTAlVT
MQ4wDAYDVQQKEwVEZW1vMTEMMAoGA1UEAxMDQ0ExMCAXDTEyMDEwMTAwMDAwMFoY
DzIxMTExMjMxMjM1OTU5WjArMQswCQYDVQQGEwJVUzEOMAwGA1UEChMFRGVtbzEx
DDAKBgNVBAMTA0NBMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAy1ygNguH
72n0l+1uy9HEM6t2LWJEmC0w4tAuXk9H1FseQMV28eBQXdyg3wK+yli6l6c9k9Aj
HAZ/6TXTVmOxtTgkXbvHlwcE3pTiHJSvZWGQMORCPNkjjiVBiLBdGQ3qFKyV+NA5
K4XnVy0jkeS/BHx7KO7m+DOLVow8FO1CstUCAwEAAaNSMFAwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUyBzakgqpSAg6dnYVOATxNNkV0CAwCwYDVR0PBAQDAgEG
MBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQUFAAOBgQBG1QBfo1kZRN50
/a3ZoQufIj0FJLMS/WkUnW0RLqEewyhEK9u86eoglcz5SxdD4T+VN9+MxoZ2J83P
b21Y4FUDqnkdoGAPdoxX+7iLQcxVoMK72n72QSSzvfnjsr9+pazLp1P6ZK9epbZf
s2WM0ty3a+sYmXANG8wGazAyRDMi0Q=="
    ),
    decode_base64(
        "MIICTzCCAbigAwIBAgIBAjANBgkqhkiG9w0BAQsFADArMQswCQYDVQQGEwJVUzEO
MAwGA1UEChMFRGVtbzExDDAKBgNVBAMTA0NBMTAeFw0xOTA0MTcxNTEzMjFaFw0y
OTA0MTQxNTEzMjFaMBcxFTATBgNVBAMMDEludGVybWVkaWF0ZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMjKRTFhhQvcFd8kkjjevKPjZRFmhd5zVWAB
tqrAEdhWwxpI3Jg1j49sbBWL2WKFhASPzYgPTE1CTQ6eH46ySmgLt8qzdPp8+kiC
RDU0h7j0YQS2jLIgMsF2J8Xt8RRjjgAw25Mv2ZgppdUR8xr6KpqIaUqsve0a8wCu
8ZFCaGMd0OcRGd7HaGSZ3Inafa8r3XtJ+HT+6iJLKyRfvwVv+9bYyyQKW8gVxMBs
51bSfELsgMzNi61HHLzp3LIE7LpWCsjiZiRIC32ZRLBzhg6Nia/TY3ooyYJJI1mH
gGAxO2QbYuRpKjitLvTxrGhGljAnbs+jbYoGz9PqLkHsmcV2YVMCAwEAAaMTMBEw
DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQC5/u770nJSh9Iev0OA
0tZ7lsVAJisJEHN34plK1oUD76mFh514ntLLDElfzMYJfXpL0WD87nisIeLpXysC
BC3QQgqfpbylZtFON5W5lxyjfVnQwFsvDC3UdK6rxCoFk/zvHeU5dahwGUHN7t7G
lJm4FfFveSZwMn7Pvgq1eKNJ4g=="
    )
];

my $rootca = <<EOF;
-----BEGIN CERTIFICATE-----
MIICIjCCAYugAwIBAgIDEjRWMA0GCSqGSIb3DQEBBQUAMCsxCzAJBgNVBAYTAlVT
MQ4wDAYDVQQKEwVEZW1vMTEMMAoGA1UEAxMDQ0ExMCAXDTEyMDEwMTAwMDAwMFoY
DzIxMTExMjMxMjM1OTU5WjArMQswCQYDVQQGEwJVUzEOMAwGA1UEChMFRGVtbzEx
DDAKBgNVBAMTA0NBMTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAy1ygNguH
72n0l+1uy9HEM6t2LWJEmC0w4tAuXk9H1FseQMV28eBQXdyg3wK+yli6l6c9k9Aj
HAZ/6TXTVmOxtTgkXbvHlwcE3pTiHJSvZWGQMORCPNkjjiVBiLBdGQ3qFKyV+NA5
K4XnVy0jkeS/BHx7KO7m+DOLVow8FO1CstUCAwEAAaNSMFAwDwYDVR0TAQH/BAUw
AwEB/zAdBgNVHQ4EFgQUyBzakgqpSAg6dnYVOATxNNkV0CAwCwYDVR0PBAQDAgEG
MBEGCWCGSAGG+EIBAQQEAwIABzANBgkqhkiG9w0BAQUFAAOBgQBG1QBfo1kZRN50
/a3ZoQufIj0FJLMS/WkUnW0RLqEewyhEK9u86eoglcz5SxdD4T+VN9+MxoZ2J83P
b21Y4FUDqnkdoGAPdoxX+7iLQcxVoMK72n72QSSzvfnjsr9+pazLp1P6ZK9epbZf
s2WM0ty3a+sYmXANG8wGazAyRDMi0Q==
-----END CERTIFICATE-----
EOF

my $yubico_u2f_cert = decode_base64url(
"MIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4"
);

my $neowave_cert = decode_base64url(
"MIIEmTCCBD-gAwIBAgIQZoGUWqM7jnhW2nmV4EZW1jAKBggqhkjOPQQDAjB0MQswCQYDVQQGEwJGUjETMBEGA1UEChMKQ2VydEV1cm9wZTEXMBUGA1UECxMOMDAwMiA0MzQyMDIxODAxHTAbBgNVBAMTFENlcnRFdXJvcGUgSWRlY3lzIENBMRgwFgYDVQRhEw9OVFJGUi00MzQyMDIxODAwHhcNMjAwNjIyMTIzMjIzWhcNMjgwMTIxMjMwMDAwWjCBsDELMAkGA1UEBhMCRlIxEDAOBgNVBAoTB05FT1dBVkUxIjAgBgNVBAsTGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xJjAkBgNVBAMTHUZJRE8yIEF0dGVzdGF0aW9uIENlcnRpZmljYXRlMREwDwYDVQQHEwhHYXJkYW5uZTEhMB8GCSqGSIb3DQEJARYSY29udGFjdEBuZW93YXZlLmZyMQ0wCwYDVQQIEwRQQUNBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE64J-F8-nXNC8pToUHRksVq2b5RFvr5lOOlK6zpj1y0GHgOITTS7DiVd6cN_GtQr2e78HS0NIi7Aw_1AuPs7kh6OCAnQwggJwMBMGA1UdJQQMMAoGCCsGAQUFBwMCMBMGA1UdIwQMMAqACENpBuFMW2NyMEwGCCsGAQUFBwEBBEAwPjA8BggrBgEFBQcwAoYwaHR0cDovL3d3dy5jZXJ0ZXVyb3BlLmZyL3JlZmVyZW5jZS9lY19pZGVjeXMuY3J0MFcGA1UdIARQME4wTAYNKoF6AWkrgxsBAQEBADA7MDkGCCsGAQUFBwIBFi1odHRwczovL3d3dy5jZXJ0ZXVyb3BlLmZyL2NoYWluZS1kZS1jb25maWFuY2UwggFKBgNVHR8EggFBMIIBPTBBoD-gPYY7aHR0cDovL3d3dy5jZXJ0ZXVyb3BlLmZyL3JlZmVyZW5jZS9jZXJ0ZXVyb3BlX2VjX2lkZWN5cy5jcmwwe6B5oHeGdWxkYXA6Ly9sY3IxLmNlcnRldXJvcGUuZnIvY249Q2VydEV1cm9wZSUyMElkZWN5cyUyMENBLG91PTAwMDIlMjA0MzQyMDIxODAsbz1DZXJ0RXVyb3BlLGM9RlI_Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDB7oHmgd4Z1bGRhcDovL2xjcjIuY2VydGV1cm9wZS5mci9jbj1DZXJ0RXVyb3BlJTIwSWRlY3lzJTIwQ0Esb3U9MDAwMiUyMDQzNDIwMjE4MCxvPUNlcnRFdXJvcGUsYz1GUj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MBEGA1UdDgQKBAhMOoIVT46cGTAOBgNVHQ8BAf8EBAMCBPAwIQYLKwYBBAGC5RwBAQQEEgQQN4nakflDRryVw1DqIBLwOjAJBgNVHRMEAjAAMAoGCCqGSM49BAMCA0gAMEUCIQCzN40Mn6ZjEjc-EkfTEQBQQlrc9DQAo6TPDAB7s3ZtQgIgaYWXNanYmBPPcRxmpwXeO4g_t3lN3FPmvjdP2SXSOx8"
);

my $neowave_roots = [
    "-----BEGIN CERTIFICATE-----
MIIEODCCA92gAwIBAgIDAInBMAoGCCqGSM49BAMCMHsxCzAJBgNVBAYTAkZSMRMw
EQYDVQQKEwpDZXJ0RXVyb3BlMRcwFQYDVQQLEw4wMDAyIDQzNDIwMjE4MDEkMCIG
A1UEAxMbQ2VydEV1cm9wZSBFbGxpcHRpYyBSb290IENBMRgwFgYDVQRhEw9OVFJG
Ui00MzQyMDIxODAwHhcNMTgwMjIyMjMwMDAwWhcNMjgwMTIxMjMwMDAwWjB0MQsw
CQYDVQQGEwJGUjETMBEGA1UEChMKQ2VydEV1cm9wZTEXMBUGA1UECxMOMDAwMiA0
MzQyMDIxODAxHTAbBgNVBAMTFENlcnRFdXJvcGUgSWRlY3lzIENBMRgwFgYDVQRh
Ew9OVFJGUi00MzQyMDIxODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASLVL+1
STJvaERO5WCR+jGcAxLvmPBDiZY1NgFFIhpX6OAZApQYmt6xSh74SwM+mjgnsSEc
c4A2Uf139FgZ4rpYo4ICVTCCAlEwEwYDVR0jBAwwCoAITZ01tGuBPLowSgYIKwYB
BQUHAQEEPjA8MDoGCCsGAQUFBzAChi5odHRwOi8vd3d3LmNlcnRldXJvcGUuZnIv
cmVmZXJlbmNlL2VjX3Jvb3QuY3J0MFMGA1UdIARMMEowSAYJKoF6AWkpAQEAMDsw
OQYIKwYBBQUHAgEWLWh0dHBzOi8vd3d3LmNlcnRldXJvcGUuZnIvY2hhaW5lLWRl
LWNvbmZpYW5jZTCCAWAGA1UdHwSCAVcwggFTMD+gPaA7hjlodHRwOi8vd3d3LmNl
cnRldXJvcGUuZnIvcmVmZXJlbmNlL2NlcnRldXJvcGVfZWNfcm9vdC5jcmwwgYag
gYOggYCGfmxkYXA6Ly9sY3IxLmNlcnRldXJvcGUuZnIvY249Q2VydEV1cm9wZSUy
MEVsbGlwdGljJTIwUm9vdCUyMENBLG91PTAwMDIlMjA0MzQyMDIxODAsbz1DZXJ0
RXVyb3BlLGM9RlI/Y2VydGlmaWNhdGVSZXZvY2F0aW9uTGlzdDCBhqCBg6CBgIZ+
bGRhcDovL2xjcjIuY2VydGV1cm9wZS5mci9jbj1DZXJ0RXVyb3BlJTIwRWxsaXB0
aWMlMjBSb290JTIwQ0Esb3U9MDAwMiUyMDQzNDIwMjE4MCxvPUNlcnRFdXJvcGUs
Yz1GUj9jZXJ0aWZpY2F0ZVJldm9jYXRpb25MaXN0MBEGA1UdDgQKBAhDaQbhTFtj
cjAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQD
AgNJADBGAiEAoEepHMC5X9jBKaGphcKjidhiN+Znz7v3S3hc31/AunsCIQDKqogK
2SZOXZcvvHCB6UQSaA0nLn4RUwy1guDivbZbwg==
-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----
MIICHTCCAcKgAwIBAgICddUwCgYIKoZIzj0EAwIwezELMAkGA1UEBhMCRlIxEzAR
BgNVBAoTCkNlcnRFdXJvcGUxFzAVBgNVBAsTDjAwMDIgNDM0MjAyMTgwMSQwIgYD
VQQDExtDZXJ0RXVyb3BlIEVsbGlwdGljIFJvb3QgQ0ExGDAWBgNVBGETD05UUkZS
LTQzNDIwMjE4MDAeFw0xODAxMjIyMzAwMDBaFw0yODAxMjIyMzAwMDBaMHsxCzAJ
BgNVBAYTAkZSMRMwEQYDVQQKEwpDZXJ0RXVyb3BlMRcwFQYDVQQLEw4wMDAyIDQz
NDIwMjE4MDEkMCIGA1UEAxMbQ2VydEV1cm9wZSBFbGxpcHRpYyBSb290IENBMRgw
FgYDVQRhEw9OVFJGUi00MzQyMDIxODAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATz2jNaKOK/MKdW2fme1tq6GREuPuuKW9HgWYgMRrjvZUTOqLANJ3Md5Hqv1EN1
zMd4lWtyfzRla7rv5ARBoOoTozYwNDAPBgNVHRMBAf8EBTADAQH/MBEGA1UdDgQK
BAhNnTW0a4E8ujAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAwRgIhAMrh
b8SmfNLeLNgaAVmQ6AOMiLNLVHX0kFUO80CnT38EAiEAzNAgv4dH+HDhZSgZWJia
Pu/nfZTeuGy4MydPMq5urs4=
-----END CERTIFICATE-----"
];

my $res;

$res =
  Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [$main::yubico_u2f_root],
    $yubico_u2f_cert, [] );
is( $res->{result}, 1, "Successful validation" ) or diag explain $res;

$res = Authen::WebAuthn::SSLeayChainVerifier::verify_chain( $neowave_roots,
    $neowave_cert, [] );
is( $res->{result}, 1, "Successful validation" ) or diag explain $res;

$res =
  Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [$main::yubico_u2f_root],
    $neowave_cert, [] );
is( $res->{result}, 0, "Wrong CA does not validate" ) or diag explain $res;

$res = Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [$rootca],
    $cert, $chain );
is( $res->{result}, 1, "Valid chain succeeds" ) or diag explain $res;

$res = Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [$rootca],
    $cert, [ $chain->[0] ] );
is( $res->{result}, 0, "Partial chain fails" ) or diag explain $res;

$res = Authen::WebAuthn::SSLeayChainVerifier::verify_chain( [$rootca],
    $cert, [ $chain->[0] ] );
is( $res->{result}, 0, "Missing chain fails" ) or diag explain $res;

done_testing();
