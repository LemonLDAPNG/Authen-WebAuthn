# Builds FIDO Metadata Service BLOBs signed with the test PKI's metadata
# signers (t/pki/generate mds)

use strict;
use warnings;
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use JSON;
use MIME::Base64 qw(decode_base64 encode_base64 encode_base64url);

sub mds_pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name" or die "t/pki/$name: $!";
    local $/;
    return <$fh>;
}

sub mds_der {
    my ($name) = @_;
    my $pem = mds_pem($name);
    $pem =~ s/-----[^-]+-----//g;
    return decode_base64($pem);
}

# A metadata entry for a model attested by one of t/pki's certificates
sub mds_entry {
    my (%args)    = @_;
    my $roots     = delete $args{roots} || ["root.pem"];
    my $statement = {
        description                 => "Test authenticator",
        protocolFamily              => "fido2",
        schema                      => 3,
        attestationTypes            => ["basic_full"],
        attestationRootCertificates =>
          [ map { encode_base64( mds_der($_), "" ) } @$roots ],
        %{ delete $args{statement} || {} },
    };
    return {
        aaguid            => "01020304-0506-0708-090a-0b0c0d0e0f10",
        metadataStatement => $statement,
        statusReports     =>
          [ { status => "FIDO_CERTIFIED_L1", effectiveDate => "2024-01-01" } ],
        timeOfLastStatusChange => "2024-01-01",
        %args,
    };
}

# A BLOB's payload: serial number 7, next update in 2100, one entry
sub mds_payload {
    my (%args) = @_;
    return {
        legalHeader => "Test metadata",
        no          => $args{no}          // 7,
        nextUpdate  => $args{next_update} // "2100-01-01",
        entries     => $args{entries} || [ mds_entry() ],
    };
}

# A signed BLOB. signer names a key and certificate in t/pki; chain lists
# the certificates for x5c (signer first), or is [] for no x5c; payload_json
# signs those bytes as the payload
sub mds_blob {
    my (%args) = @_;
    my $signer = $args{signer} // "mds-signer";
    my $chain  = $args{chain}  // [ $signer, "mds-ca" ];
    my $alg    = $args{alg}    // ( $signer =~ /rsa/ ? "RS256" : "ES256" );

    my $header = {
        alg => $alg,
        typ => "JWT",
        (
            @$chain
            ? ( x5c =>
                  [ map { encode_base64( mds_der("$_.pem"), "" ) } @$chain ] )
            : ()
        ),
        %{ $args{header} || {} },
    };
    my $payload = $args{payload} // mds_payload(%args);
    my $json    = JSON->new->canonical;
    my $tbs     = join ".", encode_base64url( $json->encode($header) ),
      encode_base64url( $args{payload_json} // $json->encode($payload) );

    my $key_pem = mds_pem("$signer-key.pem");
    my $ecc     = eval { Crypt::PK::ECC->new( \$key_pem ) };
    my $signature =
        $ecc
      ? $ecc->sign_message_rfc7518( $tbs, "SHA256" )
      : Crypt::PK::RSA->new( \$key_pem )
      ->sign_message( $tbs, "SHA256", "v1.5" );
    return "$tbs." . encode_base64url($signature);
}

sub mds_crls { [ mds_pem("mds-root.crl"), mds_pem("mds-ca.crl") ] }

1;
