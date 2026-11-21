package Authen::WebAuthn::Test;

use Mouse;
use CBOR::XS;
use MIME::Base64 qw(encode_base64url decode_base64url);
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::PK::Ed25519;
use Hash::Merge::Simple qw/merge/;
use JSON qw(encode_json decode_json);
use Authen::WebAuthn;
use utf8;

has origin => ( is => 'rw' );
has rp_id  => ( is => 'rw', lazy => 1, default => sub { $_[0]->origin } );
has credential_id => ( is => 'rw' );
has aaguid        => ( is => 'rw' );
has key           => ( is => 'rw' );
has sign_count    => ( is => 'rw', default => 0 );

# COSE algorithm; by default, inferred from the key
has alg => ( is => 'rw', lazy => 1, builder => '_build_alg' );

# "none", or "packed" for self attestation
has attestation_format => ( is => 'rw', default => 'none' );

# ECDSA curve name => COSE curve, algorithm and hash
my %EC_CURVES = (
    secp256r1 => { crv => 1, alg => -7,  hash => 'SHA256', size => 32 },
    secp384r1 => { crv => 2, alg => -35, hash => 'SHA384', size => 48 },
    secp521r1 => { crv => 3, alg => -36, hash => 'SHA512', size => 66 },
);

my %RSA_SIGNATURES = (
    -257   => [ 'SHA256', 'v1.5' ],
    -37    => [ 'SHA256', 'pss', 32 ],
    -65535 => [ 'SHA1', 'v1.5' ],
);

use constant {
    FLAG_UP => 1,
    FLAG_UV => 4,
    FLAG_BE => 8,
    FLAG_BS => 16,
    FLAG_AT => 64,
    FLAG_ED => 128,
};

sub makeAttestedCredentialData {
    my ($acd) = @_;
    return '' unless ($acd);

    my $aaguid              = exportAaguid( $acd->{aaguid} );
    my $credentialIdLength  = pack( 'n', length( $acd->{credentialId} ) );
    my $credentialId        = $acd->{credentialId};
    my $credentialPublicKey = $acd->{credentialPublicKey};
    my $attestedCredentialData =
      ( $aaguid . $credentialIdLength . $credentialId . $credentialPublicKey );

    return $attestedCredentialData;
}

sub makeAuthData {
    my ($authdata) = @_;

    my $rpIdHash  = $authdata->{rpIdHash};
    my $flags     = pack( 'C', makeFlags( $authdata->{flags} ) );
    my $signCount = pack( 'N', $authdata->{signCount} );
    my $acd = makeAttestedCredentialData( $authdata->{attestedCredentialData} );
    my $ed =
      $authdata->{extensions} ? encode_cbor( $authdata->{extensions} ) : '';
    my $res = $rpIdHash . $flags . $signCount . $acd . $ed;

    return $res;
}

sub makeAttestationObject {
    my ($dat) = @_;

    my $auth_data = makeAuthData( $dat->{authData} );

    # A code reference is given the authenticator data it signs
    my $att_stmt = $dat->{attStmt} // {};
    $att_stmt = $att_stmt->($auth_data) if ref($att_stmt) eq 'CODE';

    my $attestationObject = {
        'fmt'      => $dat->{fmt},
        'authData' => $auth_data,
        'attStmt'  => $att_stmt,
    };

    my $cbor = CBOR::XS->new;
    $cbor->text_keys(1);
    return $cbor->encode($attestationObject);
}

sub makeFlags {
    my ($flags) = @_;
    my $up = $flags->{userPresent}  ? 1 : 0;
    my $uv = $flags->{userVerified} ? 1 : 0;
    my $be = $flags->{backupEligible} ? 1 : 0;
    my $bs = $flags->{backupState} ? 1 : 0;
    my $at = $flags->{atIncluded}   ? 1 : 0;
    my $ed = $flags->{edIncluded}   ? 1 : 0;
    return ( FLAG_UP * $up +
          FLAG_UV * $uv +
          FLAG_BE * $be +
          FLAG_BS * $bs +
          FLAG_AT * $at +
          FLAG_ED * $ed );
}

# Transform string GUID into binary
sub exportAaguid {
    my ($aaguid) = @_;
    $aaguid =~ s/-//g;

    if ( length($aaguid) == 32 ) {
        return pack( 'H*', $aaguid );
    }
    else {
        die "Invalid AAGUID length";
    }
}

sub encode_credential {
    my ( $self, $credential ) = @_;

    # Encode clientDataJSON
    if ( $credential->{response}->{clientDataJSON} ) {
        $credential->{response}->{clientDataJSON} =
          encode_base64url( $credential->{response}->{clientDataJSON} );
    }

    # Encode attestationObject
    if ( $credential->{response}->{attestationObject} ) {
        $credential->{response}->{attestationObject} =
          encode_base64url( $credential->{response}->{attestationObject} );
    }

    # Encode authenticatorData
    if ( $credential->{response}->{authenticatorData} ) {
        $credential->{response}->{authenticatorData} =
          encode_base64url( $credential->{response}->{authenticatorData} );
    }

    # Encode signature
    if ( $credential->{response}->{signature} ) {
        $credential->{response}->{signature} =
          encode_base64url( $credential->{response}->{signature} );
    }

    # Encode rawId
    if ( $credential->{rawId} ) {
        $credential->{rawId} = encode_base64url( $credential->{rawId} );
    }

    return JSON->new->utf8->pretty->encode($credential);
}

# The key, as a CryptX object of whichever type the PEM holds
sub _pk {
    my ($self) = @_;
    my $pem = $self->key;
    for my $class (qw(Crypt::PK::ECC Crypt::PK::RSA Crypt::PK::Ed25519)) {
        my $pk = eval { $class->new( \$pem ) };
        return $pk if $pk;
    }
    die "Unsupported key";
}

sub _build_alg {
    my ($self) = @_;
    my $pk = $self->_pk;
    return -257 if $pk->isa('Crypt::PK::RSA');
    return -8   if $pk->isa('Crypt::PK::Ed25519');
    my $curve = $EC_CURVES{ $pk->key2hash->{curve_name} }
      or die "Unsupported curve " . $pk->key2hash->{curve_name};
    return $curve->{alg};
}

# Just enough CBOR for a COSE_Key: its labels and algorithm identifiers fit in
# 16 bits
sub _cbor_int {
    my ($n) = @_;
    my ( $major, $value ) = $n < 0 ? ( 0x20, -1 - $n ) : ( 0x00, $n );
    return pack( 'C', $major + $value ) if $value < 24;
    return pack( 'CC', $major + 24, $value ) if $value < 256;
    return pack( 'Cn', $major + 25, $value );
}

sub _cbor_bytes {
    my ($bytes) = @_;
    my $length = length($bytes);
    return pack( 'C', 0x40 + $length ) . $bytes if $length < 24;
    return pack( 'CC', 0x58, $length ) . $bytes if $length < 256;
    return pack( 'Cn', 0x59, $length ) . $bytes;
}

sub _cose_key {
    my (@pairs) = @_;
    my $cose = pack( 'C', 0xa0 + @pairs / 2 );
    while ( my ( $label, $value ) = splice( @pairs, 0, 2 ) ) {
        $cose .= _cbor_int($label) . $value;
    }
    return $cose;
}

sub encode_cosekey {
    my ($self) = @_;

    my $pk  = $self->_pk;
    my $alg = $self->alg;

    if ( $pk->isa('Crypt::PK::Ed25519') ) {
        return _cose_key(
            1  => _cbor_int(1),                               # kty OKP
            3  => _cbor_int($alg),
            -1 => _cbor_int(6),                               # Ed25519
            -2 => _cbor_bytes( $pk->export_key_raw('public') ),
        );
    }
    if ( $pk->isa('Crypt::PK::RSA') ) {
        my $hash = $pk->key2hash;
        return _cose_key(
            1  => _cbor_int(3),                               # kty RSA
            3  => _cbor_int($alg),
            -1 => _cbor_bytes( pack( 'H*', $hash->{N} ) ),
            -2 => _cbor_bytes( pack( 'H*', $hash->{e} ) ),
        );
    }

    my $hash  = $pk->key2hash;
    my $curve = $EC_CURVES{ $hash->{curve_name} };

    # Same bytes as earlier versions for P-256
    return Authen::WebAuthn::_ecc_obj_to_cose($pk) if $curve->{crv} == 1;

    my $coordinate = sub {
        pack( 'H*', sprintf( '%0*s', $curve->{size} * 2, shift ) );
    };
    return _cose_key(
        1  => _cbor_int(2),                                   # kty EC2
        3  => _cbor_int($alg),
        -1 => _cbor_int( $curve->{crv} ),
        -2 => _cbor_bytes( $coordinate->( $hash->{pub_x} ) ),
        -3 => _cbor_bytes( $coordinate->( $hash->{pub_y} ) ),
    );
}

sub sign {
    my ( $self, $message ) = @_;
    my $pk = $self->_pk;

    return $pk->sign_message($message) if $pk->isa('Crypt::PK::Ed25519');
    if ( $pk->isa('Crypt::PK::RSA') ) {
        my $options = $RSA_SIGNATURES{ $self->alg }
          or die "Unsupported RSA algorithm " . $self->alg;
        return $pk->sign_message( $message, @$options );
    }
    return $pk->sign_message( $message,
        $EC_CURVES{ $pk->key2hash->{curve_name} }->{hash} );
}

sub get_credential_response {
    my ( $self, $input, $override ) = @_;

    my $challenge = $input->{request}->{challenge};
    my $uv = $input->{request}->{authenticatorSelection}->{userVerification}
      || "preferred";

    # Self attestation signs the authenticator data and the client data hash
    my $client_data_json;
    my $att_stmt =
      $self->attestation_format eq 'packed'
      ? sub {
        my ($auth_data) = @_;
        return {
            alg => $self->alg + 0,
            sig => $self->sign( $auth_data . sha256($client_data_json) ),
        };
      }
      : {};

    # Everything is build from this array, you can override it for testing
    # various scenarios
    my $credential = merge {
        response => {
            type           => "public-key",
            rawId          => $self->credential_id,
            id             => encode_base64url( $self->credential_id ),
            clientDataJSON => {
                type        => "webauthn.create",
                challenge   => "$challenge",
                origin      => $self->origin,
                crossOrigin => JSON::false,
            },
            attestationObject => {
                'fmt'      => $self->attestation_format,
                'authData' => {
                    rpIdHash => sha256( $self->rp_id ),
                    flags    => {
                        userPresent => 1,
                        ( $uv eq "required" ? ( userVerified => 1 ) : () ),
                        atIncluded => 1,
                    },
                    signCount              => $self->sign_count,
                    attestedCredentialData => {
                        aaguid              => $self->aaguid,
                        credentialId        => $self->credential_id,
                        credentialPublicKey => $self->encode_cosekey,
                    },
                },
                'attStmt' => $att_stmt,
            }
        }
    }, $override;

    $client_data_json = $credential->{response}->{clientDataJSON} =
      encode_json $credential->{response}->{clientDataJSON};
    $credential->{response}->{attestationObject} =
      makeAttestationObject $credential->{response}->{attestationObject};

    return $credential;
}

sub get_assertion_response {
    my ( $self, $input, $override ) = @_;

    my $challenge = $input->{request}->{challenge};
    my $uv        = $input->{request}->{userVerification} || "preferred";

    # Everything is build from this array, you can override it for testing
    # various scenarios
    my $credential = merge {
        type     => "public-key",
        rawId    => $self->credential_id,
        id       => encode_base64url( $self->credential_id ),
        response => {
            clientDataJSON => {
                type        => "webauthn.get",
                challenge   => "$challenge",
                origin      => $self->origin,
                crossOrigin => JSON::false,
            },
            authenticatorData => {
                rpIdHash => sha256( $self->rp_id ),
                flags    => {
                    userPresent => 1,
                    ( $uv eq "required" ? ( userVerified => 1 ) : () ),
                },
                signCount => $self->sign_count,
            },
            userHandle => "",    #TODO
        }
    }, $override;

    my $clientData = {
        type        => "webauthn.get",
        challenge   => "$challenge",
        origin      => $self->origin,
        crossOrigin => JSON::false,
    };
    $credential->{response}->{clientDataJSON} =
      encode_json $credential->{response}->{clientDataJSON};
    $credential->{response}->{authenticatorData} =
      makeAuthData $credential->{response}->{authenticatorData};

    my $hash      = sha256( $credential->{response}->{clientDataJSON} );
    my $authData  = $credential->{response}->{authenticatorData};
    my $signature = $self->sign( $authData . $hash );

    # Add signature to hash unless we have overriden it
    unless ( $credential->{response}->{signature} ) {
        $credential->{response}->{signature} = $signature;
    }

    return $credential;
}

1;

