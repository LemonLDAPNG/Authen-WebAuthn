package Authen::WebAuthn::Test;

use Mouse;
use CBOR::XS;
use MIME::Base64 qw(encode_base64url decode_base64url);
use Digest::SHA qw(sha256);
use Crypt::PK::ECC;
use Crypt::PK::RSA;
use Crypt::PK::Ed25519;
use Crypt::OpenSSL::X509;
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

# The user handle the authenticator returns when signing, as raw bytes; empty
# by default, as when the user was identified before the ceremony
has user_handle => ( is => 'rw', default => '' );

# COSE algorithm; by default, inferred from the key
has alg => ( is => 'rw', lazy => 1, builder => '_build_alg' );

# "none", "packed" or "fido-u2f"
has attestation_format => ( is => 'rw', default => 'none' );

# For "packed" with a certificate, and "fido-u2f": the attestation key, and
# its certificate followed by any intermediates, all PEM. Without them,
# "packed" is self attestation.
has attestation_key          => ( is => 'rw' );
has attestation_certificates => ( is => 'rw' );

# ECDSA curve name => COSE curve, algorithm and hash
my %EC_CURVES = (
    secp256r1 => { crv => 1, alg => -7,  hash => 'SHA256', size => 32 },
    secp384r1 => { crv => 2, alg => -35, hash => 'SHA384', size => 48 },
    secp521r1 => { crv => 3, alg => -36, hash => 'SHA512', size => 66 },
);

my %RSA_SIGNATURES = (
    -257   => [ 'SHA256', 'v1.5' ],
    -37    => [ 'SHA256', 'pss', 32 ],
    -65535 => [ 'SHA1',   'v1.5' ],
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
      $authdata->{extensions} ? _canonical_cbor( $authdata->{extensions} ) : '';
    my $res = $rpIdHash . $flags . $signCount . $acd . $ed;

    return $res;
}

sub makeAttestationObject {
    my ($dat) = @_;

    my $auth_data = makeAuthData( $dat->{authData} );

    # A code reference is given the authenticator data it signs
    my $att_stmt = $dat->{attStmt} // {};
    $att_stmt = $att_stmt->($auth_data) if ref($att_stmt) eq 'CODE';

    # A text string, as CBOR::XS encodes a character string
    my $fmt = $dat->{fmt};
    utf8::upgrade($fmt) if defined $fmt;

    my $attestationObject = {
        'fmt'      => $fmt,
        'authData' => $auth_data,
        'attStmt'  => $att_stmt,
    };

    return _canonical_cbor($attestationObject);
}

sub makeFlags {
    my ($flags) = @_;
    my $up      = $flags->{userPresent}    ? 1 : 0;
    my $uv      = $flags->{userVerified}   ? 1 : 0;
    my $be      = $flags->{backupEligible} ? 1 : 0;
    my $bs      = $flags->{backupState}    ? 1 : 0;
    my $at      = $flags->{atIncluded}     ? 1 : 0;
    my $ed      = $flags->{edIncluded}     ? 1 : 0;
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

    # Encode userHandle
    if ( length( $credential->{response}->{userHandle} // "" ) ) {
        $credential->{response}->{userHandle} =
          encode_base64url( $credential->{response}->{userHandle} );
    }

    # Encode rawId, which a registration response carries in response
    for my $container ( $credential, $credential->{response} ) {
        if ( $container->{rawId} ) {
            $container->{rawId} = encode_base64url( $container->{rawId} );
        }
    }

    return JSON->new->utf8->pretty->encode($credential);
}

# A PEM key, as a CryptX object of whichever type it holds
sub _read_key {
    my ($pem) = @_;
    for my $class (qw(Crypt::PK::ECC Crypt::PK::RSA Crypt::PK::Ed25519)) {
        my $pk = eval { $class->new( \$pem ) };
        return $pk if $pk;
    }
    die "Unsupported key";
}

sub _pk { _read_key( $_[0]->key ) }

sub _build_alg { _alg_for( $_[0]->_pk ) }

sub _alg_for {
    my ($pk) = @_;
    return -257 if $pk->isa('Crypt::PK::RSA');
    return -8   if $pk->isa('Crypt::PK::Ed25519');
    my $curve = $EC_CURVES{ $pk->key2hash->{curve_name} }
      or die "Unsupported curve " . $pk->key2hash->{curve_name};
    return $curve->{alg};
}

# CBOR as authenticators encode it (CTAP2 canonical form): map keys sorted
# by their encoding, shortest first, then bytewise. It is also the same in
# every run, which CBOR::XS's encoding of a Perl hash is not. A map key that
# reads as an integer is a CBOR integer, as COSE labels are; others are text.
sub _canonical_cbor {
    my ($value) = @_;

    if ( ref($value) eq 'HASH' ) {
        my %encoded = map {
            $_ => /^-?[0-9]+\z/
              ? _cbor_int($_)
              : _cbor_head( 3, length $_ )
              . $_
        } keys %$value;
        my @keys = sort {
            length( $encoded{$a} ) <=> length( $encoded{$b} )
              or $encoded{$a} cmp $encoded{$b}
        } keys %$value;
        return _cbor_head( 5, scalar @keys ) . join '',
          map { $encoded{$_} . _canonical_cbor( $value->{$_} ) } @keys;
    }
    if ( ref($value) eq 'ARRAY' ) {
        return _cbor_head( 4, scalar @$value ) . join '',
          map { _canonical_cbor($_) } @$value;
    }
    return CBOR::XS::encode_cbor($value);
}

# The maps, arrays and keys the simulator encodes are all short
sub _cbor_head {
    my ( $major, $length ) = @_;
    die "Too long for this encoder: $length" if $length > 23;
    return pack( 'C', ( $major << 5 ) + $length );
}

# Just enough CBOR for a COSE_Key: its labels and algorithm identifiers fit in
# 16 bits
sub _cbor_int {
    my ($n) = @_;
    my ( $major, $value ) = $n < 0 ? ( 0x20, -1 - $n ) : ( 0x00, $n );
    return pack( 'C',  $major + $value ) if $value < 24;
    return pack( 'CC', $major + 24, $value ) if $value < 256;
    return pack( 'Cn', $major + 25, $value );
}

sub _cbor_bytes {
    my ($bytes) = @_;
    my $length = length($bytes);
    return pack( 'C',  0x40 + $length ) . $bytes if $length < 24;
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
            1  => _cbor_int(1),                                   # kty OKP
            3  => _cbor_int($alg),
            -1 => _cbor_int(6),                                   # Ed25519
            -2 => _cbor_bytes( $pk->export_key_raw('public') ),
        );
    }
    if ( $pk->isa('Crypt::PK::RSA') ) {
        my $hash = $pk->key2hash;
        return _cose_key(
            1  => _cbor_int(3),                                   # kty RSA
            3  => _cbor_int($alg),
            -1 => _cbor_bytes( pack( 'H*', $hash->{N} ) ),
            -2 => _cbor_bytes( pack( 'H*', $hash->{e} ) ),
        );
    }

    my $hash  = $pk->key2hash;
    my $curve = $EC_CURVES{ $hash->{curve_name} };

    my $coordinate = sub {
        pack( 'H*', sprintf( '%0*s', $curve->{size} * 2, shift ) );
    };
    return _cose_key(
        1  => _cbor_int(2),                                     # kty EC2
        3  => _cbor_int($alg),
        -1 => _cbor_int( $curve->{crv} ),
        -2 => _cbor_bytes( $coordinate->( $hash->{pub_x} ) ),
        -3 => _cbor_bytes( $coordinate->( $hash->{pub_y} ) ),
    );
}

sub sign {
    my ( $self, $message ) = @_;
    return _sign_with( $self->_pk, $self->alg, $message );
}

sub _sign_with {
    my ( $pk, $alg, $message ) = @_;

    return $pk->sign_message($message) if $pk->isa('Crypt::PK::Ed25519');
    if ( $pk->isa('Crypt::PK::RSA') ) {
        my $options = $RSA_SIGNATURES{$alg}
          or die "Unsupported RSA algorithm $alg";
        return $pk->sign_message( $message, @$options );
    }
    return $pk->sign_message( $message,
        $EC_CURVES{ $pk->key2hash->{curve_name} }->{hash} );
}

sub _der {
    my ($pem) = @_;
    return Crypt::OpenSSL::X509->new_from_string($pem)
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
}

# The attestation statement for this format, as a function of the
# authenticator data it signs
sub _attestation_statement {
    my ( $self, $client_data_json ) = @_;

    my $format = $self->attestation_format;
    return {} if $format eq 'none';

    my $certificates = $self->attestation_certificates;
    my $x5c = $certificates ? [ map { _der($_) } @$certificates ] : undef;
    my $attestation_key =
      $self->attestation_key ? _read_key( $self->attestation_key ) : undef;

    if ( $format eq 'fido-u2f' ) {
        die "fido-u2f needs an attestation key and certificate"
          unless $attestation_key and $x5c;
        return sub {
            my ($auth_data) = @_;
            my $public_key = $self->_pk->export_key_raw('public');
            return {
                sig => $attestation_key->sign_message(
                    "\x00"
                      . sha256( $self->rp_id )
                      . sha256( ${$client_data_json} )
                      . $self->credential_id
                      . $public_key,
                    'SHA256'
                ),
                x5c => [ $x5c->[0] ],
            };
        };
    }

    die "Unsupported attestation format $format" unless $format eq 'packed';
    return sub {
        my ($auth_data) = @_;
        my $signed = $auth_data . sha256( ${$client_data_json} );
        return { alg => $self->alg + 0, sig => $self->sign($signed) }
          unless $attestation_key;

        my $alg = _alg_for($attestation_key);
        return {
            alg => $alg + 0,
            sig => _sign_with( $attestation_key, $alg, $signed ),
            x5c => $x5c,
        };
    };
}

sub get_credential_response {
    my ( $self, $input, $override ) = @_;

    my $challenge = $input->{request}->{challenge};
    my $uv = $input->{request}->{authenticatorSelection}->{userVerification}
      || "preferred";

    # Filled in below, once the client data is encoded
    my $client_data_json;
    my $att_stmt = $self->_attestation_statement( \$client_data_json );

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
            userHandle => $self->user_handle,
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

__END__

=head1 NAME

Authen::WebAuthn::Test - A software authenticator, for testing

=head1 SYNOPSIS

    use Authen::WebAuthn::Test;

    my $authenticator = Authen::WebAuthn::Test->new(
        origin        => "https://app.example.com",
        rp_id         => "app.example.com",
        credential_id => "my-credential",
        aaguid        => "00000000-0000-0000-0000-000000000000",
        key           => $private_key_pem,
    );

    # What navigator.credentials.create() would return
    my $registration = $authenticator->get_credential_response(
        { request => { challenge => $challenge_b64 } } );

    # What navigator.credentials.get() would return
    my $assertion = $authenticator->get_assertion_response(
        { request => { challenge => $challenge_b64 } } );

=head1 DESCRIPTION

This module plays the part of an authenticator and its browser, so that a
Relying Party built on L<Authen::WebAuthn> can be tested without either.
It signs with the private key it is given; never give it a real one.

=head1 ATTRIBUTES

=over 4

=item origin, rp_id

The origin the browser reports, and the RP ID the authenticator data is
bound to. C<rp_id> defaults to C<origin>.

=item credential_id

The credential ID, as raw bytes.

=item aaguid

The authenticator's AAGUID, as a UUID string.

=item key

The credential's private key, PEM-encoded: ECDSA on P-256, P-384 or P-521,
RSA, or Ed25519.

=item alg

The COSE algorithm the credential signs with. By default it follows from
the key: ES256, ES384 or ES512 for ECDSA, RS256 for RSA (set C<-37> for
PS256), EdDSA for Ed25519.

=item sign_count

The signature counter to report. Default 0.

=item user_handle

The user handle returned when signing, as raw bytes, as an authenticator does
for a discoverable credential. Empty by default.

=item attestation_format

C<none> (the default), C<packed> or C<fido-u2f>.

=item attestation_key, attestation_certificates

For C<packed> attestation with a certificate, and for C<fido-u2f>: the
attestation private key, PEM-encoded, and an arrayref of PEM certificates,
the attestation certificate first. Without them, C<packed> is self
attestation.

=back

=head1 METHODS

=over 4

=item get_credential_response($input, $override)

Returns a registration response for C<< $input->{request} >>, which holds
at least the C<challenge>. Its C<clientDataJSON> and C<attestationObject>
are raw bytes, to be base64url-encoded for C<validate_registration>.

C<$override> is merged into the response before it is encoded, to make
it wrong in a chosen way: for example C<< { response => { clientDataJSON
=> { origin => "https://evil.example.com" } } } >>.

=item get_assertion_response($input, $override)

The same for authentication, with C<authenticatorData> and C<signature>.

=item encode_cosekey

The credential's public key as a COSE key, in raw bytes.
C<validate_registration> returns the same key base64url-encoded, as
C<credential_pubkey>.

=item sign($message)

Signs C<$message> with the credential key.

=item encode_credential($response)

Encodes a response's binary fields as base64url, as a browser does, and
returns it as JSON. The layout is the simulator's: a registration response
carries C<id>, C<rawId> and C<type> inside C<response>.

=back

=cut
