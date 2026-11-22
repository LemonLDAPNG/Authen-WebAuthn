use Test::More;
use Crypt::OpenSSL::X509;
use Crypt::PK::ECC;
use Digest::SHA  qw(sha1_hex);
use MIME::Base64 qw(decode_base64 encode_base64 encode_base64url);
use strict;

use Authen::WebAuthn;
use Authen::WebAuthn::Metadata;
use Authen::WebAuthn::Test;

# FIDO Metadata Service BLOBs signed with the test PKI's metadata service
# (t/pki/generate mds), built by t/mds.pl
require "./t/mds.pl";

my $root   = mds_pem("mds-root.pem");
my $AAGUID = "01020304-0506-0708-090a-0b0c0d0e0f10";

sub metadata {
    my (%args) = @_;
    my %new = (
        root => delete $args{root} // $root,
        crls => exists $args{crls} ? delete $args{crls} : mds_crls(),
        (
            exists $args{previous_no}
            ? ( previous_no => delete $args{previous_no} )
            : ()
        ),
    );
    delete $new{crls} unless defined $new{crls};
    return
      scalar
      eval { Authen::WebAuthn::Metadata->new( blob => mds_blob(%args), %new ); };
}

sub refused {
    my ( $result, $message, $name ) = @_;
    ok( !$result, $name );
    like( $@, $message, "... with the expected message" );
}

subtest "Reading a BLOB" => sub {
    my $md = metadata();
    ok( $md, "An ES256 BLOB with its CRLs" ) or diag($@);
    is( $md->no,          7,            "... its serial number" );
    is( $md->next_update, "2100-01-01", "... its next update" );
    is( $md->expires,     4102531200,   "... expiring at the end of that day" );
    ok( $md->crl_checked, "... checked against CRLs" );
    like( $md->blob, qr/\A[\w-]+\.[\w-]+\.[\w-]+\z/, "... and the BLOB" );

    my $entry = $md->entry( aaguid => uc $AAGUID );
    is(
        $entry->{description},
        "Test authenticator",
        "Entries are found by AAGUID, in either case"
    );
    is( $entry->{status}, "FIDO_CERTIFIED_L1", "... with their status" );
    like(
        $entry->{attestation_roots}->[0],
        qr/\A-----BEGIN CERTIFICATE-----\n/,
        "... and roots as PEM"
    );
    is( $md->entry( aaguid => "00000000-0000-0000-0000-000000000000" ),
        undef, "An unknown AAGUID has no entry" );
    is( $md->entry( aaguid => undef ), undef, "... nor no AAGUID" );
    ok( !eval { $md->entry( name => "x" ) }, "entry by anything else" );
    like( $@, qr/entry takes aaguid or key_identifier/, "... croaks" );

    ok( metadata( signer => "mds-signer-rsa" ), "An RS256 BLOB" ) or diag($@);
    my $no_crls = metadata( crls => undef );
    ok( $no_crls && !$no_crls->crl_checked, "Without CRLs, not checked" );

    my $der_crls = metadata(
        crls => [
            map {
                ( my $b64 = $_ ) =~ s/-----[^-]+-----//g;
                decode_base64($b64);
            } @{ mds_crls() }
        ]
    );
    ok( $der_crls, "CRLs in DER" ) or diag($@);

    my $by_root = metadata( signer => "mds-root", chain => [] );
    ok( $by_root, "A BLOB without x5c, signed by the root itself" ) or diag($@);
    ok( $by_root && !$by_root->crl_checked, "... has no chain to check" );

    my $md2 = metadata(
        entries => [
            mds_entry(
                statusReports => [
                    { status => "FIDO_CERTIFIED" },
                    { status => "SOMETHING_NEW" },
                ]
            )
        ]
    );
    is( $md2->entry( aaguid => $AAGUID )->{status},
        "FIDO_CERTIFIED", "Unknown statuses are ignored" );
};

subtest "The default root" => sub {
    my $x509 = Crypt::OpenSSL::X509->new_from_string(
        $Authen::WebAuthn::Metadata::DEFAULT_ROOT);
    is(
        $x509->subject,
        "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Root R46",
        "is GlobalSign Root R46"
    );
    is(
        $x509->fingerprint_sha256,
"4F:A3:12:6D:8D:3A:11:D1:C4:85:5A:4F:80:7C:BA:D6:CF:91:9D:3A:5A:88:B0:3B:EA:2C:63:72:D9:3C:40:C9",
        "... GlobalSign's own"
    );
};

subtest "Refusing a BLOB" => sub {
    refused(
        metadata(
            signer => "mds-revoked",
            chain  => [ "mds-revoked", "mds-ca" ]
        ),
        qr/certificate revoked/,
        "A signer its CA revoked"
    );
    ok(
        metadata(
            signer => "mds-revoked",
            chain  => [ "mds-revoked", "mds-ca" ],
            crls   => undef
        ),
        "... which only CRLs can tell"
    );
    refused(
        metadata( crls => [ mds_pem("mds-root.crl") ] ),
        qr/unable to get certificate CRL/,
        "A certificate without its CRL"
    );
    refused(
        metadata( crls => ["junk"] ),
        qr/Could not parse CRL/,
        "A CRL that does not parse"
    );
    refused(
        metadata( crls => "junk" ),
        qr/crls must be an ARRAY/,
        "crls not in a list"
    );
    refused(
        metadata( crls => [ {} ] ),
        qr/CRL must be a string/,
        "A CRL that is not a string"
    );
    refused(
        metadata( root => mds_pem("root.pem") ),
        qr/Cannot verify the metadata BLOB's certificates/,
        "Another root"
    );
    refused(
        metadata( chain => ["mds-signer"] ),
        qr/Cannot verify the metadata BLOB's certificates/,
        "Without the intermediate"
    );
    refused(
        metadata( previous_no => 7 ),
        qr/BLOB 7 is not newer than 7/,
        "A BLOB no newer than the last"
    );
    ok( metadata( previous_no => 6 ), "... but a newer one is read" );

    refused(
        metadata( alg => "RS256" ),
        qr/BLOB key does not match its algorithm RS256/,
        "An algorithm the key cannot use"
    );
    refused(
        metadata( signer => "mds-signer-rsa", alg => "ES256" ),
        qr/BLOB key does not match its algorithm ES256/,
        "... the other way round"
    );
    refused(
        metadata( alg => "none" ),
        qr/Unsupported metadata BLOB algorithm none/,
        "alg none"
    );
    refused(
        metadata( header => { x5u => "https://mds.test/chain" } ),
        qr/x5u\) are not supported/,
        "Certificates by URL"
    );
    refused(
        metadata( header => { x5c => ["not base64!"] } ),
        qr/Invalid metadata BLOB certificate chain/,
        "An x5c that is not base64"
    );
    refused(
        metadata( header => { x5c => [] } ),
        qr/Invalid metadata BLOB certificate chain/,
        "An empty x5c"
    );

    my $blob = mds_blob();
    my ( $h, $p, $s ) = split /\./, $blob;
    my $other = ( split /\./, mds_blob( no => 8 ) )[1];
    for (
        [
            "$h.$other.$s",
            qr/Invalid metadata BLOB signature/,
            "A changed payload"
        ],
        [ "$h.$p",     qr/not a JWT/,               "Two parts" ],
        [ "$h.$p.$s=", qr/not a JWT/,               "Padding" ],
        [ "$h.$p.",    qr/not a JWT/,               "No signature" ],
        [ "x.y.z", qr/header is not a JSON object/, "Parts that are not JSON" ],
        [
            encode_base64url("[]") . ".$p.$s",
            qr/header is not a JSON object/,
            "A header that is not an object"
        ],
        [
            "$h." . encode_base64url("{") . ".$s",
            qr/payload is not a JSON object/,
            "A payload that is not JSON"
        ],
      )
    {
        my ( $bad, $message, $name ) = @$_;
        refused(
            scalar eval {
                Authen::WebAuthn::Metadata->new( blob => $bad, root => $root );
            },
            $message,
            $name
        );
    }
    refused(
        scalar eval { Authen::WebAuthn::Metadata->new( root => $root ) },
        qr/Missing metadata BLOB/,
        "No BLOB"
    );
    refused(
        scalar eval { Authen::WebAuthn::Metadata->new( blob => $blob ) },
        qr/Cannot verify the metadata BLOB's certificates/,
        "The default root, FIDO's, did not sign the test BLOB"
    );
    refused(
        scalar
          eval { Authen::WebAuthn::Metadata->new( blob => $blob, root => [] ); }
        ,
        qr/Missing root certificate/,
        "No root"
    );
    refused(
        scalar
          eval { Authen::WebAuthn::Metadata->new( blob => $blob, root => "x" ) }
        ,
        qr/Cannot verify the metadata BLOB's certificates/,
        "A root that is not PEM"
    );
    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->new(
                blob => mds_blob( signer => "mds-root", chain => [] ),
                root => "x"
            );
        },
        qr/Cannot read metadata BLOB certificate/,
        "... signing the BLOB itself"
    );

    my %payload = ( no => 7, nextUpdate => "2100-01-01", entries => [] );
    for (
        [
            { %payload, no => "seven" },
            qr/Invalid metadata BLOB serial number/,
            "A serial number that is not one"
        ],
        [
            { %payload, no => undef },
            qr/Invalid metadata BLOB serial number/,
            "No serial number"
        ],
        [
            { %payload, nextUpdate => "soon" },
            qr/Invalid metadata BLOB nextUpdate/,
            "A nextUpdate that is not a date"
        ],
        [
            { %payload, nextUpdate => "2100-13-40" },
            qr/Invalid metadata BLOB nextUpdate/,
            "... nor a real date"
        ],
        [
            { %payload, nextUpdate => "2100-1-1" },
            qr/Invalid metadata BLOB nextUpdate/,
            "... nor written as ISO 8601 does"
        ],
        [
            { %payload, entries => [ mds_entry( aaguid => {} ) ] },
            qr/entry 0: invalid aaguid/,
            "An AAGUID that is not a string"
        ],
        [
            { %payload, entries => {} },
            qr/Invalid metadata BLOB entries/,
            "Entries not in a list"
        ],
        [
            { %payload, entries => ["x"] },
            qr/entry 0: not an object/,
            "An entry that is not an object"
        ],
        [
            { %payload, entries => [ { aaguid => $AAGUID } ] },
            qr/entry 0: no metadataStatement/,
            "An entry without a statement"
        ],
        [
            { %payload, entries => [ mds_entry( aaguid => "not-a-uuid" ) ] },
            qr/entry 0: invalid aaguid/,
            "An invalid AAGUID"
        ],
        [
            {
                %payload,
                entries => [
                    mds_entry(
                        attestationCertificateKeyIdentifiers => ["xyz"]
                    )
                ]
            },
            qr/invalid attestationCertificateKeyIdentifiers/,
            "An invalid key identifier"
        ],
        [
            { %payload, entries => [ mds_entry( statusReports => [ {} ] ) ] },
            qr/invalid statusReports/,
            "A status report without a status"
        ],
        [
            {
                %payload,
                entries => [
                    mds_entry(
                        statement => { attestationRootCertificates => ["?"] }
                    )
                ]
            },
            qr/invalid attestationRootCertificates/,
            "A root that is not base64"
        ],
        [
            {
                %payload,
                entries => [
                    mds_entry(
                        statement => { attestationTypes => "basic_full" }
                    )
                ]
            },
            qr/invalid attestationTypes/,
            "Attestation types not in a list"
        ],
      )
    {
        my ( $payload, $message, $name ) = @$_;
        refused( metadata( payload => $payload ), $message, $name );
    }
};

# Registration, with metadata naming the roots of the authenticator model

my $rp = Authen::WebAuthn->new(
    origin => "http://auth.example.com",
    rp_id  => "auth.example.com",
);

my $credential_key = Crypt::PK::ECC->new;
$credential_key->generate_key("secp256r1");

sub authenticator {
    my (%args) = @_;
    my $certificate = delete $args{certificate} // "packed-aaguid";
    return Authen::WebAuthn::Test->new(
        origin             => "http://auth.example.com",
        rp_id              => "auth.example.com",
        credential_id      => "credential",
        aaguid             => $AAGUID,
        key                => $credential_key->export_key_pem("private"),
        attestation_format => "packed",
        (
            $certificate eq "self"
            ? ()
            : (
                attestation_key          => mds_pem("$certificate-key.pem"),
                attestation_certificates => [ mds_pem("$certificate.pem") ],
            )
        ),
        %args,
    );
}

sub register {
    my ( $authenticator, %options ) = @_;
    my $credential = $authenticator->get_credential_response(
        { request => { challenge => "abc" } } );
    return scalar eval {
        $rp->validate_registration(
            challenge_b64        => "abc",
            client_data_json_b64 =>
              encode_base64url( $credential->{response}->{clientDataJSON} ),
            attestation_object_b64 =>
              encode_base64url( $credential->{response}->{attestationObject} ),
            %options,
        );
    };
}

sub with_entry { metadata( entries => [ mds_entry(@_) ] ) }

subtest "Trust anchors from metadata" => sub {
    my $reg = register( authenticator(), metadata => with_entry() );
    ok( $reg, "The model's roots come from its metadata" ) or diag($@);
    is( $reg && $reg->{attestation_result}->{type}, "Basic", "... as Basic" );
    is(
        $reg && $reg->{metadata}->{description},
        "Test authenticator",
        "... reporting its description"
    );
    is( $reg && $reg->{metadata}->{status},
        "FIDO_CERTIFIED_L1", "... and status" );

    refused(
        register( authenticator() ),
        qr/Could not validate attestation trust/,
        "Without metadata or trust anchors"
    );
    refused(
        register(
            authenticator(),
            metadata => with_entry( roots => ["intermediate.pem"] )
        ),
        qr/Could not validate attestation trust/,
        "Roots that are not the model's"
    );
    ok(
        register(
            authenticator(),
            metadata      => with_entry( roots => ["intermediate.pem"] ),
            trust_anchors => [ mds_pem("root.pem") ],
        ),
        "... with trust_anchors that are"
    );

    ok(
        register(
            authenticator(
                certificate              => "packed-chained",
                attestation_certificates => [
                    mds_pem("packed-chained.pem"), mds_pem("intermediate.pem")
                ],
            ),
            metadata => with_entry()
        ),
        "Through an intermediate"
    ) or diag($@);

    refused(
        register(
            authenticator(),
            metadata => with_entry(
                statement => { attestationTypes => ["attca"] }
            )
        ),
        qr/Test authenticator \($AAGUID\) does not offer Basic attestation/,
        "A type of attestation the model does not offer"
    );

    refused(
        register( authenticator(), metadata => "metadata" ),
        qr/metadata must be an Authen::WebAuthn::Metadata object/,
        "Metadata that is not an object"
    );
};

subtest "Models the metadata does not list" => sub {
    my $md = with_entry( aaguid => "ffffffff-0506-0708-090a-0b0c0d0e0f10" );
    ok(
        register(
            authenticator(),
            metadata      => $md,
            trust_anchors => [ mds_pem("root.pem") ]
        ),
        "Fall back to trust_anchors"
    );
    refused(
        register( authenticator(), metadata => $md ),
        qr/Could not validate attestation trust/,
        "... without which they fail"
    );
    refused(
        register(
            authenticator(),
            metadata          => $md,
            trust_anchors     => [ mds_pem("root.pem") ],
            metadata_required => 1
        ),
        qr/Authenticator $AAGUID is not in the metadata/,
        "... or are refused with metadata_required"
    );

    my $self_attested = authenticator( certificate => "self" );
    ok( register( $self_attested, metadata => $md, metadata_required => 1 ),
        "Self attestation names no model to look up" )
      or diag($@);
};

subtest "U2F authenticators, by key identifier" => sub {
    my $key    = Crypt::PK::ECC->new( \mds_pem("packed-p256-key.pem") );
    my $key_id = sha1_hex( $key->export_key_raw("public") );
    my $md     = with_entry(
        aaguid                               => undef,
        attestationCertificateKeyIdentifiers => [ uc $key_id ],
        statement => { description => "Test U2F key", protocolFamily => "u2f" },
    );
    my $reg = register(
        authenticator(
            certificate        => "packed-p256",
            attestation_format => "fido-u2f",
            aaguid             => "00000000-0000-0000-0000-000000000000",
        ),
        metadata => $md,
    );
    ok( $reg, "A fido-u2f attestation is found by its key identifier" )
      or diag($@);
    is( $reg && $reg->{metadata}->{description},
        "Test U2F key", "... its entry" );
};

subtest "Statuses" => sub {
    for my $status (
        qw(REVOKED ATTESTATION_KEY_COMPROMISE USER_KEY_REMOTE_COMPROMISE
        USER_KEY_PHYSICAL_COMPROMISE USER_VERIFICATION_BYPASS)
      )
    {
        my $md = with_entry(
            statusReports => [
                { status => "FIDO_CERTIFIED_L1" },
                { status => $status, effectiveDate => "2025-06-01" },
            ]
        );
        refused(
            register( authenticator(), metadata => $md ),
qr/Test authenticator \($AAGUID\) has metadata status $status since 2025-06-01/,
            "$status is refused"
        );
        ok(
            register(
                authenticator(),
                metadata         => $md,
                refused_statuses => []
            ),
            "... unless refused_statuses leaves it out"
        );
    }

    my $later = with_entry( statusReports =>
          [ { status => "REVOKED" }, { status => "FIDO_CERTIFIED" } ] );
    ok( register( authenticator(), metadata => $later ),
        "Only the current status counts" );
    ok(
        register(
            authenticator(),
            metadata => with_entry(
                statusReports => [ { status => "UPDATE_AVAILABLE" } ]
            )
        ),
        "UPDATE_AVAILABLE is accepted"
    );
    refused(
        register(
            authenticator(),
            metadata =>
              with_entry( statusReports => [ { status => "REVOKED" } ] )
        ),
        qr/has metadata status REVOKED$|has metadata status REVOKED at/,
        "A status without a date"
    );

    my $compromised = sub {
        my ($certificate) = @_;
        return with_entry(
            statusReports => [
                {
                    status      => "ATTESTATION_KEY_COMPROMISE",
                    certificate =>
                      encode_base64( mds_der("$certificate.pem"), "" ),
                }
            ]
        );
    };
    refused(
        register(
            authenticator(), metadata => $compromised->("packed-aaguid")
        ),
        qr/has metadata status ATTESTATION_KEY_COMPROMISE/,
        "A compromised attestation key named in the report"
    );
    ok(
        register( authenticator(), metadata => $compromised->("packed-p384") ),
        "... concerns only chains with that certificate"
    );
};

subtest "Out of date metadata" => sub {
    my $stale = metadata( next_update => "2020-01-01" );
    refused(
        register( authenticator(), metadata => $stale ),
qr/Metadata BLOB 7 is out of date: its next update was due by 2020-01-01/,
        "Metadata past its next update"
    );
    refused(
        register(
            authenticator( attestation_format => "none" ),
            metadata => $stale
        ),
        qr/is out of date/,
        "... even for a registration without attestation"
    );
    ok(
        register(
            authenticator(),
            metadata             => $stale,
            allow_stale_metadata => 1
        ),
        "... unless allowed"
    );
    ok(
        register(
            authenticator(),
            metadata            => $stale,
            metadata_grace_days => 100000
        ),
        "... or within the grace given"
    );
    refused(
        register(
            authenticator(),
            metadata            => $stale,
            metadata_grace_days => "a week"
        ),
        qr/metadata_grace_days must be a number of days/,
        "A grace that is not a number of days"
    );

    local $Authen::WebAuthn::SSLeayChainVerifier::verification_time =
      4102531199;
    ok(
        register( authenticator(), metadata => metadata() ),
        "Metadata is current until the end of its nextUpdate day"
    ) or diag($@);
    local $Authen::WebAuthn::SSLeayChainVerifier::verification_time =
      4102531200;
    refused(
        register( authenticator(), metadata => metadata() ),
        qr/is out of date/,
        "... and out of date after it"
    );
};

subtest "Downloading" => sub {
    {

        package FakeHTTP;

        sub new {
            my ( $class, %pages ) = @_;
            bless { pages => \%pages, got => [] }, $class;
        }

        sub get {
            my ( $self, $url ) = @_;
            push @{ $self->{got} }, $url;
            my $page = $self->{pages}->{$url};
            return
              ref $page ? $page
              : defined $page
              ? { success => 1, status => 200, content => $page }
              : { success => 0, status => 404, reason  => "Not Found" };
        }
    }
    my %pages = (
        "https://mds3.fidoalliance.org/" => mds_blob() . "\n",
        "http://mds.test/crl/root.crl"   => mds_pem("mds-root.crl"),
        "http://mds.test/crl/ca.crl"     => mds_pem("mds-ca.crl"),
    );

    my $http = FakeHTTP->new(%pages);
    my $md =
      eval { Authen::WebAuthn::Metadata->fetch( root => $root, http => $http ) };
    ok( $md, "The BLOB and the CRLs of its chain" ) or diag($@);
    ok( $md && $md->crl_checked, "... checked against them" );
    is_deeply(
        $http->{got},
        [
            "https://mds3.fidoalliance.org/", "http://mds.test/crl/ca.crl",
            "http://mds.test/crl/root.crl"
        ],
        "... each fetched once"
    );

    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->fetch(
                root        => $root,
                http        => $http,
                previous_no => 7
            );
        },
        qr/not newer than 7/,
        "A BLOB no newer than the last"
    );
    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->fetch(
                root => $root,
                url  => "https://mds.test/blob",
                http => FakeHTTP->new( %pages, "https://mds.test/blob" => "x" )
            );
        },
        qr{Metadata BLOB from https://mds.test/blob is not a JWT},
        "Something other than a BLOB"
    );
    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->fetch(
                root => $root,
                http => FakeHTTP->new(
                    %pages, "http://mds.test/crl/ca.crl" => undef
                )
            );
        },
        qr{Cannot download http://mds.test/crl/ca.crl: 404 Not Found},
        "A CRL that cannot be downloaded"
    );
    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->fetch(
                root => $root,
                http => FakeHTTP->new(
                    "https://mds3.fidoalliance.org/" => {
                        success => 0,
                        status  => 599,
                        reason  => "Internal Exception",
                        content => "Could not connect"
                    }
                )
            );
        },
qr{Cannot download https://mds3.fidoalliance.org/: 599 Internal Exception: Could not connect},
        "A connection that fails"
    );

    # Port 1 on the loopback refuses connections, without the network
    refused(
        scalar eval {
            Authen::WebAuthn::Metadata->fetch(
                root => $root,
                url  => "http://127.0.0.1:1/"
            );
        },
        qr{Cannot download http://127.0.0.1:1/: 599},
        "With HTTP::Tiny"
    );
};

done_testing();
