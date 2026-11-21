use Test::More;
use Crypt::OpenSSL::X509;
use Net::SSLeay;
use strict;

use Authen::WebAuthn::SSLeayChainVerifier;

# Each OpenSSL call the verifier makes can fail. Make one fail at a time and
# check that the verifier reports it, and that verification still works
# afterwards (a double free would usually crash here).

sub pem {
    my ($name) = @_;
    open my $fh, '<', "t/pki/$name.pem" or die "t/pki/$name.pem: $!";
    local $/;
    return <$fh>;
}

sub der {
    return Crypt::OpenSSL::X509->new_from_string( pem(shift) )
      ->as_string(Crypt::OpenSSL::X509::FORMAT_ASN1);
}

my @chain = ( [ pem("root") ], der("packed-chained"), [ der("intermediate") ] );

sub verify {
    return Authen::WebAuthn::SSLeayChainVerifier::verify_chain(@chain);
}

is_deeply( verify(), { result => 1 }, "The chain verifies" );

my %failures = (
    BIO_s_mem           => qr/Could not resolve BIO_s_mem/,
    BIO_new             => qr/Could not allocate new BIO/,
    BIO_write           => qr/Could not copy certificate to BIO/,
    X509_STORE_new      => qr/Could not allocate new trust store/,
    X509_STORE_add_cert => qr/Could not add certificate to store/,
    sk_X509_new_null    => qr/Cannot allocate X509 stack/,
    sk_X509_push        => qr/Could not add certificate to stack/,
    X509_STORE_CTX_new  => qr/Cannot allocate X509 store context/,
    X509_STORE_CTX_init => qr/Cannot initialize X509 store context/,
);

for my $function ( sort keys %failures ) {
    my $result = do {
        no strict 'refs';
        no warnings 'redefine';
        local *{"Net::SSLeay::$function"} = sub { 0 };
        verify();
    };
    is( $result->{result}, 0, "$function failing fails verification" );
    like( $result->{message}, $failures{$function}, "... and says why" );
    is_deeply( verify(), { result => 1 }, "... and verification recovers" );
}

# Net::SSLeay before 1.91 returns nothing from X509_STORE_CTX_init
{
    local $Net::SSLeay::VERSION = '1.90';
    is_deeply(
        verify(),
        { result => 1 },
        "The chain verifies with an older Net::SSLeay"
    );
}

done_testing();
