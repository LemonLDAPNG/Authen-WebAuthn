package Authen::WebAuthn::SSLeayChainVerifier;

use warnings;
use strict;

# VERSION
use Net::SSLeay 1.88;
Net::SSLeay::initialize();

our $verification_time;

# From OpenSSL's x509_vfy.h; Net::SSLeay does not export them
my $X509_V_FLAG_CRL_CHECK     = 0x4;
my $X509_V_FLAG_CRL_CHECK_ALL = 0x8;

# Parse PEM data into a X509 structure
# The returned structure must be freed
sub getX509 {
    my ( $data, $is_pem ) = @_;

    my $method = Net::SSLeay::BIO_s_mem();
    die "Could not resolve BIO_s_mem" unless $method;
    my $bio = Net::SSLeay::BIO_new($method);
    if ($bio) {
        my $rv = Net::SSLeay::BIO_write( $bio, $data );
        if ( $rv > 0 ) {
            my $x509;
            if ($is_pem) {
                $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
            }
            else {
                $x509 = Net::SSLeay::d2i_X509_bio($bio);

                # d2i reads one certificate and ignores what follows it
                if ( $x509 != 0 and Net::SSLeay::BIO_pending($bio) > 0 ) {
                    Net::SSLeay::X509_free($x509);
                    Net::SSLeay::BIO_free($bio);
                    die "Trailing bytes after certificate";
                }
            }
            Net::SSLeay::BIO_free($bio);

            if ( $x509 != 0 ) {
                return $x509;
            }
            else {
                my $error =
                  Net::SSLeay::ERR_error_string( Net::SSLeay::ERR_get_error() );
                Net::SSLeay::ERR_clear_error();
                die "Could not parse certificate: $error";
            }
        }
        else {
            Net::SSLeay::BIO_free($bio);
            die "Could not copy certificate to BIO";
        }
    }
    else {
        die "Could not allocate new BIO" unless $bio;
    }

}

# Create a trust store and populate it with the provided list
# The return value must be freed by the caller
sub _get_trust_store {
    my @x509_list = @_;

    my $x509_store = Net::SSLeay::X509_STORE_new();
    if ( $x509_store != 0 ) {
        for my $x509 (@x509_list) {
            my $rv = Net::SSLeay::X509_STORE_add_cert( $x509_store, $x509 );

            if ( $rv == 0 ) {
                Net::SSLeay::X509_STORE_free($x509_store);
                die "Could not add certificate to store";
            }
        }

        if ($verification_time) {
            my $pm = Net::SSLeay::X509_VERIFY_PARAM_new();
            Net::SSLeay::X509_VERIFY_PARAM_set_time( $pm, $verification_time );
            Net::SSLeay::X509_STORE_set1_param( $x509_store, $pm );
            Net::SSLeay::X509_VERIFY_PARAM_free($pm);
        }

        return $x509_store;

    }
    else {
        die "Could not allocate new trust store";
    }
}

# The result must be freed with _free_x509_list
sub _get_x509_list {
    my ( $list, $is_pem ) = @_;

    my @result;

    for my $pem (@$list) {
        my $x509 = eval { getX509( $pem, $is_pem ) };

        if ($@) {

            # Release already allocated list
            _free_x509_list(@result);
            die $@;
        }
        push @result, $x509;
    }
    return @result;
}

sub _free_x509_list {
    my (@list) = @_;
    Net::SSLeay::X509_free($_) for @list;
}

sub _get_stack {
    my @x509_list = @_;

    my $stack = Net::SSLeay::sk_X509_new_null();
    if ($stack) {
        for my $x509 (@x509_list) {
            my $rv = Net::SSLeay::sk_X509_push( $stack, $x509 );
            if ( $rv == 0 ) {
                Net::SSLeay::sk_X509_free($stack);
                die "Could not add certificate to stack";
            }
        }
        return $stack;
    }
    else {
        die "Cannot allocate X509 stack";
    }
}

sub _get_context {
    my ( $trust_store, $to_verify, $chain ) = @_;

    my $x509_store_ctx = Net::SSLeay::X509_STORE_CTX_new;
    if ( $x509_store_ctx != 0 ) {
        my $rv =
          Net::SSLeay::X509_STORE_CTX_init( $x509_store_ctx, $trust_store,
            $to_verify, $chain );

        # Old versions of Net::SSLeay don't provide a return code
        if ( $Net::SSLeay::VERSION < '1.91' ) {
            $rv = 1;
        }

        if ( $rv != 0 ) {
            return $x509_store_ctx;
        }
        else {
            Net::SSLeay::X509_STORE_CTX_free($x509_store_ctx);
            die "Cannot initialize X509 store context";
        }
    }
    else {
        die "Cannot allocate X509 store context";
    }
}

# Parse a DER CRL; the returned structure must be freed
sub _get_crl {
    my ($der) = @_;

    my $bio = Net::SSLeay::BIO_new( Net::SSLeay::BIO_s_mem() )
      or die "Could not allocate new BIO";
    Net::SSLeay::BIO_write( $bio, $der );
    my $crl      = Net::SSLeay::d2i_X509_CRL_bio($bio);
    my $trailing = $crl && Net::SSLeay::BIO_pending($bio) > 0;
    Net::SSLeay::BIO_free($bio);
    Net::SSLeay::X509_CRL_free($crl) if $trailing;
    die "Could not parse CRL" unless $crl and !$trailing;
    return $crl;
}

# With CRLs, every certificate of the chain must have one, from its issuer,
# that does not list it
sub _add_crls {
    my ( $trust_store, $crl_list ) = @_;

    for my $der (@$crl_list) {
        my $crl = _get_crl($der);
        my $rv  = Net::SSLeay::X509_STORE_add_crl( $trust_store, $crl );
        Net::SSLeay::X509_CRL_free($crl);
        die "Could not add CRL to store" if $rv == 0;
    }
    Net::SSLeay::X509_STORE_set_flags( $trust_store,
        $X509_V_FLAG_CRL_CHECK | $X509_V_FLAG_CRL_CHECK_ALL );
    return;
}

sub verify_chain {
    my ( $trusted_list, $target, $untrusted_list, $crl_list ) = @_;

    my ( $to_verify, @trusted, @untrusted, $trust_store, $chain, $context );
    my $result = { result => 0 };

    # Catch any dies so we can deallocate resources used by this function
    eval {

        # Allocations are made here
        $to_verify   = getX509($target);
        @trusted     = _get_x509_list( $trusted_list, 1 );
        @untrusted   = _get_x509_list($untrusted_list);
        $trust_store = _get_trust_store(@trusted);
        _add_crls( $trust_store, $crl_list ) if $crl_list;
        $chain   = _get_stack(@untrusted);
        $context = _get_context( $trust_store, $to_verify, $chain );

        my $rv    = Net::SSLeay::X509_verify_cert($context);
        my $error = Net::SSLeay::X509_STORE_CTX_get_error($context);
        Net::SSLeay::ERR_clear_error();
        if ( $rv == 1 ) {
            $result = { result => 1 };
        }
        else {
            die( "Could not verify X.509 chain: "
                  . Net::SSLeay::X509_verify_cert_error_string($error) );
        }
    };
    my $eval_result = $@;

    # Deallocate everything we used
    Net::SSLeay::X509_free($to_verify)         if $to_verify;
    _free_x509_list(@trusted)                  if @trusted;
    _free_x509_list(@untrusted)                if @untrusted;
    Net::SSLeay::X509_STORE_free($trust_store) if $trust_store;
    Net::SSLeay::sk_X509_free($chain)          if $chain;
    Net::SSLeay::X509_STORE_CTX_free($context) if $context;

    if ($eval_result) {
        return { result => 0, message => "$eval_result" };
    }
    return $result;

}

1;

__END__

=head1 NAME

Authen::WebAuthn::SSLeayChainVerifier - Verify attestation certificate chains

=head1 DESCRIPTION

This module is internal to L<Authen::WebAuthn>, which uses it to check an
attestation certificate chain against the trust anchors given to
C<validate_registration>. Its interface may change in any release.

=for Pod::Coverage getX509 verify_chain

=cut
