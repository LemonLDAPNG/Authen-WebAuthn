use Test::More;
use File::Spec;
use strict;

# Runs the tests under valgrind's memcheck, which reports invalid reads,
# writes and frees in the XS code underneath (OpenSSL through Net::SSLeay
# and Crypt::OpenSSL::X509, CryptX, CBOR::XS). Leaks are not checked: Perl
# itself does not free everything at exit.
#
#   prove -l xt/valgrind.t                       # every test in t/
#   prove -l xt/valgrind.t :: t/18-*.t           # some of them

my ($valgrind) =
  grep { -f $_ && -x _ }
  map { File::Spec->catfile( $_, "valgrind" ) } File::Spec->path;
plan skip_all => "valgrind is not installed" unless $valgrind;

my @tests = @ARGV ? @ARGV : sort glob("t/*.t");
my $errors_status = 99;

local $ENV{PERL_DESTRUCT_LEVEL} = 2;

for my $test (@tests) {
    open my $run, "-|", $valgrind, "--tool=memcheck", "--quiet",
      "--leak-check=no", "--error-exitcode=$errors_status", "--log-fd=1",
      $^X, "-Ilib", $test
      or die "Cannot run valgrind: $!";
    my $output = do { local $/; <$run> };
    close $run;
    my $status = $? >> 8;

    my @errors = $output =~ /^(==\d+== \S.*)$/mg;
    if ( $status == $errors_status or @errors ) {
        fail("$test: memory errors");
        diag( join "\n", @errors[ 0 .. ( $#errors < 20 ? $#errors : 20 ) ] );
    }
    elsif ($status) {
        fail("$test: exited with status $status under valgrind");
        diag($output);
    }
    else {
        pass("$test: no memory errors");
    }
}

done_testing();
