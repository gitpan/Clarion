# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

use Test;
BEGIN { plan tests => 9 };
use Clarion;
use Data::Dumper;
use File::Compare;
ok(1); # If we made it this far, we're ok.

#########################

# Insert your test code below, the Test module is use()ed here so read
# its man page ( perldoc Test ) for help writing this test script.

my $dbh=new Clarion "dat/test.dat";
ok(1);

open(F,">dat/struct.txt") || die($!);
binmode(F);
print F $dbh->file_struct;
close(F);
ok(1);
ok(compare("dat/struct.txt","dat/test.str")==0);

open(F,">dat/test.txt") || die($!);
for ( $dbh->bof .. $dbh->eof ) {
    my @r=$dbh->get_record($_);
    print F join(":",@r)."\n";
}
close(F);
$dbh->close();
ok(1);

$dbh=new Clarion "dat/test1.dat";
open(F,">dat/test1.txt") || die($!);
for ( $dbh->bof .. $dbh->eof ) {
    my @r=$dbh->get_record($_);
    print F join(":",@r)."\n";
}
close(F);
$dbh->close();
ok(1);

$dbh=new Clarion "dat/test2.dat";
open(F,">dat/test2.txt") || die($!);
for ( $dbh->bof .. $dbh->eof ) {
    my @r=$dbh->get_record($_);
    print F join(":",@r)."\n";
}
close(F);
$dbh->close();
ok(1);

ok(compare("dat/test.txt","dat/test1.txt")==0);

ok(compare("dat/test.txt","dat/test2.txt")==0);
