# -*- perl -*-

# t/002_simple.t - basic reading of .dat-files. Random access

use strict;
use Test::More tests => 9;
use Clarion;

open F, 'dat/test.csv';
binmode F;
my $csv=join('', <F>);
close F;

for my $i(1..3)
{
 my $z=new Clarion "dat/test$i.dat";
 isa_ok ($z, 'Clarion');

 open F, "dat/test$i.cla";
 binmode F;
 my $s=join('', <F>);
 close F;
 is($z->file_struct, $s, 'Schema is correct');

 is(getCSV($z), $csv, "Data read correctly");
}

sub getCSV
{
 my $z=shift;
 my $s='';
 foreach my $f(@{$z->{fields}})
 {
  $s.=';'	if length($s);
  $s.=$f->{Name};
 }
 $s.="\n";
 for my $i(1 .. $z->last_record)
 {
  my @x=$z->get_record($i);
  next	if shift @x;
  my $ss='';
  foreach my $n(@x)
  {
   $ss.=';'	if length($ss);
   $ss.=$n;
  }
  $s.=$ss."\n";
 }
 return $s;
}

__END__
