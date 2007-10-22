# -*- perl -*-

# t/003_adv.t - checking GROUP and MEMO fields. Sequential access

use strict;
use Test::More tests => 12;
use Clarion;

open F, 'dat/adv.csv';
binmode F;
my $csv=join('', <F>);
close F;

for my $i(1..3)
{
 my $z=new Clarion "dat/adv$i.dat", 1;
 isa_ok ($z, 'Clarion');

 $z=new Clarion "dat/adv$i.dat";
 isa_ok ($z, 'Clarion');

 open F, "dat/adv$i.cla";
 binmode F;
 my $s=join('', <F>);
 close F;
 is($z->file_struct, $s, 'Schema is correct');

 is(getCSV($z), $csv, 'Data read correctly');
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
 while(my @x=$z->get_record())
 {
  next	if shift @x;
  my $ss='';
  foreach my $n(@x)
  {
   $ss.=';'	if length($ss);
   $ss.=$n||'';
  }
  $s.=$ss."\n";
 }
 return $s;
}

__END__
