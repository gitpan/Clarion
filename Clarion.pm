package Clarion;

use 5.006;
use strict;
use warnings;
use Carp;
use FileHandle;

require Exporter;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Clarion ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);
our $VERSION = '1.01';


=head1 NAME

Clarion - Perl extension for reading CLARION data files

=head1 ABSTRACT

This is a perl module to access CLARION 2.1 files.
At the moment only read access to the files are provided by this package.
"Encrypted" files are processed transparently, you do not need to specify the 
password of a file.

=head1 SYNOPSIS

	use Clarion;

	my $dbh=new Clarion "customer.dat";

	print $dbh->file_struct;

	for ( 1 .. $dbh->last_record ) {
    	my $r=$dbh->get_record_hash($_);
		next if $r->{_DELETED};
	    print $r->{CODE}." ".$r->{NAME}." ".$r->{PHONE}."\n";
	}

	$dbh->close();

=head1 DESCRIPTION

The various methods that are supported by this module are given
below.

=head2 METHODS

=over 4

=item $dbh=new Clarion;

=item $dbh=new Clarion "test.dat";

This will create an object $dbh that will be used to interact with the
various methods the module provides. If file name is specified then
associate the DAT file with the object. "Encrypted" files are processed 
transparently, you do not need to specify the password of a file.

=cut

sub new {
    shift;
	my $self={};
	bless $self;
    my $name=shift;
    $self->open($name) if defined($name);
    $self;
}

=item $dbh->open("test.dat");

Associate the DAT file with the object, opens file.

=cut

sub open {
	my ($self,$name)=@_;

	my $fh=new FileHandle $name;
	croak("Can't open $name: $!") if !defined($fh);
    binmode($fh);
	$self->{fh}=$fh;
    $self->{name}=$name;
	read_header($self);
}

sub FILLOCK { 0x01; }	#file is locked
sub FILOWN  { 0x02; }	#file is owned
sub FILCRYP { 0x04; }	#records are encrypted
sub FILMEMO { 0x08; }	#memo file exists
sub FILCOMP { 0x10; }	#file is compressed
sub FILRCLM { 0x20; }	#reclaim deleted records
sub FILREAD { 0x40; }	#file is read only
sub FILCRET { 0x80; }	#file may be created

sub decrypt {
	my ($buf,$addr,$key0,$key1)=@_;

	my $l=length($$buf)-1;
	for my $i ( $addr .. ($l-($l&1)) ) {
		if ( ($i-$addr) & 1) {
			substr($$buf,$i,1)=chr(ord(substr($$buf,$i,1)) ^ $key1);
		} else {
			substr($$buf,$i,1)=chr(ord(substr($$buf,$i,1)) ^ $key0);
		}
	}
}

sub read_header {
	my ($self)=@_;
	my $file_header;
	my ($key0,$key1);

	#read signature & flags
    $self->read_dat(\$file_header,4,0,"header");
    my ($filesig,$sfatr) = unpack("S S",$file_header);
    croak("Not a CLARION datafile") if $filesig != 0x3343;
    $self->{sfatr} = $sfatr;

    #read header
    $self->read_dat(\$file_header,2*9+31+9*4-4,0,"header");
    if ( $sfatr & FILOWN ) {
    	($key1,$key0)=unpack("x7 C C",$file_header);
    	($self->{_key0},$self->{_key1})=($key0,$key1);
    	decrypt(\$file_header,0,$key0,$key1);
    }
	$self->{header}={};
    my @header_fields_names=qw(numbkeys numrecs numdels numflds numpics nummars reclen offset logeof logbof freerec recname memnam filpre recpre memolen memowid reserved chgtime chgdate reserved2);
    my @header_fields_vals=unpack("C L L S S S S L L L L A12 A12 A3 A3 S S L L L S",$file_header);
	for my $i (0..20) {
        $self->{header}{$header_fields_names[$i]}=$header_fields_vals[$i];
	}
    #read field descriptors
    $self->{fields}=[];
    my @fld_desc_fields_names=qw(fldtype fldname foffset length decsig decdec arrnum picnum);
    for ( my $i=0 ; $i<$self->{header}{numflds}; $i++ ) {
        my $fld_desc;
        $self->read_dat(\$fld_desc,3+16+2*4,$sfatr & FILOWN,"field descriptors");
        my @fld_desc_fields_vals=unpack("C A16 S S C C S S",$fld_desc);
        for my $j (0..7) {
            $self->{fields}[$i]{$fld_desc_fields_names[$j]}=$fld_desc_fields_vals[$j];
        }
        $self->{fields}[$i]{_fieldno}=$i;
    }
    #read key descriptors
    $self->{keys}=[];
    my @key_desc_fields_names=qw(numcomps keynams comptype complen);
    my @key_part_fields_names=qw(fldtype fldnum elmoff elmlen);
    for ( my $i=0 ; $i<$self->{header}{numbkeys}; $i++ ) {
        my $key_desc;
        $self->read_dat(\$key_desc,1+16+1+1,$sfatr & FILOWN,"key descriptors");
        my @key_desc_fields_vals=unpack("C A16 C C",$key_desc);
        for my $j (0..3) {
            $self->{keys}[$i]{$key_desc_fields_names[$j]}=$key_desc_fields_vals[$j];
        }
        #read key parts
        $self->{keys}[$i]{parts}=[];
        for ( my $k=0 ; $k<$self->{keys}[$i]{numcomps}; $k++ ) {
            $self->{keys}[$i]{parts}[$k]={};
            my $key_part;
            $self->read_dat(\$key_part,1+2+2+1,$self->{sfatr} & FILOWN,"key parts");
            my @key_part_fields_vals=unpack("C S S C",$key_part);
            for my $j (0..3) {
                $self->{keys}[$i]{parts}[$k]{$key_part_fields_names[$j]}=$key_part_fields_vals[$j];
            }
        }
    }
    #build record unpack template
    my $tpl="C L";
    $self->{field_map}={};
    for my $f ( @{$self->{fields}} ) {
        if ( $f->{fldtype}==1 ) {
            $tpl.=" l";
        } elsif ( $f->{fldtype}==2) {
            $tpl.=" d";
        } elsif ( $f->{fldtype}==3 || $f->{fldtype}==4 ) {
            $tpl.=sprintf(" A%d",$f->{length});
        } elsif ( $f->{fldtype}==5) {
            $tpl.=" C";
        } elsif ( $f->{fldtype}==6) {
            $tpl.=" s";
        } elsif ( $f->{fldtype}==7) {
            $tpl.=sprintf(" a%d",$f->{length});
        } elsif ( $f->{fldtype}==8) {
            $tpl.=sprintf(" a%d",$f->{length});
            $self->{decimal_fields}=[] if !exists($self->{decimal_fields});
            push @{$self->{decimal_fields}},$f;
        } else {
            #?
            $tpl.=sprintf(" a%d",$f->{length});
        }
        #and field map
        my $fldname=$f->{fldname};
        $fldname=~s/^.+://;
        $self->{field_map}{$fldname}=$f->{_fieldno};
    }
    $self->{record_template}=$tpl;
}

sub read_record {
    my ($self,$recno)=@_;

    return undef if $recno<1 or $recno>$self->{header}{numrecs};
    seek($self->{fh},
        $self->{header}{offset}+$self->{header}{reclen}*($recno-1),
        0);
    my $rec_buf;
    $self->read_dat(\$rec_buf, $self->{header}{reclen}, 0,"record");
	if ( $self->{sfatr} & FILCRYP ) {
    	decrypt(\$rec_buf,5,$self->{_key0},$self->{_key1});
	}
    my $data=[unpack($self->{record_template},$rec_buf)];
    if ( exists($self->{decimal_fields}) ) {
        for my $f ( @{$self->{decimal_fields}} ) {
            $data->[$f->{_fieldno}+2]=unpack_bcd($data->[$f->{_fieldno}+2],$f->{decsig},$f->{decdec});
        }
    }
    $self->{data}=$data;
}

=item @r=$dbh->get_record($_,@fields);

=item @r=$dbh->get_record($_);

Returns a list of data (field values) from the specified record.
The first parameter in the call is the number of the physical
record. If you do not specify any other parameters, all fields are
returned in the same order as they appear in the file. You can also
put list of field names after the record number and then only those
will be returned. The first value of the returned list is always the
logical (0 or not 0) value saying whether the record is deleted or not.

=cut

sub get_record {
	my ($self,$recno,@fields)=@_;

    $self->read_record($recno);
    @fields=sort {$self->{field_map}{$a}<=>$self->{field_map}{$b}} keys %{$self->{field_map}} if !@fields;
    return $self->{data}[0]&0x10,map($self->{data}[$self->{field_map}{$_}+2],@fields);
}

=item $r=$dbh->get_record_hash;

Returns reference to hash containing field values indexed by field names. 
The name of the deleted flag is C<_DELETED>. The first parameter in the call 
is the number of the physical record. If you do not specify any other 
parameters, all fields are returned. You can also put list of field names 
after the record number and then only those will be returned.

=cut

sub get_record_hash {
	my ($self,$recno,@fields)=@_;

    $self->read_record($recno);
    @fields=sort {$self->{field_map}{$a}<=>$self->{field_map}{$b}} keys %{$self->{field_map}} if !@fields;
    my $res={};
    %$res=map(($_,$self->{data}[$self->{field_map}{$_}+2]),@fields);
    $res->{_DELETED}=$self->{data}[0]&0x10,
    return $res;
}

=item $n=$dbh->last_record;

Returns the number of recods in the database file.

=cut

sub last_record {
    shift->{header}{numrecs};
}

=item $n=$dbh->bof;

Returns the physical number of first logical record.

=cut

sub bof {
    shift->{header}{logbof};
}

=item $n=$dbh->eof;

Returns the physical number of last logical record.

=cut

sub eof {
    shift->{header}{logeof};
}

=item $dbh->close;

This closes the database file that are associated with the $dbh.

=cut

sub close {
    my $self=shift;

	if ( $self->{fh} ) {
	    $self->{fh}->close();
		$self->{fh}=0;
	}
}

sub DESTROY {
	shift->close;
}


sub unpack_bcd {
    my ($val,$decsig,$decdec)=@_;
	my $res='';
	my $n=$decsig+$decdec+1;
    for my $i ( 0 .. int(($n+1)/2)-1 ) {
		my $b=ord(substr($val,$i,1));
        $res.=chr((($b>>4)&0xf)+ord('0'));
		last if --$n == 0;
       	$res.=chr(($b&0xf)+ord('0'));
		--$n;
    }

	my $sign;
	if ( substr($res,0,1) ne '0' ) {
		$sign='-';
	} else {
		$sign='';
	}
	my $sig=substr($res,1,$decsig);
	my $dec=substr($res,$decsig+1,$decdec);

	if ( $sig == 0 ) {
		$sig='0';
	} else {
		$sig=~s/^0+//;
	}
	if ( $decdec > 0 ) {
		if ( $dec == 0 ) {
			$dec='';
		} else {
			$dec=~s/0+$//;
			$dec='.'.$dec;
		}
	}
    return $sign.$sig.$dec;
}

sub read_dat {
	my ($self,$buf,$bytes,$decrypt,$what)=@_;

	my $pos=tell($self->{fh});
    my $rc=read($self->{fh},$$buf,$bytes);
    croak("Error reading file ($what) ($rc<>$bytes)") if $rc!=$bytes;
    if ( $decrypt ) {
    	decrypt($buf,0,$self->{_key0},$self->{_key1});
    }
}

=item $struct = $dbh->file_struct;

This returns CLARION file structure.

=cut

sub file_struct {
	my ($self)=@_;
	my $res;

	my $label=$self->{name};
	$label=~s/\.dat//i;
	$label=~s/^.+[\/\\]//;
	$label=uc($label);

	my $options;
	$options.=",OWNER('???')" if $self->{sfatr} & FILOWN;
	$options.=",ENCRYPT" if $self->{sfatr} & FILCRYP;
	$options.=",CREATE" if $self->{sfatr} & FILCRET;
	$options.=",RECLAIM" if $self->{sfatr} & FILRCLM;
	$options.=",PROTECT" if $self->{sfatr} & FILREAD;

	$res=<<EOT;
$label\tFILE,NAME('$label'),PRE('$self->{header}{filpre}')$options
$self->{header}{recname}\tRECORD
EOT
	for my $f ( @{$self->{fields}} ) {
		my $name=$f->{fldname};
		$name=~s/^[^:]+://;
        if ( $f->{fldtype}==1 ) {
            $res.="$name\tLONG\n";
        } elsif ( $f->{fldtype}==2) {
            $res.="$name\tREAL\n";
        } elsif ( $f->{fldtype}==3 || $f->{fldtype}==4 ) {
            $res.="$name\tSTRING($f->{length})\n";
        } elsif ( $f->{fldtype}==5) {
            $res.="$name\tBYTE\n";
        } elsif ( $f->{fldtype}==6) {
            $res.="$name\tSHORT\n";
        } elsif ( $f->{fldtype}==7) {
            $res.="$name\tSTRING($f->{length})\t!GROUP\n";
        } elsif ( $f->{fldtype}==8) {
            $res.=sprintf("%s\tDECIMAL(%d,%d)\n",$name,$f->{decsig}+$f->{decdec},$f->{decdec});
        } else {
            $res.="!$name\tUNKNOWN TYPE\n";
        }
	}
	$res.="\t. .\n";

	return $res;
}

1;
__END__

=back

=head2 EXPORT

None.

=head1 AUTHOR

Ilya Chelpanov <ilya@macro.ru>
http://i72.narod.ru, http://i72.by.ru

=head1 SEE ALSO

Clarion data files and indexes description at http://i72.by.ru.

=cut
