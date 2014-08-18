#!/usr/bin/perl

use IO::File;
use strict;

my $fh;# = IO::File->new('< string_test1.txt');
open($fh, "< string_test1.txt");
my $a = `dir`;
#print $a;
#warn $a;
while (<$fh>) {
    print 'exec command with ' . $_;
    my $a = `./main $_`;
    print $a;
}
