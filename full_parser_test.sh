#!/usr/bin/perl

use IO::File;
use strict;

my $fh;# = IO::File->new('< string_test1.txt');
open($fh, "< string_test1.txt");
my $a = `dir`;
#print $a;
#warn $a;
while (<$fh>) {
    #chomp $_;
    print 'exec command with ' . '"' . $_ . '"';
    my $a = system("./main \"$_\"");
    print $a;
}
