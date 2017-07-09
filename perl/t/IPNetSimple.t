#! /usr/bin/perl
# -*- coding: utf-8 -*-
use strict;
use warnings;
use Test::More;

use lib qw|../|;
use IPNetSimple;

my $ipcalc = new IPNetSimple("10.0.0.1", "255.255.255.0");
ok ($ipcalc->ip_address        eq "10.0.0.1",      "ip address output");
ok ($ipcalc->netmask           eq "255.255.255.0", "netmask output");
ok ($ipcalc->network_address   eq "10.0.0.0", "network_address output");
ok ($ipcalc->broadcast_address eq "10.0.0.255", "broadcast_address output");
ok ($ipcalc->prefix eq "24", "prefix output");
ok ($ipcalc->contains_in_subnet("10.0.0.100"), "contains_in_subnet is true");
ok (!$ipcalc->contains_in_subnet("100.0.0.100"), "contains_in_subnet is false for 10.0.0.1/24");
ok (!$ipcalc->contains_in_subnet("10.100.0.100"), "contains_in_subnet is false for 10.0.0.1/24");
ok (!$ipcalc->contains_in_subnet("10.0.100.100"), "contains_in_subnet is false for 10.0.0.1/24");
ok ($ipcalc->is_ambiguous_address, $ipcalc->to_string." is_ambiguous_address");
ok (!$ipcalc->is_multicast, $ipcalc->to_string." is not multicaset address");

$ipcalc = new IPNetSimple("192.255.0.129", "255.255.255.128");
ok ($ipcalc->ip_address        eq "192.255.0.129",      "ip address output");
ok ($ipcalc->netmask           eq "255.255.255.128", "netmask output");
ok ($ipcalc->network_address   eq "192.255.0.128", "network_address output");
ok ($ipcalc->broadcast_address eq "192.255.0.255", "broadcast_address output");
ok ($ipcalc->prefix eq "25", "prefix output");
ok ($ipcalc->contains_in_subnet("192.255.0.130"), "contains_in_subnet is true");
ok ($ipcalc->contains_in_subnet("192.255.0.228"), "contains_in_subnet is true");
ok (!$ipcalc->contains_in_subnet("192.255.0.0"), "contains_in_subnet is false");
ok (!$ipcalc->contains_in_subnet("192.255.0.1"), "contains_in_subnet is false");
ok (!$ipcalc->contains_in_subnet("192.255.0.127"), "contains_in_subnet is false");
ok ($ipcalc->is_ambiguous_address, "is_ambiguous_address");

$ipcalc = new IPNetSimple("192.255.0.0", "255.255.255.0");
ok (!$ipcalc->is_ambiguous_address, "is_ambiguous_address is false");
ok ($ipcalc->prefix eq "24", "prefix output");
$ipcalc = new IPNetSimple("192.255.0.0", "255.255.0.0");
ok (!$ipcalc->is_ambiguous_address, "is_ambiguous_address is false");
ok ($ipcalc->prefix eq "16", "prefix output");
$ipcalc = new IPNetSimple("192.128.0.0", "255.192.0.0");
ok (!$ipcalc->is_ambiguous_address, "is_ambiguous_address is false");
ok ($ipcalc->prefix eq "10", "prefix output");
$ipcalc = new IPNetSimple("192.128.0.0", "255.0.0.0");
ok ($ipcalc->is_ambiguous_address, "is_ambiguous_address");
ok ($ipcalc->prefix eq "8", "prefix output");

for (my $octet = 224; $octet <= 239; $octet++) {
	$ipcalc = new IPNetSimple($octet.".255.0.0");
	ok ($ipcalc->is_multicast, $ipcalc->to_string." is multicast address");
}
$ipcalc = new IPNetSimple("240.255.0.0");
ok (!$ipcalc->is_multicast, $ipcalc->to_string." is not multicast address");

done_testing();
