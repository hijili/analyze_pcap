#!/usr/bin/perl
use strict;
use warnings;

use Data::Dumper;
use Whois;
#use HostData;
use IPNetSimple;

my $pcap_file = $ARGV[0];
if (! defined $pcap_file || ! -f $pcap_file) {
	die "file \"$pcap_file\" does not exist!";
}

my $self_ip = "192.168.11.2";

my $ALL = {}; # "host -> HostData"

my $cmd = "tcpdump -nn -r $pcap_file";
open my $fh, "-|", $cmd or die "cannot exec $cmd: $!";
while (defined(my $line = <$fh>)) {
	my ($src_host_and_port, $dst_host_and_port);
	my ($shost, $stype, $dhost, $dtype, $length); # typeは ICMPかポート番号、とりえあずね
	my $id;

	#print "[DEBUG] $line";

	if ($line =~ /: ICMP /) {
		if ($line =~ / ([^ ]+) > ([^ ]+): .*length (\d+)/) {
			$shost = $1; $stype = "ICMP";
			$dhost = $2; $dtype = "ICMP";
			$length = $3;
		} else {
			die "unknown ICMP packet... : $line";
		}
	}
	elsif ($line =~ /: igmp /) {
		if ($line =~ / ([^ ]+) > ([^ ]+): /) {
			$shost = $1; $stype = "igmp";
			$dhost = $2; $dtype = "igmp";
			$length = 0;
		} else {
			die "unknown igmp packet... : $line";
		}
	}
	elsif ($line =~ / ARP, /) {
		print STDERR "[WARN] ignore arp $line";
		next;
	}
	elsif ($line =~ / IP6 /) {
		print STDERR "[WARN] ignore ipv6 $line";
		next;
	}
	# 20:50:18.946252 IP 192.168.11.2.52725 > 192.168.11.1.53: 50853+ A? www.evernote.com. (34)
	elsif ($line =~ / ([^ ]+) > ([^ ]+): /) {
		$src_host_and_port = $1;
		$dst_host_and_port = $2;
		if ($src_host_and_port =~ /(.+)\.([^\.]+)$/) {
			$shost = $1; $stype = $2;
		}
		if ($dst_host_and_port =~ /(.+)\.([^\.]+)$/) {
			$dhost = $1; $dtype = $2;
		}

		if ($line =~ / length (\d+)/) {
			$length = $1;
		}
		elsif ($line =~ / \((\d+)\) *$/) {
			$length = $1;
		}
		elsif ($line =~ /NBT UDP PACKET/) {
			$length = 0;
		}
	} else {
		die "unexpected line: $line";
	}


	if (!defined $dhost || !defined $shost || !defined $dtype || !defined $stype || !defined $length) {
		die "unexpected parse: dhost=$dhost shost=$shost dtype=$dtype stype=$stype length=$length for line:$line";
	}

	# send
	if ($shost eq $self_ip) {
		$id = $dhost.":".$dtype;
		if (! defined $ALL->{$id} ) {
			$ALL->{$id} = new HostData($id, $dhost, $dtype);
		}
		$ALL->{$id}->add_send_count;
		$ALL->{$id}->add_length($length);
	}
	# recv
	elsif ($dhost eq $self_ip) {
		$id = $shost.":".$stype;
		if (! defined $ALL->{$id} ) {
			$ALL->{$id} = new HostData($id, $shost, $stype);
		}
		$ALL->{$id}->add_recv_count;
		$ALL->{$id}->add_length($length);
	}
	# multicast
	elsif (IPNetSimple->new($dhost)->is_multicast) {
		$id = $shost.":multi_".$dtype;
		if (! defined $ALL->{$id} ) {
			$ALL->{$id} = new HostData($id, $shost, "multi->".$dtype);
		}
		$ALL->{$id}->add_recv_count;
		$ALL->{$id}->add_length($length);
	}
	else {
		die "unkown line: $line";
	}
}
close($fh);

foreach my $host_id (sort keys %{$ALL}) {
	my $hostdata = $ALL->{$host_id};
	print $hostdata->to_string."\n";
}
#print Dumper $ALL;

exit 0;


# key: {host}.{port} tcpdumpのまま
package HostData;
use Whois;

sub new ($$$) {
	my $class = shift;
	my $self = {
		ID => shift,
		HOST => shift,
		TYPE => shift, # ICMP, ARP, port
		SEND_COUNT => 0,
		RECV_COUNT => 0,
		LENGTH => 0,

		WHOIS => "",
	   };
	bless $self, $class;

	$self->whois(Whois::lookup($self->host));
	return $self;
}

sub id {
	my $self = shift;
	return $self->{ID};
}
sub host {
	my $self = shift;
	if (@_) { $self->{HOST} = shift; }
	return $self->{HOST};
}
sub type {
	my $self = shift;
	if (@_) { $self->{TYPE} = shift; }
	return $self->{TYPE};
}

sub send_count {
	my $self = shift;
	return $self->{SEND_COUNT};
}
sub recv_count {
	my $self = shift;
	return $self->{RECV_COUNT};
}
sub add_send_count {
	my $self = shift;
	return ++($self->{SEND_COUNT});
}
sub add_recv_count {
	my $self = shift;
	return ++($self->{RECV_COUNT});
}

sub length {
	my $self = shift;
	return $self->{LENGTH};
}
sub add_length {
	my $self = shift;
	if (@_) { $self->{LENGTH} += shift; }
	return $self->{LENGTH};
}

sub whois() {
	my $self = shift;
	if (@_) { $self->{WHOIS} = shift; }
	return $self->{WHOIS};
}

sub to_string() {
	my $self = shift;
	return $self->id." recv:".$self->recv_count." send:".$self->send_count. " length:".$self->length.
		" whois:". (defined $self->whois ? $self->whois->to_string : "undef");
}

1;
