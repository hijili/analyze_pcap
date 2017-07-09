package Whois;
use strict;
use warnings;

#use WhoisCache;
#use WhoisData;
use IPNetSimple;

# Usage: Whois::loockup($target)
#   ret: Obj of WhoisData
sub lookup ($) {
	my $target = shift;

	if (WhoisCache::has($target)) {
		return WhoisCache::get_whoisdata($target);
	}

	my $row_data = Whois::_send_query($target);
	if ($row_data) {
		WhoisCache::put($target, $row_data);
		return WhoisCache::get_whoisdata($target);
	}

	return undef;
}

my $COMMAND = "LANG=C whois";

sub _send_query {
	my $target = shift;
	my $raw_data = qx/$COMMAND $target/;
	my $ret = $? << 8;
	if ($ret != 0) {
		my $_raw_data = Whois::_guess_target($target);
		if (defined $_raw_data) {
			return $_raw_data;
		}
		die "may be failed \"$COMMAND $target\". retval=$ret\n\n$raw_data";
		return undef;
	}
	return $raw_data;
}

sub _guess_target {
	my $target = shift;
	my $dummy_raw_data;

	# multicast: 224.0.0.0〜239.255.255.255
	my $target_ip = new IPNetSimple($target);
	if ($target_ip->is_multicast) {
		$dummy_raw_data = "# created by Whois.pm\n";
		$dummy_raw_data = "NetName: multicast addr\n";
	}

	return $dummy_raw_data;
}

1;



package WhoisCache;
use strict;
use warnings;

use File::Path;
#use WhoisData;

my $BASE = "./whois_cache";
my $EXPIRE = 60 * 60 * 24 * 30; # 30days

sub _target_to_path($) {
	my $target = shift;
	my $path = $target;
	$path =~ s/\./\//g; # 10.0.0.1 -> 10/0/0/1
	return $BASE."/".$path;
}

sub has($) {
	my $target = shift;
	my $cache_file = WhoisCache::_target_to_path($target);
	if (! -f $cache_file) {
		return 0; # false
	}
	my $mtime = (stat $cache_file)[9];
	my $limit = time - $EXPIRE;
	if ($mtime < $limit) {
		return 0; # false
	}
	return 1; # true
}

sub get_whoisdata($) {
	my $target = shift;
	my $file = WhoisCache::_target_to_path($target);
	open my $fh, "<", $file or die "cannot open cache file \"$file\": $!";
	my $row_data = do { local $/; <$fh> }; # http://perl-users.jp/articles/advent-calendar/2008/18.html
	close $fh;
	return new WhoisData($target, $row_data);
}

sub put($$) {
	my $target = shift;
	my $data = shift;
	my $file = WhoisCache::_target_to_path($target);

	my $dir = $file;       print "[DEBUG]: file = $file\n";
	$dir =~ s@\/[^\/]+$@@; print "[DEBUG]: dir  = $dir\n";
	if (! -d $dir) {
		mkpath $dir or die "mkpath failed: $!";
	}

	open my $fh, ">", $file or die "cannot open cache file \"$file\": $!";
	print $fh $data;
	close ($fh);
	return;
}

1;


package WhoisData;
use strict;
use warnings;

sub new ($$) {
	my $class = shift;
	my $target = shift;
	my $raw_data = shift;

	my $self = {
		TARGET => $target,
		NAME         => undef,
		ORGANIZATION => undef,
		COUNTRY      => undef,
	};
	bless $self, $class;

	$self->parse($raw_data);
	return $self;
}

# parse whois info...
sub parse($) {
	my $self = shift;
	my $raw_data = shift;

	foreach my $line (split('\n',$raw_data)) {
		if ($line =~ /NetName: *(.+)/i || $line =~ /\[Network Name\] *(.+)/i) {
			$self->{NAME} = $1 if !defined $self->{NAME};
		}
		elsif ($line =~ /Organization: *(.+)/i || $line =~ /\[Organization\] *(.+)/i ||
			  $line =~ /descr: *(.+)/i) {
			$self->{ORGANIZATION} = $1 if !defined $self->{ORGANIZATION};
		}
		elsif ($line =~ /Country: *(.+)/i) {
			$self->{COUNTRY} = $1 if !defined $self->{COUNTRY};
		}
		elsif ($line =~ /JPNIC database provides/) {
			$self->{COUNTRY} = "JP" if !defined $self->{COUNTRY};
		}
	}
}

sub to_string() {
	my $self = shift;
	my $name = defined $self->{NAME} ? $self->{NAME} : "";
	my $org  = defined $self->{ORGANIZATION} ? $self->{ORGANIZATION} : "";
	my $country = defined $self->{COUNTRY} ? $self->{COUNTRY} : "";
	return $name .":". $org . ":". $country;

}

1;
