package IPNetSimple;
use strict;
use warnings;

# arg1: ip_address, arg2: netmask (default is 255.255.255.255)
sub new ($$) {
	my $class = shift;
	my $self = {
		ip_address         => shift,
		netmask            => shift, # format: 255.255.255.0
		network_address    => undef,
		broadcast_address  => undef,
	};
	bless $self, $class;

	unless ( $self->_validate_address($self->{ip_address}) ) {
		die("invalid ip address: $self->{ip_address}");
	}
	if (!defined $self->{netmask}) { $self->{netmask} = "255.255.255.255"; }
	unless ( $self->_validate_address($self->{netmask}) ) {
		die("invalid netmask: $self->{netmask}");
	}

	$self->_init;

	return $self;
}

sub _init {
	my $self = shift;

	my @ip_octets = split(/\./, $self->{ip_address});
	my $ip_address_bin = unpack("N", pack("C4", @ip_octets));
	my @mask_octets = split(/\./, $self->{netmask});
	my $netmask_bin = unpack("N", pack("C4", @mask_octets));

	my $network_address_bin = $ip_address_bin & $netmask_bin;
	my @network_address_octets = unpack("C4", pack("N", $network_address_bin));
	$self->{network_address} = join(".", @network_address_octets);

	my $broadcast_address_bin = ($ip_address_bin & $netmask_bin) + (~ $netmask_bin);
	my @broadcast_address_octets = unpack("C4", pack("N", $broadcast_address_bin)) ;
	$self->{broadcast_address} = join(".", @broadcast_address_octets);
}

sub _validate_address ($) {
	my $self    = shift;
	my $address = shift;

	if ($address !~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/) {
		return 0;
	}
	my @octets = ($address =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	foreach my $octet (@octets) {
		if ($octet < 0 || $octet > 255) {
			return 0;
					}
	}
	return 1;
}

sub ip_address() {
	my $self = shift;
	return $self->{ip_address};
}
sub netmask() {
	my $self = shift;
	return $self->{netmask};
}
sub network_address() {
	my $self = shift;
	return $self->{network_address};
}
sub broadcast_address() {
	my $self = shift;
	return $self->{broadcast_address};
}

sub prefix() {
	my $self = shift;
	my @mask_octets = split(/\./, $self->netmask);
	my $netmask_bin = unpack("N", pack("C4", @mask_octets));
	#print "[DEBUG] netmask=".$self->netmask."\n";
	#print "[DEBUG] netmask_bin=$netmask_bin\n";
	#print "[DEBUG] ".sprintf("%032b",$netmask_bin)."\n";
	sprintf("%032b",$netmask_bin) =~ /^(1*)/g; # 先頭の1の数 XXX: もっと簡単にできる?
	my $count = length($1);
	return $count;
}

sub is_multicast($) {
	my $self = shift;
	# 224.0.0.0〜239.255.255.255
	my $multicast = new IPNetSimple("224.0.0.0","240.0.0.0");
	return $multicast->contains_in_subnet($self->ip_address);
}

sub contains_in_subnet ($) {
	my $self = shift;
	my $target_ip_address = shift;

	my @target_ip_octets = split(/\./, $target_ip_address);
	my $target_ip_address_bin = unpack("N", pack("C4", @target_ip_octets));

	# self
	my @ip_octets = split(/\./, $self->ip_address);
	my $ip_address_bin = unpack("N", pack("C4", @ip_octets));
	my @mask_octets = split(/\./, $self->netmask);
	my $netmask_bin = unpack("N", pack("C4", @mask_octets));

	# print "[DEBUG] target_ip_address: $target_ip_address\n";
	# print "[DEBUG]      self netmask: $self->{netmask}\n";
	# printf "[DEBUG] target_ip_address_bin: %032b\n", $target_ip_address_bin;
	# printf "[DEBUG]        ip_address_bin: %032b\n", $ip_address_bin;
	# printf "[DEBUG]           netmask_bin: %032b\n", $netmask_bin;
	if (($target_ip_address_bin & $netmask_bin) == ($ip_address_bin & $netmask_bin)) {
		return 1; # contain
	}
	return 0;
}

# ip_addressとnetmaskの組み合わせがネットワークアドレスかホストアドレスを明確に表すかを判定する
# 10.0.0.1/24  ... 曖昧 ret=1
# 10.0.0.0/24  ... ネットワークアドレスを指すので曖昧でない ret=0
sub is_ambiguous_address() {
	my $self = shift;

	my @ip_octets = split(/\./, $self->ip_address);
	my $ip_address_bin = unpack("N", pack("C4", @ip_octets));
	my @mask_octets = split(/\./, $self->netmask);
	my $netmask_bin = unpack("N", pack("C4", @mask_octets));

	if ( ($ip_address_bin & (~ $netmask_bin)) == 0 ) {
		return 0;
	}
	return 1;
}

sub to_string() {
	my $self = shift;
	return $self->ip_address."/".$self->netmask;
}

1;
