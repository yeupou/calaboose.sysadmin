#
# FILE DISCONTINUED HERE
# UPDATED VERSION AT
#         https://gitlab.com/yeupou/calaboose.sysadmin/raw/master/websysadmin-update.pl
#
#                                 |     |
#                                 \_V_//
#                                 \/=|=\/
#                                  [=v=]
#                                __\___/_____
#                               /..[  _____  ]
#                              /_  [ [  M /] ]
#                             /../.[ [ M /@] ]
#                            <-->[_[ [M /@/] ]
#                           /../ [.[ [ /@/ ] ]
#      _________________]\ /__/  [_[ [/@/ C] ]
#     <_________________>>0---]  [=\ \@/ C / /
#        ___      ___   ]/000o   /__\ \ C / /
#           \    /              /....\ \_/ /
#        ....\||/....           [___/=\___/
#       .    .  .    .          [...] [...]
#      .      ..      .         [___/ \___]
#      .    0 .. 0    .         <---> <--->
#   /\/\.    .  .    ./\/\      [..]   [..]
#
#!/usr/bin/perl
#
# Copyright (c) 2012-2015 Mathieu Roy <yeupou--gnu.org>
# http://yeupou.wordpress.com
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#   USA
#
#  See https://yeupou.wordpress.com/2015/03/12/resetting-samba-password-and-monitoring-wifi-via-a-web-interface/

use strict;
use DBI;
use Net::Domain qw(hostname hostfqdn hostdomain domainname);
use Socket;
use Mail::Send;


# default
my $db_password = "kdkadkda";
my $wlan = "";
my $wlan_deny = "/etc/hostapd/hostapd.deny";
my $wlan_conf = "/etc/hostapd/hostapd.conf";

# system config
my $rc = "/etc/websysadminrc";
die "Unable to read $rc. We need database password (db_password) to be set, exiting" unless -r $rc;
open(RCFILE, "< $rc");
while(<RCFILE>){
    $db_password = $1 if /^db_password\s?=\s?(\S*)\s*$/i;
    $wlan= $1 if /^wlan\s?=\s?(\S*)\s*$/i;
    $wlan_deny = $1 if /^wlan_deny\s?=\s?(\S*)\s*$/i;
    $wlan_conf = $1 if /^wlan_conf\s?=\s?(\S*)\s*$/i;
}
close(RCFILE);

# Connect to database
my $dbd =DBI->connect('DBI:mysql:database=sysadmin:host=localhost',
		      'www-data', 
		      $db_password,
		      { RaiseError => 1, AutoCommit => 1});


## USERS
# check whether we asked for a new password to be set via the web interface

# get a list of users thatr belongs to group users
my (@grnam) = getgrnam('users');
my (@users) = split(' ',$grnam[3]);

# Treat each distinct request (ignore if the same user made the request several times)
my $hop;
$hop = $dbd->prepare("SELECT DISTINCT user_name FROM sambaclients");
$hop->execute;
while (my ($user) = $hop->fetchrow_array) {
    # check if legit user
    die "What's the heck?!# Someone just tried to tamper with account $user " unless ($user ~~ @users);
    # generate random password
    my @chars = (0 .. 9, 'a' .. 'z', 'A' .. 'Z');
    my $random =  join "", @chars[ map rand @chars, 0 .. 9 ];
    # update the password
    system("/usr/sbin/usermod", "--password", crypt($random, $random), $user);
    # send a mail
    my $msg = new Mail::Send;
    $msg->to($user);
    $msg->subject("Changement de mot de passe ".hostdomain());
    $msg->add("User-Agent", "calaboose.sysadmin");
    my $fh = $msg->open;
    print $fh "Bonjour,\n\Votre mot de passe est désormais :\n\n\t".$random."\n\n";
    $fh->close;
        
}
$hop->finish;

# cLeanup database
$dbd->do("DELETE FROM sambaclients");


# finish here is no wifi is set up
exit if $wlan eq "";

## Wifi
# get the list of connected wifi clients
# they can have the following flags:
#  A = approved   (legitimate client) 
#  S = suspect    (neither approved or banned)
#  SI = suspect inactive 
#  B = banned
#
# We'll send a mail each time a client enter suspect state (which means
# each time a new client is know or a suspect one goes from inactive to 
# active)

my (%clients, %client_dbstatus, %client_hwstatus);

# extract database known clients, ignored SI as they are to be treated as a 
# new client
$hop = $dbd->prepare("SELECT hw_address,status FROM wificlients WHERE status<>'SI'");
$hop->execute;
my (%db_client_status);
while (my ($client, $client_status) = $hop->fetchrow_array) {
    $clients{$client} = $client;
    $client_dbstatus{$client} = $client_status;
}

# extract currently connected clients according to hardware
open(IW, "/sbin/iw $wlan station dump |");
while (<IW>) {
    if (/^Station\s([^\s]*)\s/) {
	$clients{$1} = $1;
	$client_hwstatus{$1} = 1;
    }
}


# then compare to the database
my @banned;
foreach my $client (keys %clients) {

    # clean up the air:
    # add banned clients to hostapd deny file and forget about them forever
    if ($client_dbstatus{$client} eq 'B') {
        # check if it's not already in
        my $found = 0;
        open(DENY_IN, "< $wlan_deny");
        while(<DENY_IN>){
            $found = 1 if /^$client$/;
            last if $found;
        }
        close(DENY_IN);
        # if not, add it
        unless ($found) {
            open(DENY_OUT, ">> $wlan_deny");
            print DENY_OUT "$client\n";
            close(DENY_OUT);
        }
        # remove from the database because we wont actually manage this
        # with this interface any further
        $dbd->do("DELETE FROM wificlients WHERE hw_address=".$dbd->quote($client));
    }

    # if unknown to the database (or SI) but know the hardware, 
    # add it as suspect
    if (!exists($client_dbstatus{$client}) && 
	$client_hwstatus{$client} eq 1) {

	my ($ip, $name);
	my $domain = hostdomain();
	open(ARP, "/usr/sbin/arp -n -i $wlan |");
	while (<ARP>) {
	    # this will work properly only if the arp cache is up to date
	    # it would be overkill to make this script keeping it so
	    next unless /\s$client\s/;
	    $ip = $1 if /^([^\s]*)\s/;
	}
	close(ARP);
	$name = gethostbyaddr(inet_aton($ip), AF_INET);
	$name = substr($name, 0, (length($name)-(length($domain)+1)));

	$dbd->do("REPLACE INTO wificlients VALUES ('".$client."','S','".$ip."','".$name."')");


	# send a mail 
	my $msg = new Mail::Send;
	$msg->to("root");
	my $id = $client;
	$id = $name unless $name eq "";
	$msg->subject("Client Wifi inconnu (".$id.") sur ".$domain);
	$msg->add("User-Agent", "calaboose.sysadmin");
        my $fh = $msg->open;
        print $fh "Bonjour,\n\nUn client Wifi inconnu vient de se connecter au réseau :\n\n\t- prétend avoir la carte réseau ".$client."\n";
	unless ($ip eq "") {
	    # if ip is unset, it is probably because the arp cache is 
	    # outdated. Skip this.
	    print $fh "\t- demande à être appelé ".$name."\n";
	    print $fh "\t- s'est vu attribuer l'IP ".$ip."\n";
	    print $fh "\n";
	}
	use URI::Encode qw(uri_encode);
	print $fh "Confirmer l'accès accordé :\n\t".uri_encode("http://".hostfqdn()."/sysadmin/?client=$client&amp;status=A")."\n";
	print $fh "Bannir définitivement: \n\t".uri_encode("http://".hostfqdn()."/sysadmin/?client=$client&amp;status=B")."\n";
	
	$fh->close;
    }

    # if known to the database as suspect but unknown to the hardware, mark
    # it as suspect inactive
    $dbd->do("UPDATE wificlients SET status='SI' WHERE hw_address=".$dbd->quote($client))
	if ($client_dbstatus{$client} eq 'S' && 
	    !exists($client_hwstatus{$client}));

    # otherwise, nothing to do
}



# EOF
