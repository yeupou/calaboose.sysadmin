#!/usr/bin/perl
#
# Copyright (c) 2012 Mathieu Roy <yeupou--gnu.org>
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

use strict;
use DBI;

my $db_password = "DAnalkdnAD";

# get a list of users thatr belongs to group users                              
my (@grnam) = getgrnam('users');
my (@users) = split(' ',$grnam[3]);


# Connect to database
my $dbd =DBI->connect('DBI:mysql:database=updatepasswords:host=localhost',
		      'www-data', 
		      $db_password,
		      { RaiseError => 1, AutoCommit => 1});


# Treat each distinct request (ignore if the same user made the request several times)
my $hop;
$hop = $dbd->prepare("SELECT DISTINCT user_name FROM requests");
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
    use Mail::Send;
    use Net::Domain qw(hostname hostfqdn hostdomain domainname);
    my $msg = new Mail::Send;
    $msg->to($user);
    $msg->subject("Changement de mot de passe ".hostdomain());
    $msg->add("User-Agent", "calaboose.sysadmin-updatepasswords");
    my $fh = $msg->open;
    print $fh "Bonjour,\n\Votre mot de passe est désormais :\n\n\t\t".$random."\n\n";
    $fh->close;
        
}
$hop->finish;

# CLeanup database
$dbd->do("DELETE FROM requests");



# EOF
