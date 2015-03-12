#!/usr/bin/perl
#
# (c) 2012 Mathieu Roy <yeupou--gnu.org>
#     http://yeupou.wordpress.com
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
#    USA
use strict;
use DBI;
use CGI qw(:standard Link);
use CGI::Carp;
use Net::Domain qw(hostdomain); 
use URI::Encode qw(uri_encode);
use Data::Password qw(:all);

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

# database connect
my $dbd =DBI->connect('DBI:mysql:database=sysadmin:host=localhost',
		      'www-data',
		      $db_password,
		      { RaiseError => 1, AutoCommit => 1});


# update wifi related info
if (param('client')) {
    if (param('status')) {
	# update the database without much checks 
	$dbd->do("UPDATE wificlients SET status=".$dbd->quote(param('status'))." WHERE hw_address=".$dbd->quote(param('client'))); 
    } elsif (param('forget')) {
	# update the database without much checks
	$dbd->do("DELETE FROM wificlients WHERE hw_address=".$dbd->quote(param('client')));
    }
    # reload the page so the url get cleaned up 
    print redirect(script_name());
}


# get a list of users thatr belongs to group users
my (@grnam) = getgrnam('users');
my (@users) = split(' ',$grnam[3]);

# find out their email alias
my %users_plus_emails;
open(ALIASES, "< /etc/aliases");
while(<ALIASES>) {
    my ($thisuser, $thisalias) = split(":", $_);
    $thisalias =~ s/\s//g;
    next unless ($thisuser ~~ @users);
    $users_plus_emails{$thisuser} = "$thisuser <$thisalias>";
}
close(ALIASES);

# start html (using phpsysinfo theme)
print header(-charset => 'UTF-8');
print start_html(-lang =>  'fr-FR',
                 -title => "Administration du domaine ".hostdomain(),
		 -head => [ Link({-rel=>'stylesheet', -type=>'text/css', -href=>'/sysinfo/templates/two.css'})."\n" ] );

print h1("Administration du domaine ".hostdomain()).br().br().br().br();

## RESET SAMBA/UNIX PASSWORD
print h2("Utilisateurs :");

if (param('user')) {
    # A form was already posted

    # check if the requested user truly belongs to 'users'
    die "What's the heck?!# Someone just tried to tamper with account ".param('user') unless (param('user') ~~ @users);

    # feed the database - a distinct script will do the change, as it requires
    # root privileges
    $dbd->do("REPLACE INTO sambaclients VALUES (".$dbd->quote($ENV{'REMOTE_ADDR'}).",".$dbd->quote(param('user')).")");

    print p("Demande de changement de mot de passe pour ".param('user')." enregistrée.");

} 
# Always print the form anyway
print start_form(-method=>"POST",-action=>script_name());
print "Réinitialiser le mot de passe de ";
print popup_menu(-name=>"user",-values=>\@users,-labels=>\%users_plus_emails);
print submit().end_form();
print br().em("(Ne fonctionnera que si /etc/aliases est à jour)");
print end_html();

# PRINT WIFI PASSWORD AND LIST OF WIFI CLIENTS 
print br().br();
print h2("Connexions wifi :");

# find wifi pass
open(WLAN_CONF, "< $wlan_conf");
my $wlan_pass;
while(<WLAN_CONF>) { $wlan_pass = $1 if /^wpa_passphrase=(.*)$/; }
close (WLAN_CONF);
print p("Le mot de passe wifi ".em("($wlan_conf)")." est $wlan_pass");
# assess strenght
$MINLEN = 50;
$MAXLEN = 63;
$GROUPS = 3;
$FOLLOWING = 2;
$FOLLOWING_KEYBOARD = 1;
$DICTIONARY = 5;
@DICTIONARIES = ("/usr/share/dict/french", "/usr/share/dict/american-english");

my $failcheck = IsBadPassword($wlan_pass);
if ($failcheck) {
    # generate random example  
    my @chars = (0 .. 9, 'a' .. 'z', 'A' .. 'Z', ',' .. '-');
    my $random =  join "", @chars[ map rand @chars, 0 .. 55 ];
    print p("Il est ".a({-href=>'http://en.wikipedia.org/wiki/Wi-Fi_Protected_Access#Security'}, "visiblement insécure")." : ".em($failcheck)).p("Exemple de mot de passe sécure : ".em($random));
}
print br();

print h3("Clients autorisés :");

# look at the database (updated by the cronjob)
# to check the status of currently known clients
# Is it possible then to:
#    approve
#    remove from list of approved

my $hop;
$hop = $dbd->prepare("SELECT * FROM wificlients WHERE status='A' OR status='S' or status='SI'");
$hop->execute;
my (%db_client_status);
while (my ($client, $client_status, $client_ip, $client_name) = $hop->fetchrow_array) {
    my $string;

    # show a color code depending on the status
    my $status_color = "#000000";
    $status_color = "#1CA61E" if $client_status eq 'A';
    $status_color = "#FFBC48" if $client_status eq 'S' or $client_status eq 'SI';
    $string = span({-style=>"background-color: ".$status_color}, "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")."&nbsp;";

    # show the most meaningful info to the end user if possible:
    # hostname > ip > hwaddress 
    if ($client_name) {
	$string .= a({-title=>"$client_ip $client"}, $client_name);
    } elsif ($client_ip) {
	$string .= a({-title=>"$client"}, $client_ip);
    } else {
	$string .= $client;
    }

    $string .= ".................. ";
    $string .= a({-href=>uri_encode(script_name()."?client=$client&amp;status=A")}, "confirmer")." / " 
	if $client_status ne 'A';
    $string .= a({-href=>uri_encode(script_name()."?client=$client&amp;forget=1")}, "oublier")." / ";
    $string .= a({-href=>uri_encode(script_name()."?client=$client&amp;status=B")}, "bannir");

    print p($string);
}



print br().h3("Clients bannis ".em("($wlan_deny)")." :");
open(WLAN_DENY, "< $wlan_deny");
my $deny;
while(<WLAN_DENY>) {
    chomp();
    $deny .= " $_,";
}
close(WLAN_DENY);
chop($deny);
$deny = "Aucun" unless $deny;
print p(span({-style=>"background-color: #7A090B"}, "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")."&nbsp;".$deny);
close(WLAN_DENY);




# EOF
