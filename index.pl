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
use Net::Domain qw(hostname hostfqdn hostdomain domainname);

my $db_password = "DAnalkdnAD";

# get a list of users thatr belongs to group users
my (@grnam) = getgrnam('users');
my (@users) = split(' ',$grnam[3]);


# start html
print header(-charset => 'UTF-8');
print start_html(-lang =>  'fr-FR',
                 -title => "Administration de ".hostdomain());


# Reset password
print h2("Utilisateurs :");

if (param('user')) {
    # A form was already posted

    # check if the requested user truly belongs to 'users'
    die "What's the heck?!# Someone just tried to tamper with account ".param('user') unless (param('user') ~~ @users);

    # feed the database - a distinct script will do the change, as it requires
    # root privileges
    my $dbd =DBI->connect('DBI:mysql:database=updatepasswords:host=localhost',
			  'www-data', 
			  $db_password,
			  { RaiseError => 1, AutoCommit => 1});
    $dbd->do("INSERT INTO requests VALUES ('".$ENV{'REMOTE_ADDR'}."','".param('user')."')");

    print p("Demande de changement de mot de passe pour ".param('user')." enregistrée.");

} else {
    # Otherwise print the form
    print start_form(-method=>"POST",-action=>script_name());
    print "Réinitialiser le mot de passe de ";
    print popup_menu(-name=>"user",-values=>\@users);
    print submit().end_form();
    print em("(Ne fonctionnera que si /etc/aliases est à jour)");
    print end_html();
}


print h2("Wifi :");

# EOF
