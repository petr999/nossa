package Net::OpenID::Server::Standalone;

use strict;
use warnings;

my $configPackage = __PACKAGE__."::Config";
eval( "use $configPackage;" );
length( $@ ) and die " No $configPackage! (please create it from Config.pm.sample): $@";

1;
