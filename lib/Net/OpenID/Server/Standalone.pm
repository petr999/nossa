package Net::OpenID::Server::Standalone;

use strict;
use warnings;

my $configPackage = __PACKAGE__."::Config";
eval( "use $configPackage;" );
length( $@ ) and die " No $configPackage! (please create it from Config.pm.sample): $@";

my( $cgi, $session );

sub id {
	my $self = __PACKAGE__->new;
	my $requireSsl = $configPackage->get( 'requireSsl' );
	unless( $requireSsl and isRedirectedToSsl() ){
	}
}
sub new	{
	$cgi = new CGI; $cgi->charset( 'utf-8' );
	my $session_href = $configPackage->get( 'session' );
	my( $session_name, $session_dsn, $session_expire ) = map{ $session_href->{ $_ } } qw/name dsn expire/;
	CGI::Session->name( $session_name );
	$session = new CGI::Session( $session_dsn, undef ) or die CGI::Session->errstr;
	$session->expire( $session_expire );
	bless {	
	}, __PACKAGE__ ;
}

sub setup {
	my $self = __PACKAGE__->new;
}

sub redirect {
	my( $status, $location, ) = @_;
	print $session->header( -status => $status, -location => $location, );
	print redirectMessage();
}
sub redirectMessage {
	my( $status, $location, ) = @_;
	return <<EOF;
<html><h1
>$status</h1
><p
>The document is moved <a href='$location'>here.</a
></p><hr
/>nossa &mdash; Net::OpenID::Server::Standalone.</html>
EOF
}

sub isRedirectedToSsl{
	my $self = shift;
	my $cgi = $self->{ cgi };
	my $mode = $cgi->param( 'openid.mode' );
	if( 
			(
				( $mode eq 'checkid_setup' )
				or
				( $mode eq 'checkid_immediate' )
			)
			and
			(	$ENV{ SERVER_PORT } != 443 )
		){
		my $url = 'https://'.$ENV{ HTTP_HOST };
		$url .= $ENV{ REQUEST_URI };
		redirect( "301 SSL please", $url, );
	}
}

sub getUser {
		my $authorized = 0;
    my ($login, $pass) = getAuth();
		my $users = $configPackage->get( 'users' );
    if ( defined( $login ) and defined $users->{$login}) {
			my $user = $users->{$login};
			if( defined( $pass ) and ( $user->{pass} eq md5_base64 $pass ) ) {
				$session->param( login => $login );
				$session->flush;
				$authorized = 1;
			}
		} elsif( defined( $session->param( "login" ) ) and length $session->param( "login" ) ){
			$login = $session->param( "login" );
			$authorized = 1;
		}
		if( $authorized ) {
			return $login;
		} else {
      requireAuth();
    }
}
sub getAuth {
		my( $login, $password ) = map{ defined( $cgi->param( $_ ) ) ? $cgi->param( $_ ) : ''; 
		} qw/login password/;
		if( defined( $login ) and length( $login )
						and defined( $password ) and length( $password )
			){
			return $login, $password;
		} else {
			return;
		}
}
sub requireAuth {
		my $params = $cgi->Vars;
		map{ delete( $params->{ $_ } ) if defined $params->{ $_ } } qw/login password action setup_trust_root/;
		$session->param( 'vars', $params ) or die CGI::Session->errstr;
		$session->flush or die CGI::Session->errstr;
		print redirect( "301 Login please", $configPackage->get( 'setupUrl' ), );
		return undef;
}

sub isIdentity {
    my ($user, $url) = @_;
    return unless defined $user;
		my $configUrl = $configPackage->get( 'users', $user, 'url' );
    return defined( $configUrl ) and $configUrl  eq $url;
}

sub isTrusted {
    my ($user, $trustRoot, $isIdentity) = @_;
		my $trusted = 0; my $setupTrustRoot = $cgi->param( 'setup_trust_root' );
    if( defined( $user ) and defined( $isIdentity ) and $isIdentity ){
			if( defined( $setupTrustRoot ) and $setupTrustRoot eq 'Yes' ){
				$trusted = 1;
			} else {
				my $trustRootCref = $configPackage->get( 'users', $user, 'trust_root', );
				if( defined( $trustRootCref ) and 'CODE' eq ref $trustRootCref ) {
    			$trusted = $trustRootCref->( $trustRoot );
				}
			}
			if(	defined( $setupTrustRoot ) and length $setupTrustRoot ){
				$session->clear( [ 'vars' ] );
				$session->flush;
				unless(	$trusted ){
						redirect( "301 Not Trusted", $trustRoot, );
						exit;
				}
			}
			unless( $trusted ){
				unless(	defined( $setupTrustRoot ) ){
					my $params = $cgi->Vars;
					map{ delete( $params->{ $_ } ) if defined $params->{ $_ } } qw/login password action setup_trust_root/;
					$session->param( 'vars', $params ) or die CGI::Session->errstr;
					$session->flush or die CGI::Session->errstr;
				}
			}
		}
		return $trusted;
}

1;
