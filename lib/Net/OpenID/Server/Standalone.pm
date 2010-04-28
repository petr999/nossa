package Net::OpenID::Server::Standalone;

use strict;
use warnings;

use Net::OpenID::Server;
use Data::UUID;
use MIME::Base64 qw/encode_base64/;
use HTML::Entities qw/encode_entities/;

my $configPackage = __PACKAGE__."::Config";
eval( "use $configPackage;" );
length( $@ ) and Carp::croak "No $configPackage! (please create it from Config.pm.sample): $@";

my( $cgi, $session );

*_push_url_arg = \&Net::OpenID::Server::_push_url_arg;

sub id {
  my $self = __PACKAGE__->new;
  my $requireSsl = $configPackage->get( 'requireSsl' );
  unless( $requireSsl and isRedirectedToSsl() ){
    my $nos = Net::OpenID::Server->new(
      get_args      => $cgi,
      post_args     => $cgi,
      get_user      => \&getUser,
      is_identity   => \&isIdentity,
      is_trusted    => \&isTrusted,
      server_secret => $configPackage->get( 'serverSecret' ),
      setup_url     => $self->{ setupUrl },
      compat         => 1,
    );
    my ($type, $data) = $nos->handle_page();
    my $redirect = [ '200', $data, -type => $type, ];
    if( $type eq 'redirect' ){
      my $user = $nos->get_user()->();
      my $url = $data;
      my $sre = $configPackage->get( 'users', $user, 'sre', );
      if( defined( $sre ) and 'HASH' eq ref $sre ){
        $url = _push_url_arg( $url, %$sre, );
      }
      $redirect = [ '301 Identity Provided', $url, ];
    } elsif( $type eq 'setup' ){
      my $url = $nos->setup_url();
      $url = _push_url_arg( $url, %$data, );
      $redirect = [ '301 Setup Required', $url, ];
    }
     redirect( @$redirect );
  }
}
sub new  {
  $cgi = new CGI; $cgi->charset( 'utf-8' );
  my $rnd = encode_base64( Data::UUID->new->create() ); chomp $rnd;
  my $setupUrl = _push_url_arg(
    $configPackage->get( 'setupUrl' ), 'rnd' => $rnd,
  );
  my $idSvrUrl = _push_url_arg(
    $configPackage->get( 'idSvrUrl' ), 'rnd' => $rnd,
  );
  my $session_href = $configPackage->get( 'session' );
  my( $session_name, $session_dsn, $session_expire ) = map{ $session_href->{ $_ } } qw/name dsn expire/;
  CGI::Session->name( $session_name );
  $session = new CGI::Session( $session_dsn, undef ) or die CGI::Session->errstr;
  $session->expire( $session_expire );
  bless {  
    setupUrl => $setupUrl,
    idSvrUrl => $idSvrUrl,
  }, __PACKAGE__ ;
}

sub setup {
  my $self = __PACKAGE__->new;
  my $action = $cgi->param( 'action' );
  print $cgi->header;
  if( $session->param( 'login' ) ){
    if( $action eq 'logout' ){
      $session->delete;
      $session->flush;
      $self->printLoginForm;
    } elsif( defined( $cgi->param( 'trust_root' ) ) and length $cgi->param( 'trust_root' ) ){
      my $trustRoot = $cgi->param( 'openid.trust_root' );
      $self->printTrustForm( encode_entities( $trustRoot ) );
    } else {
      $self->printLogoutForm;
    }
  } else {
    $self->printLoginForm;
  }
}

sub redirect {
  my( $status, $location, ) = ( shift, shift, );
  print $session->header( -status => $status, -location => $location, @_ );
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
      (  $ENV{ SERVER_PORT } != 443 )
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
    if(  defined( $setupTrustRoot ) and length $setupTrustRoot ){
      unless(  $trusted ){
        redirect( "301 Not Trusted", $trustRoot, );
        exit;
      }
    }
  }
  return $trusted;
}
sub printLoginForm {
  my $self = shift;
  my $idSrvUrl = $self->{ idSrvUrl };
  my $hiddens = &cgiHiddens;
  print <<EOF;
<html><form action='$idSrvUrl' method='POST'
>$hiddens<table width='0' cellspacing='0' cellpadding='0' border='0'>
<tr>
<td>Login: </td><td><input type='text' name='login' /></td>
</tr><tr>
<td>Pzzwd: </td><td><input type='password' name='password' /></td>
</tr>
<tr><td colspan='2' align='center'><input type='submit' name='button' value='Go' /></td></tr>
</table></form></html>
EOF
}
sub cgiHiddens {
  my $cgi_htmled = { map{  
      encode_entities( $_, '<>&"\'' ) => encode_entities( $cgi->param( $_ ), '<>&"\'' )
  } $cgi->param };
  $cgi_htmled->{ mode } = 'checkid_setup';
  return join "\n",
    map {
      my $val = $cgi_htmled->{ $_ };
      "<input type='hidden' name='openid.$_' value='$val' />";
    } keys  %$cgi_htmled  ;
}
sub printTrustForm {
  my $self = shift;
  my $trustRootHtmled = shift;
  my $idSrvUrl = $self->{ idSrvUrl };
  my $hiddens = &cgiHiddens;
  print <<EOF;
<html><form action='$idSrvUrl' method='POST'
>$hiddens<table width='0' cellspacing='0' cellpadding='0' border='0'>
<tr>
<tr><td colspan='2' align='center'>Trust this root?<br /><b>$trustRootHtmled</b></td></tr>
<tr><td align='center'><input type='submit' name='setup_trust_root' value='Yes' /></td><td align='center'><input type='submit' name='setup_trust_root' value='No' /></td>
</tr>
</table></form></html>
EOF
}
sub printLogoutForm {
  my $self = shift;
  my $setupUrl = $self->{ setupUrl };
  print <<EOF;
<html><form action='$setupUrl' method='POST'
><input type='hidden' name='action' value='logout'
/><input type='submit' name='button' value='Out' 
/></form></html>
EOF
}

1;
