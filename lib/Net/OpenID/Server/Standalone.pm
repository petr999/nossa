package Net::OpenID::Server::Standalone;

use vars qw($VERSION);
BEGIN {
  $VERSION = '0.1.1';
  $Net::OpenID::Server::Standalone::Default = 'Net::OpenID::Server::Standalone';
}

=pod

=head1 NAME

  Net::OpenID::Server::Standalone - personal standalone OpenID server ready-to-use out-of-the-box

=head1 SYNOPSIS

id script use this:

  Net::OpenID::Server::Standalone::id;

setup script use this:

  Net::OpenID::Server::Standalone::setup;

For more sophisticated use see below.
     
=head1 DESCRIPTION

Typical layout follows:
  ./ --- application root, e. g. $HOME on your hosting.
    lib/Net/OpenID/Server/Standalone/
      Config.pm --- configuration of your OpenID server,
                    created from Config.pm.sample
    www/ or public_html/
      index.html or whatever to be your XRD document like it is at 
      L<http://peter.vereshagin.org>.
    cgi/ or perl/ or cgi-bin/ or www/
      id.cgi    or id.pl    or id    --- id script
      setup.cgi or setup.pl or setup --- setup script

=cut

use strict;
use warnings;

use Net::OpenID::Server;
use Data::UUID;
use MIME::Base64 qw/encode_base64/;
use HTML::Entities qw/encode_entities/;
use Digest::MD5 qw/md5_base64/;
use CGI;
use CGI::Session;

my $configPackage;

my( $cgi, $session, );

my $htmlStyle = { start => '<html>', end => '</html>', };

*_push_url_arg = \&Net::OpenID::Server::_push_url_arg;
*_eurl = \&Net::OpenID::Server::_eurl;
*hashFunction =\&md5_base64;

sub new  {
  my $pkg = shift;
  $configPackage = $pkg."::Config";
  eval( "use $configPackage;" );
  length( $@ ) and Carp::croak "No $configPackage! (please create it from Config.pm.sample): $@";
  $cgi = new CGI; $cgi->charset( 'utf-8' );
  my $rnd = encode_base64( Data::UUID->new->create() ); chomp $rnd;
  my $setupUrl = $configPackage->get( 'setupUrl' );
  _push_url_arg( \$setupUrl , 'rnd' => $rnd, );
  my $session_href = $configPackage->get( 'session' );
  my( $session_name, $session_dsn, $session_expire ) = map{ $session_href->{ $_ } } qw/name dsn expire/;
  CGI::Session->name( $session_name );
  $session = new CGI::Session( $session_dsn, undef ) or die CGI::Session->errstr;
  $session->expire( $session_expire );
  bless {  
    rnd => $rnd,
    setupUrl => $setupUrl,
  }, $pkg ;
}
sub id {
  my $self = ( @_ ? shift : __PACKAGE__ )->new ;
  my $requireSsl = $configPackage->get( 'requireSsl' );
  unless( $requireSsl and isRedirectedToSsl() ){
    my $setupUrl = $self->{ setupUrl };
    my $nos = Net::OpenID::Server->new(
      get_args      => $cgi,
      post_args     => $cgi,
      get_user      => sub{ $self->getUser( @_ ) },
      is_identity   => \&isIdentity,
      is_trusted    => \&isTrusted,
      server_secret => $configPackage->get( 'serverSecret' ),
      setup_url     => $setupUrl ,
      compat         => 1,
    );
    my ($type, $data) = $nos->handle_page();
    my $redirect = [ '200', $data, -type => $type, ];
    if( $type eq 'redirect' ){
      my $user = $nos->get_user()->();
      #my $url = $data;
      my $url = {
        identity            => $nos->args('openid.identity'),
        return_to           => $nos->args('openid.return_to'),
        assoc_handle        => $nos->args('openid.assoc_handle'),
        trust_root          => $nos->args('openid.trust_root'),
      };
      my $sre = $configPackage->get( 'users', $user, 'sre', );
      if( defined( $sre ) and 'HASH' eq ref $sre ){
        $url->{ additional_fields }  = $sre;
      }
      $url = $nos->signed_return_url( %$url );
      $redirect = [ '301 Identity Provided', $url, ];
    } elsif( $type eq 'setup' ){
      my $url = $setupUrl;
      _push_url_arg( \$url, %$data, );
      $redirect = [ '301 Setup Required', $url, ];
    }
     redirect( @$redirect );
  }
}

sub setup {
  my $self = ( @_ ? shift : __PACKAGE__ )->new ;
  my $idSvrUrl = $configPackage->get( 'idSvrUrl' );
  _push_url_arg( \$idSvrUrl , 'rnd' => $self->{ rnd }, );
  $self->{ idSvrUrl } = $idSvrUrl;
  my $action = $cgi->param( 'action' );
  print $session->header;
  if( $session->param( 'login' ) ){
    if( defined( $action ) and $action eq 'logout' ){
      $session->delete;
      $session->flush;
      $self->printLoginForm;
    } elsif( defined( $cgi->param( 'trust_root' ) ) and length $cgi->param( 'trust_root' ) ){
      my $trustRoot = $cgi->param( 'trust_root' );
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
  if( substr( $status, 0, 3 ) eq '200' ){
    print $location;
  } else {
    print redirectMessage( $status, $location, );
  }
}
sub redirectMessage {
  my( $status, $location, ) = @_;
  return <<EOF;
$htmlStyle->{start}<h1
>$status</h1
><p
>The document is moved <a href='$location'>here.</a
></p><hr
/>nossa &mdash; Net::OpenID::Server::Standalone.$htmlStyle->{ end }
EOF
}

sub isRedirectedToSsl{
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
  my $self = shift;
  my $authorized = 0;
  my ($login, $pass) = getAuth();
  my $users = $configPackage->get( 'users' );
  if ( defined( $login ) and defined $users->{$login}) {
    my $user = $users->{$login};
    if( defined( $pass ) and ( $user->{pass} eq $self->callHashFunction( $pass ) ) ) {
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
  # map{ delete( $params->{ $_ } ) if defined $params->{ $_ } } qw/login password action setup_trust_root/;
  $params = {
    map{ substr( $_, 7, length( $_ ) -7 ) => $cgi->param( $_ )  }
      grep /^openid\./, $cgi->param
  };
  my $setupUrl = $configPackage->get( 'setupUrl' );
  _push_url_arg( \$setupUrl, %$params );
  print &redirect( "301 Login please", $setupUrl, );
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
sub cgiHiddens {
  my $cgi_htmled = { map{  
      encode_entities( $_, '<>&"\'' ) => encode_entities( $cgi->param( $_ ), '<>&"\'' )
  } $cgi->param };
  $cgi_htmled->{ mode } = 'checkid_setup';
  $cgi_htmled =  join "\n",
    map {
      my $val = $cgi_htmled->{ $_ };
      "<input type='hidden' name='openid.$_' value='$val' />";
    } keys  %$cgi_htmled  ;
  return  \$cgi_htmled;
}
sub printLoginForm {
  my $self = shift;
  my $idSvrUrl = $self->{ idSvrUrl };
  my $hiddens = &cgiHiddens;
  print <<EOF;
$htmlStyle->{ start }<form action='$idSvrUrl' method='POST'
>$$hiddens<table width='0' cellspacing='0' cellpadding='0' border='0'>
<tr>
<td>Login: </td><td><input type='text' name='login' /></td>
</tr><tr>
<td>Pzzwd: </td><td><input type='password' name='password' /></td>
</tr>
<tr><td colspan='2' align='center'><input type='submit' name='button' value='Go' /></td></tr>
</table></form>$htmlStyle->{ end }
EOF
}
sub printTrustForm {
  my $self = shift;
  my $trustRootHtmled = shift;
  my $idSvrUrl = $self->{ idSvrUrl };
  my $hiddens = &cgiHiddens;
  print <<EOF;
$htmlStyle->{ start }<form action='$idSvrUrl' method='POST'
>$$hiddens<table width='0' cellspacing='0' cellpadding='0' border='0'>
<tr>
<tr><td colspan='2' align='center'>Trust this root?<br /><b>$trustRootHtmled</b></td></tr>
<tr><td align='center'><input type='submit' name='setup_trust_root' value='Yes' /></td><td align='center'><input type='submit' name='setup_trust_root' value='No' /></td>
</tr>
</table></form>$htmlStyle->{ end }
EOF
}
sub printLogoutForm {
  my $self = shift;
  my $setupUrl = $self->{ setupUrl };
  print <<EOF;
$htmlStyle->{ start }<form action='$setupUrl' method='POST'
><input type='hidden' name='action' value='logout'
/><input type='submit' name='button' value='Out' 
/></form>$htmlStyle->{ end }
EOF
}

sub callHashFunction {
  &hashFunction( $_[1] );
}

1;
