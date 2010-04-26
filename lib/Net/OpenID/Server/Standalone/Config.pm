package Net::OpenID::Server::Standalone::Config;

use strict;
use warnings;

our $config;

=pod
  my $config = {
    users => {
      'the_your_nickname' => {
        pass        => 'md5_base64 of your password',
        url         => 'http://your.openid.url/',
        trust_root  => sub{
                            shift =~ m/(blogger\.com|cpan\.org|ccmixter\.org|stickr\.com|mychores\.co\.uk\/openid|qdos\.com
                                        |demand-openid\.rpxnow\.com|livejournal\.com|sourceforge\.net)\/?$/x;
                        },
        # http://openid.net/specs/openid-simple-registration-extension-1_0.html
        sre         => {
          'sreg.nickname'     => 'nickname_for_outside_world',
          'sreg.fullname'     => 'Your Fullname',
        },
      },
    },
  # Where to redirect in case of wrong login/pass, wrong OpenID url, or
  # failed filter for RP:
    setupUrl => '/setup',
    idSvrUrl => '/id',
    serverSecret => 'some_random_sequence_put_your_own',
    requireSsl=> 0,
    session  =>  {
      dsn  =>"driver:DB_File;serializer:FreezeThaw",
      name  => 'nossa_cookie',
      expire  => '+1h',
    },
  };
=cut

###  No user-serviceable part below this line ###

sub get{
  my $pkg = shift if ( $_[0] eq __PACKAGE__ ) or defined ref $_[0] ;
	no strict 'refs';
  my $rv = ${ *{ $pkg. '::' }->{ config } };
	use strict 'refs';
  if( @_ > 0 ){
    while( $_ = shift @_ ){
      if( defined $rv->{ $_ } ){
        $rv = $rv->{ $_ };
      } else {
        $rv = undef;
        last;
      }
    }
  }
  return $rv;
}

1;
