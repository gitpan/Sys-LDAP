# $Id: LDAP.pm,v 0.0 0000/00/00 00:00:00 cfaerber Exp $

package Sys::LDAP;

require v5.6.0;

use strict;

our $VERSION = '0.10_20060903';
our $DEBUG = $VERSION =~ m/_/;
$VERSION = eval $VERSION;

use Carp;
use URI;
use Net::LDAP;

=head1 NAME

Sys::LDAP - Connects to the LDAP server that serves as the authentication backend for the local system.

=head1 SYNOPSIS

  use Sys::LDAP;
  $ldap = new Sys::LDAP;

=head1 DESCRIPTION

The "Sys::LDAP" module connects to the LDAP server that serves as the
authentication backend for the local system.

=cut

=head1 FUNCTIONS

=head2 new()

Creates a Net::LDAP object using a local configuration file.

If the config paramter is given, this file is read.

If no config paramter is given, several file names are tried (C</etc/pam_ldap.conf>,
C</etc/libnss-ldap.conf>, C</etc/ldap/ldap.conf>) to get the
configuration.

If C</etc/ldap.secret> is readable, rootbinddn is used instead of binddn.

=head1 AUTHOR

Claus A. Färber <perl@faerber.muc.de>

=head1 COPYRIGHT

Copyright © 2006 Claus A. Färber All rights reserved. This program
is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut

our @_FILENAMES = 
(
  '/etc/pam_ldap.conf',
  '/etc/libnss-ldap.conf',
  '/etc/ldap/ldap.conf',
  '/etc/ldap.conf',
);

our @_SECRET_FILENAMES =
(
  '/etc/ldap.secret',
);

sub _kw 
{
  my $k = lc(shift);
  $k =~ s/\s//g;
  return $k;
}

sub _cl
{
  return 'none'		if $_[0] =~ m/^(n|of)/i;
  return 'optional'	if $_[0] =~ m/^(a|t)/i;
  return 'require';
}

sub new
{
  my ($self,%param) = @_;
  my %config =  ();
  my $secret = undef;

  # read system configuration
  #
  foreach my $filename (@_FILENAMES)
  {
    if(open LDAPCONF, "<", $filename)
    {
      print STDERR "Sys::LDAP: Reading config from $filename...\n" if $DEBUG;
      while(<LDAPCONF>)
      {
        s/#.*//;
        m/\s*(\S*)\s+(\S.*)/ || next;
	$config{lc $1} = $2;
      }
      close LDAPCONF;
      last;
    }
  }

  # read ldap.secrets
  #
  foreach my $secret_filename (@_SECRET_FILENAMES)
  {
    if(open LDAPSECRET, "<", $secret_filename) 
    {
      print STDERR "Sys::LDAP: Reading secret from $secret...\n" if $DEBUG;
      chomp($secret = <LDAPSECRET>);
      close LDAPSECRET;
    }
  }
    
  my %options = ();
  my %ssl_opt = ();
  my $uri;

  if(exists $config{'uri'})
  {
    $uri = URI->new( $config{'uri'} );
  }
  else
  {
    $uri = URI->new(_kw($config{'ssl'}) eq 'on' ? 'ldaps:' : 'ldap:');
    $uri->host( $config{'host'} || 'localhost' );
    $uri->port( $config{'port'} ) if $config{'port'};
  }

  if(_kw($config{'ssl'}) eq 'start_tls' or lc($uri->scheme) eq 'ldaps')
  {
    $ssl_opt{'verify'}	= _cl($config{'TLS_REQCERT'}) if exists $config{'TLS_REQCERT'};
    $ssl_opt{'clientcert'} = $config{'TLS_CERT'} if exists $config{'TLS_CERT'};
    $ssl_opt{'clientkey'} = $config{'TLS_KEY'} if exists $config{'TLS_KEY'};
    $ssl_opt{'capath'}	= $config{'TLS_CACERTDIR'} if exists $config{'TLS_CACERTDIR'};
    $ssl_opt{'cafile'}	= $config{'TLS_CACERT'} if exists $config{'TLS_CACERT'};
  }

  %options = (%options,%ssl_opt) if(lc($uri->scheme) eq 'ldaps');

  print STDERR "Sys::LDAP: Connecting to $uri...\n" if $DEBUG;
  print STDERR "  <$_>=<$options{$_}>\n" foreach(sort keys %options);

  my $ldap = Net::LDAP->new($uri->as_string, %options, %param) || return undef;

  if(_kw($config{'ssl'}) eq 'start_tls')
  {
    print STDERR "Sys::LDAP: Starting TLS...\n" if $DEBUG;
    $ldap->start_tls(%ssl_opt);
  }

  if($config{'rootbinddn'} && defined($secret))
  { 
    print STDERR "Sys::LDAP: Binding as $config{'rootbinddn'}...\n" if $DEBUG;
    $ldap->bind($config{'rootbinddn'}, 'password' => $secret);
  }
  elsif(exists $config{'binddn'})
  {
    print STDERR "Sys::LDAP: Binding as $config{'binddn'}...\n" if $DEBUG;
    $ldap->bind($config{'binddn'}, 'password' => $config{'bindpw'});
  }

  return $ldap;
}

1;
