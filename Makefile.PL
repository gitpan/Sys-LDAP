# $Id: Makefile.PL,v 0.0 0000/00/00 00:00:00 cfaerber Exp $
#
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Sys::LDAP',
    'VERSION_FROM'	=> 'LDAP.pm', # finds $VERSION
    'PREREQ_PM'		=> {
		'Net::LDAP' => 0.33,
	},
    ($] >= 5.005 ?    ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM => 'LDAP.pm', # retrieve abstract from module
       AUTHOR     => 'Claus Färber <perl@faerber.muc.de>') : ()),
);
