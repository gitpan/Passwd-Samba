package Passwd::Samba;

use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);

use warnings;
use strict;

use Crypt::SmbHash;
#======================================================================
$VERSION = '0.12';
@ISA = qw(Exporter);
@EXPORT_OK = qw(del uid maxuid passwd rename users);
#======================================================================
use constant PASSWD => '/etc/samba/smbpasswd';
#======================================================================
sub new { return bless { }, __PACKAGE__; }
#======================================================================
sub del {
	shift if $_[0] =~ __PACKAGE__;
	
	open(my $fh, '<', PASSWD);
	my @a;
	while(<$fh>){
		push @a,$_ if /^[^:]+:/o;
	}
	close($fh);
	
	my $re = '^'.join('$|^', @_).'$';
	$re = qr/$re/;
	
	open($fh, '>', PASSWD);
	print $fh grep { (split(/:/,$_))[0] !~ $re } @a;
	close($fh);
	
	return;
}
#======================================================================
sub rename {
	shift if $_[0] =~ __PACKAGE__;
	return unless defined $_[1];
	
	open(my $fh, '<', PASSWD);
	my @a;
	while(<$fh>){
		push @a,$_ if /^[^:]+:/o;
	}
	close($fh);
	# jesli taki uzytkownik juz istnieje
	return if grep { /^$_[1]:/ } @a;
	
	@a = map { s/^$_[0]:/$_[1]:/;$_ } @a;
	
	open($fh, '>', PASSWD);
	print $fh @a;
	close($fh);
	
	return 1;
}
#======================================================================
sub uid {
	shift if $_[0] =~ __PACKAGE__;
	
	open(my $fh, '<', PASSWD);
	if(not defined $_[1]){
		while(<$fh>){
			return (split(/:/,$_))[1] if /^$_[0]:/;
		}
	}else{
		my @a;
		while(<$fh>){
			if(/^[^:]+:/o){
				if(/^$_[0]:/){
					my @tmp = split(/:/,$_);
					$tmp[1] = $_[1];
					push @a, join(':', @tmp);
				}else{ push @a, $_; }
			}
		}
		close($fh);
		open($fh, '>', PASSWD);
		print $fh @a;
	}
	close($fh);

	return 1;
}
#======================================================================
sub maxuid {
	my $max = 0;
	open(my $fh, '<', PASSWD);
	while(<$fh>){
		my $tmp = (split(/:/,$_))[1];
		$max = $tmp > $max ? $tmp : $max;
	}
	close($fh);
	return $max;
}
#======================================================================
sub passwd {
	shift if $_[0] =~ __PACKAGE__;
	
	my ($name, $passwd) = @_;
	return unless defined $passwd;
	my $uid = (getpwnam($name))[2];
	my ($lm, $nt);
	ntlmgen $passwd, $lm, $nt;
	__PACKAGE__::del($name);

	open(my $fh, '>>', PASSWD);
	printf $fh "%s:%d:%s:%s:[%-11s]:LCT-%08X\n", $name, $uid, $lm, $nt, "U", time;
	close($fh);

	return 1;
}
#======================================================================
sub users {
	my @a;
	open(my $fh, '<', PASSWD);
	push @a, (split(/:/,$_))[0] while <$fh>;
	close($fh);
	return @a;
}
#======================================================================
1;


=head1 NAME

Passwd::Samba


=head1 SYNOPSIS

	use Passwd::Samba;
	
	my $ps = Passwd::Samba->new();
	my $err = $ps->passwd("example", "_plain_text_secret_" );
	foreach my $user ($ps->users) {
		print "Username: $user\nUID: ", $ps->uid($user), "\n\n";
	}
	my $uid = $ps->uid('example');
	$ps->rename('example', 'new_example');
	$pu->del('new_example');

	# or 

	use Passwd::Samba qw(del uid maxuid passwd rename users);

	my $err = passwd("example", "_plain_text_secret_" );
	foreach my $user (users()) {
		print "Username: $user\nUID: ", uid($user), "\n\n";
	}
	my $uid = uid('example');
	rename('example', 'new_example');
	del('new_example');

=head1 DESCRIPTION

The Passwd::Samba module provides an abstract interface to /etc/samba/smbpasswd format files. It is inspired by Unix::PasswdFile module.

=head1 SUBROUTINES/METHODS

=over 4

=item B<new( )>

Constructor.

=item B<del( USERNAME0, USERNAME1... )>

This method will delete the list of users. It has no effect if the supplied user does not exist.

=item B<maxuid( )>

This method returns the maximum UID in use by all users. 

=item B<passwd( USERNAME, PASSWD )>

Modify a user's password. Returns the result of operation (TRUE or FALSE).

=item B<rename( OLDNAME, NEWNAME )>

This method changes the username for a user. If NEWNAME corresponds to an existing user, that user will be overwritten. It returns FALSE on failure and TRUE on success.

=item B<uid( USERNAME [,UID] )>

Read or modify a user's UID. Returns the result of operation (TRUE or FALSE) if UID was specified otherwhise returns the UID.

=item B<users()>

This method returns a list of all existing usernames. 

=back

=head1 DEPENDENCIES

=over 4

=item Crypt::SmbHash

=item Exporter

=back


=head1 INCOMPATIBILITIES

None known.

=head1 BUGS AND LIMITATIONS

None known.

=head1 AUTHOR

Strzelecki Łukasz <strzelec@rswsystems.com>

=head1 LICENCE AND COPYRIGHT

This program is free software; you can redistribute it and/or modify it under the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

