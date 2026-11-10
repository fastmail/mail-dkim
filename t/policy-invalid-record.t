#!/usr/bin/perl -I../blib/lib

use strict;
use warnings;
use Test::More tests => 10;

use Mail::DKIM::Verifier;
use Mail::DKIM::DkPolicy;
use Mail::DKIM::DkimPolicy;
use Mail::DKIM::AuthorDomainPolicy;

# A domain with a wildcard TXT record that isn't a policy record, so it
# also answers the policy lookups. RFC 5617, section 4.2.1: such records
# are ignored, like no record at all.
my $WILDCARD = '29c427f856e239d161fafb77c8471ea3a3e09f9f6bc66daeb2179386f3b13c1';

no warnings 'redefine';
*Mail::DKIM::DNS::query = sub {
    my ( $name, $type ) = @_;
    $@ = '';
    return bless { type => $type, data => $WILDCARD }, 'FakeDNS::Record'
      if $name =~ /(^|\.)wildcard\.example$/;
    $@ = 'NXDOMAIN';
    return;
};
use warnings 'redefine';

foreach my $class (
    qw( Mail::DKIM::DkPolicy Mail::DKIM::DkimPolicy
        Mail::DKIM::AuthorDomainPolicy )
  )
{
    my $policy = eval {
        $class->fetch(
            Protocol => 'dns',
            Domain   => 'wildcard.example',
        );
    };
    ok( $policy, "$class: fetch() ignores an invalid record" )
      or diag $@;
    ok( $policy && $policy->is_implied_default_policy,
        "$class: default policy" );
}

my $message = <<'END';
From: Someone <someone@wildcard.example>
Subject: test message

This message has no signature.
END
$message =~ s/\n/\015\012/gs;

my $dkim = Mail::DKIM::Verifier->new();
$dkim->PRINT($message);
$dkim->CLOSE;

my @policies = eval { $dkim->policies };
ok( !$@, "policies() doesn't die" ) or diag $@;
is( scalar @policies, 3, "policies() returns all three policies" );
ok( !( grep { !$_->is_implied_default_policy } @policies ),
    "all of them are the default policy" );
is( $policies[-1]->apply($dkim), 'neutral', "ADSP result is neutral" );

package FakeDNS::Record;

sub type    { $_[0]{type} }
sub txtdata { $_[0]{data} }
