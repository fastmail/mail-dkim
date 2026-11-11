#!/usr/bin/perl -I../lib

# the ARC verifier's result_detail gives the reason the chain failed

use strict;
use warnings;
use Test::More tests => 8;

use Crypt::OpenSSL::RSA;
use Mail::DKIM::ARC::Signer;
use Mail::DKIM::ARC::Verifier;

my $tdir    = -f "t/test.key" ? "t" : ".";
my $keyfile = "$tdir/test.key";

# publish the test key as test._domainkey.example.org
my $public_key = do {
    open my $fh, '<', $keyfile or die "$keyfile: $!";
    local $/;
    my $rsa = Crypt::OpenSSL::RSA->new_private_key(<$fh>);
    my $pem = $rsa->get_public_key_x509_string;
    $pem =~ s/-----[^-]+-----|\s+//g;
    $pem;
};
my $publish = 1;
{
    no warnings 'redefine';
    *Mail::DKIM::DNS::query = sub {
        my ( $domain, $type ) = @_;
        return ()
          unless $publish and lc $domain eq 'test._domainkey.example.org';
        my $txt = "v=DKIM1; k=rsa; p=$public_key";
        return bless \$txt, 'FakeDNS::Record';
    };
}

sub sign {
    my ( $msg, $ar ) = @_;
    my $arc = Mail::DKIM::ARC::Signer->new(
        Algorithm => 'rsa-sha256',
        Domain    => 'example.org',
        SrvId     => 'example.org',
        Selector  => 'test',
        Chain     => 'ar',
        KeyFile   => $keyfile,
    );
    $arc->PRINT("Authentication-Results: example.org; $ar\015\012$msg");
    $arc->CLOSE;
    return $arc->as_string . $msg;
}

my $arc;

sub detail {
    my ($msg) = @_;
    $arc = Mail::DKIM::ARC::Verifier->new;
    $arc->PRINT($msg);
    $arc->CLOSE;
    return $arc->result_detail;
}

my $msg = "From: a\@example.org\015\012Subject: hi\015\012\015\012hello\015\012";
my $sealed = sign( $msg, 'spf=pass smtp.mailfrom=example.org' );

is( detail($msg),    'none', 'no ARC headers' );
is( detail($sealed), 'pass', 'a valid chain' );

( my $body = $sealed ) =~ s/hello/goodbye/;
is( detail($body), 'fail (body has been altered)',
    'a changed body: the ARC-Message-Signature reason' );

( my $aar = $sealed ) =~ s/spf=pass/spf=fail/;
is( detail($aar), 'fail (message has been altered)',
    'a changed ARC-Authentication-Results: the ARC-Seal reason' );

is( detail("ARC-Authentication-Results: i=2; evil; dmarc=pass\015\012$sealed"),
    'fail (missing Arc-Seal 2)', 'an ARC-Authentication-Results no seal covers' );

( my $cv = $sealed ) =~ s/cv=none/cv=pass/;
is( detail($cv), 'fail (message has been altered)', 'a changed cv= on the first seal' );

$publish = 0;
is( detail($sealed), 'invalid (public key: not available)',
    'no public key' );
$publish = 1;

$arc = Mail::DKIM::ARC::Verifier->new;
ok( !eval { $arc->result_detail(1); 1 }, 'result_detail takes no arguments' );

package FakeDNS::Record;

sub type { return 'TXT' }
sub txtdata { return ${ $_[0] } }
