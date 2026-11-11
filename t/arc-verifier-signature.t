#!/usr/bin/perl -I../lib

# the ARC verifier's signature is the signature that decided the result

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
{
    no warnings 'redefine';
    *Mail::DKIM::DNS::query = sub {
        my ( $domain, $type ) = @_;
        return () unless lc $domain eq 'test._domainkey.example.org';
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

sub verify {
    my ($msg) = @_;
    my $arc = Mail::DKIM::ARC::Verifier->new;
    $arc->PRINT($msg);
    $arc->CLOSE;
    return $arc;
}

my $msg = "From: a\@example.org\015\012Subject: hi\015\012\015\012hello\015\012";
my $one = sign( $msg, 'spf=pass smtp.mailfrom=example.org' );
my $two = sign( $one, 'arc=pass' );

my $arc = verify($two);
is( $arc->result, 'pass', 'a 2-hop chain passes' );
isa_ok( $arc->signature, 'Mail::DKIM::ARC::Seal', 'its signature' );
is( $arc->signature->instance, 2, '... the most recent ARC-Seal' );

( my $body = $two ) =~ s/hello/goodbye/;
$arc = verify($body);
is( $arc->result, 'fail', 'a changed body fails' );
isa_ok( $arc->signature, 'Mail::DKIM::ARC::MessageSignature', 'its signature' );
is( $arc->signature->instance, 2, '... the most recent ARC-Message-Signature' );

( my $aar = $two ) =~ s/spf=pass/spf=fail/;
$arc = verify($aar);
isa_ok( $arc->signature, 'Mail::DKIM::ARC::Seal',
    'a changed ARC-Authentication-Results: its signature' );
is( $arc->signature->instance, 1, '... the ARC-Seal that covers it' );

package FakeDNS::Record;

sub type { return 'TXT' }
sub txtdata { return ${ $_[0] } }
