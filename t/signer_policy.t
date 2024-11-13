#!/usr/bin/perl -I../lib

use strict;
use warnings;
use Test::Simple tests => 32;

use Mail::DKIM::Signer;

my $tdir = -f "t/test.key" ? "t" : ".";
my $keyfile = "$tdir/test.key";
my $keyfile_ed = "$tdir/test.ed.key";
my $policy;
my $dkim;

# test specification of a policy "class"
$policy = "MySignerPolicy";
$dkim   = sign_sample_using_args(
    Policy  => $policy,
    KeyFile => $keyfile
);
ok( $dkim, "processed message" );

my $signature = $dkim->signature;
ok( $signature, "signature() works" );

print "# signature=" . $signature->as_string . "\n";
ok( $signature->as_string =~ /d=different-domain/,
    "got expected domain in signature" );
ok( $signature->as_string =~ /c=relaxed/,
    "got expected canonicalization method in signature" );
ok(
    $signature->as_string =~ /a=rsa-sha256/,
    "got expected algorithm in signature"
);

# try using a policy "object"
$policy = bless {}, "MySignerPolicy";
$dkim = sign_sample_using_args(
    Policy  => $policy,
    KeyFile => $keyfile
);
ok( $dkim, "processed message" );

$signature = $dkim->signature;
ok( $signature, "signature() works" );

print "# signature=" . $signature->as_string . "\n";
ok( $signature->as_string =~ /d=different-domain/,
    "got expected domain in signature" );

# now a policy as an anonymous subroutine
$policy = sub {
    my $signer = shift;
    $signer->domain("different-domain.example");
    $signer->method("relaxed");
    $signer->algorithm("rsa-sha256");
    $signer->selector("beta");
    $signer->key_file($keyfile);
    return 1;
};
$dkim = sign_sample_using_args( Policy => $policy );
ok( $dkim, "processed message" );

$signature = $dkim->signature;
ok( $signature, "got signature" );

# this policy should not produce any signature
$policy = sub {
    my $signer = shift;
    return 0;
};
$dkim = sign_sample_using_args(
    Policy  => $policy,
    KeyFile => $keyfile
);
ok( $dkim, "processed message" );

$signature = $dkim->signature;
ok( !$signature, "no signature" );

# this policy should produce a DomainKeys signature
use Mail::DKIM::DkSignature;
$policy = sub {
    my $signer = shift;
    $signer->add_signature(
        new Mail::DKIM::DkSignature(
            Algorithm => "rsa-sha1",
            Method    => "nofws",
            Headers   => $dkim->headers,
            Domain    => "different-domain.example",
            Selector  => "beta",
        )
    );
    return;
};
$dkim = sign_sample_using_args(
    Policy  => $policy,
    KeyFile => $keyfile
);
ok( $dkim, "processed message" );

$signature = $dkim->signature;
ok( $signature, "got signature" );

print "# signature=" . $signature->as_string . "\n";
ok( $signature->as_string =~ /DomainKey-Signature/,
    "got DomainKeys signature" );
ok( $signature->as_string =~ /d=different-domain/,
    "got expected domain in signature" );
ok( $signature->as_string =~ /c=nofws/,
    "got expected canonicalization method in signature" );
ok( $signature->as_string !~ /bh=/, "no bh= tag in signature" );

# this policy should produce two signature (one DKIM and one DomainKeys)
$policy = sub {
    my $signer = shift;
    $signer->add_signature(
        new Mail::DKIM::DkSignature(
            Algorithm => "rsa-sha1",
            Method    => "nofws",
            Headers   => $dkim->headers,
            Domain    => "different-domain.example",
            Selector  => "beta",
        )
    );
    $signer->add_signature(
        new Mail::DKIM::Signature(
            Algorithm => "rsa-sha256",
            Method    => "relaxed",
            Headers   => $dkim->headers,
            Domain    => "different-domain.example",
            Selector  => "beta",
        )
    );
};
$dkim = sign_sample_using_args(
    Policy  => $policy,
    KeyFile => $keyfile
);
ok( $dkim, "processed message" );

$signature = $dkim->signature;
ok( $signature, "got signature" );

print "# signature=" . $signature->as_string . "\n";
ok( $signature->as_string =~ /^DKIM-Signature/, "got DKIM signature" );

my @multiple = $dkim->signatures;
ok( @multiple == 2, "got 2 signatures" );
ok( $multiple[0]->as_string =~ /^DomainKey-Signature/,
    "first is DomainKeys signature" );
ok( $multiple[1]->as_string =~ /^DKIM-Signature/, "second is DKIM signature" );

# this policy should produce two DKIM signatures, one rsa and one ed25519
$policy = sub {
    my $signer = shift;
    $signer->add_signature(
        new Mail::DKIM::Signature(
            Algorithm => "rsa-sha256",
            Method    => "relaxed",
            Headers   => $signer->headers,
            Domain    => "different-domain.example",
            Selector  => "beta",
            Key       => Mail::DKIM::PrivateKey->load( Type => 'rsa',
                                                       File => $keyfile),
        )
    );
    $signer->add_signature(
        new Mail::DKIM::Signature(
            Algorithm => "ed25519-sha256",
            Method    => "relaxed",
            Headers   => $signer->headers,
            Domain    => "different-domain.example",
            Selector  => "gamma",
            Key       => Mail::DKIM::PrivateKey->load( Type => 'ed25519',
                                                       File => $keyfile_ed),
        )
    );
};
$dkim = sign_sample_using_args(
    Policy  => $policy,
);
ok( $dkim, "processed message" );

@multiple = $dkim->signatures;
ok( @multiple == 2, "got 2 signatures" );

print "# signature=" . $multiple[0]->as_string . "\n";
ok( $multiple[0]->as_string =~ /a=rsa-sha256/,
    "got expected algorithm in first signature" );

print "# signature=" . $multiple[1]->as_string . "\n";
ok( $multiple[1]->as_string =~ /a=ed25519-sha256/,
    "got expected algorithm in second signature" );

# same test but this time with Signer loading the private keys
$policy = sub {
    my $signer = shift;
    my $sig =
        new Mail::DKIM::Signature(
            Algorithm => "rsa-sha256",
            Method    => "relaxed",
            Headers   => $signer->headers,
            Domain    => "different-domain.example",
            Selector  => "beta",
        );
    $sig->{KeyFile} = $keyfile;
    $signer->add_signature($sig);

    $sig =
        new Mail::DKIM::Signature(
            Algorithm => "ed25519-sha256",
            Method    => "relaxed",
            Headers   => $signer->headers,
            Domain    => "different-domain.example",
            Selector  => "gamma",
        );
    $sig->{KeyFile} = $keyfile_ed;
    $signer->add_signature($sig);
};
$dkim = sign_sample_using_args(
    Policy  => $policy,
);
ok( $dkim, "processed message" );

@multiple = $dkim->signatures;
ok( @multiple == 2, "got 2 signatures" );

print "# signature=" . $multiple[0]->as_string . "\n";
ok( $multiple[0]->as_string =~ /a=rsa-sha256/,
    "got expected algorithm in first signature" );

print "# signature=" . $multiple[1]->as_string . "\n";
ok( $multiple[1]->as_string =~ /a=ed25519-sha256/,
    "got expected algorithm in second signature" );

sub sign_sample_using_args {
    my %args = @_;

    my $dkim = Mail::DKIM::Signer->new(%args)
      or die "couldn't create signer object";

    my $sample_email = <<END_OF_SAMPLE;
From: jason <jason\@example.org>
Subject: hi there

this is a sample message
END_OF_SAMPLE
    $sample_email =~ s/\n/\015\012/gs;

    $dkim->PRINT($sample_email);
    $dkim->CLOSE;
    return $dkim;
}

package MySignerPolicy;
use Mail::DKIM::SignerPolicy;
use base "Mail::DKIM::SignerPolicy";

sub apply {
    my ( $self, $signer ) = @_;

    $signer->domain("different-domain.example");
    $signer->method("relaxed");
    $signer->algorithm("rsa-sha256");
    $signer->selector("beta");
    return 1;
}
