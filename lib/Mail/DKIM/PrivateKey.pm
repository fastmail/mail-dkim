package Mail::DKIM::PrivateKey;
use strict;
use warnings;
# VERSION
# ABSTRACT: a private key loaded in memory for DKIM signing

# Copyright 2005-2007 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>
#
# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

=head1 SYNOPSIS

 my $key1 = Mail::DKIM::PrivateKey->load(
               File => '/path/to/private.key');

 my $key2 = Mail::DKIM::PrivateKey->load(
               Data => $base64);

 # use the loaded key in a DKIM signing object
 my $dkim = Mail::DKIM::Signer->new(
               Key => $key2,
             );

=cut

use base 'Mail::DKIM::Key';
use Carp;
*calculate_EM = \&Mail::DKIM::Key::calculate_EM;
use Crypt::OpenSSL::RSA;
use Crypt::PK::Ed25519;

=head1 CONSTRUCTOR

=head2 load() - loads a private key into memory

 my $key1 = Mail::DKIM::PrivateKey->load(
               File => '/path/to/private.key');

Loads the Base64-encoded key from the specified file.

  my $key2 = Mail::DKIM::PrivateKey->load(Data => $base64);

Loads the Base64-encoded key from a string already in memory.

  my $key3 = Mail::DKIM::PrivateKey->load(Cork => $openssl_object);

Creates a Mail::DKIM::PrivateKey wrapper object for the given
OpenSSL key object. The key object should be of type
L<Crypt::OpenSSL::RSA>.

=cut

sub load {
    my $class = shift;
    my %prms  = @_;

    my $self = bless {}, $class;

    $self->{'TYPE'} = ( $prms{'Type'} or 'rsa' );

    if ( $prms{'Data'} ) {
        $self->{'DATA'} = $prms{'Data'};
    }
    elsif ( defined $prms{'File'} ) {
        my @data;
        open my $file, '<', $prms{'File'}
          or die "Error: cannot read $prms{File}: $!\n";
        while ( my $line = <$file> ) {
            chomp $line;
            next if $line =~ /^---/;
            push @data, $line;
        }
        $self->{'DATA'} = join '', @data;
        close $file;
    }
    elsif ( $prms{'Cork'} ) {
        $self->{'CORK'} = $prms{'Cork'};
    }
    else {
        croak 'missing required argument';
    }

    return $self;
}

=head1 METHODS

=head2 cork() - access the underlying OpenSSL key object

  $openssl_object = $key->cork;

The returned object is of type L<Crypt::OpenSSL::RSA>.

=cut

sub _convert_rsa {
    my $self = shift;

    # have to PKCS1ify the privkey because openssl is too finicky...
    my $pkcs = "-----BEGIN RSA PRIVATE KEY-----\n";

    for ( my $i = 0 ; $i < length $self->data ; $i += 64 ) {
        $pkcs .= substr $self->data, $i, 64;
        $pkcs .= "\n";
    }

    $pkcs .= "-----END RSA PRIVATE KEY-----\n";

    my $cork;

    eval {
        local $SIG{__DIE__};
        $cork = new_private_key Crypt::OpenSSL::RSA($pkcs);
    1
    } || do {
        $self->errorstr($@);
        return;
    };

    $cork
      or return;

    # segfaults on my machine
    #	$cork->check_key or
    #		return;

    $self->cork($cork);
    return 1;
}

sub _convert_ed25519 {
    my $self = shift;
    my $cork;

    eval {
        local $SIG{__DIE__};
        $cork = new Crypt::PK::Ed25519;

        # Prepend/append with PEM boilerplate
        my $pem = "-----BEGIN PRIVATE KEY-----\n";
        $pem .= $self->data;
        $pem .= "\n";
        $pem .= "-----END PRIVATE KEY-----\n";

        # Pass PEM text buffer
        $cork->import_key(\$pem)
            or die 'failed to load Ed25519 private key';

        # Alternatively, import_raw_key() could be used,
        # but requires the 32-byte key, which must be extracted
        # from the ASN.1 structure first.

    1
    } || do {
        $self->errorstr($@);
        return;
    };

    $cork
      or return;

    $self->cork($cork);
    return 1;
}

sub convert {
    my $self = shift;

    $self->data
      or return;

    return $self->_convert_rsa if $self->{TYPE} eq 'rsa';
    return $self->_convert_ed25519 if $self->{TYPE} eq 'ed25519';
    self->errorstr('unsupported key type');
    return;
}

#deprecated
sub sign {
    my $self = shift;
    my $mail = shift;

    return $self->cork->sign($mail);
}

#deprecated- use sign_digest() instead
sub sign_sha1_digest {
    my $self = shift;
    my ($digest) = @_;
    return $self->sign_digest( 'SHA-1', $digest );
}

=head2 sign_digest()

Cryptographically sign the given message digest.

  $key->sign_digest('SHA-1', sha1('my message text'));

The first parameter is the name of the digest: one of "SHA-1", "SHA-256".

The second parameter is the message digest as a binary string.

The result should be the signed digest as a binary string.

=cut

sub _sign_digest_rsa {
    my $self = shift;
    my ( $digest_algorithm, $digest ) = @_;

    my $rsa_priv = $self->cork;
    $rsa_priv->use_no_padding;
    my $k = $rsa_priv->size;
    my $EM = calculate_EM( $digest_algorithm, $digest, $k );
    return $rsa_priv->decrypt($EM);
}

sub _sign_digest_ed25519 {
    my $self = shift;
    my ( $digest_algorithm, $digest ) = @_;

    my $ed = $self->cork;
    if ( !$ed ) {
        $@ = $@ ne '' ? "Ed25519 failed: $@" : 'Ed25519 unknown problem';
        die;
    }
    return $ed->sign_message($digest);
}

sub sign_digest {
    my $self = shift;
    my ( $digest_algorithm, $digest ) = @_;

    return $self->_sign_digest_rsa($digest_algorithm, $digest) if $self->{TYPE} eq 'rsa';
    return $self->_sign_digest_ed25519($digest_algorithm, $digest) if $self->{TYPE} eq 'ed25519';
    die 'unsupported key type';
}

=cut

1;
