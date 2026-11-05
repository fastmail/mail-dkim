package Mail::DKIM::Canonicalization::seal;
use strict;
use warnings;
# VERSION
# ABSTRACT: arc seal canonicalization

# Copyright 2017 FastMail Pty Ltd. All Rights Reserved.
# Bron Gondwana <brong@fastmailteam.com>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

# This canonicalization is for the ARC-Seal header from
# https://tools.ietf.org/html/draft-ietf-dmarc-arc-protocol-06
# Rather than having a 'h' property, it processes the headers in
# a pre-defined way.
#
# 5.1.1.3.  Deterministic (Implicit) 'h' Tag Value for ARC-Seal
#
#   In this section, the term "scope" is used to indicate those header
#   fields signed by an ARC-Seal header field.  A number in parentheses
#   indicates the instance of that field, starting at 1.  The suffix "-
#   no-b" is used with an ARC-Seal field to indicate that its "b" field
#   is empty at the time the signature is computed, as described in
#   Section 3.5 of [RFC6376].  "AAR" refers to ARC-Authentication-
#   Results, "AMS" to ARC-Message-Signature, "AS" to ARC-Seal, and "ASB"
#   to an ARC-Seal with an empty "b" tag.
#
#   Generally, the scope of an ARC set for a message containing "n" ARC
#   sets is the concatenation of the following, for x (instance number)
#   from 1 to n:
#
#   o  AAR(x);
#
#   o  AMS(x);
#
#   o  ASB(x) if x = n, else AS(x)
#
#   Thus for a message with no seals (i.e., upon injection), the scope of
#   the first ARC set is AAR(1):AMS(1):ASB(1).  The ARC set thus
#   generated would produce a first ARC-Seal with a "b" value.  The next
#   ARC set would include in its signed content the prior scope, so it
#   would have a scope of AAR(1):AMS(1):AS(1):AAR(2):AMS(2):ASB(2).
#
#   Note: Typically header field sets appear within the header in
#   descending instance order.

use base 'Mail::DKIM::Canonicalization::relaxed';
use Carp;

sub init {
    my $self = shift;
    $self->SUPER::init;
}

# ARC limits instance numbers to 1..50 (RFC 8617 section 4.2.1)
our $MAX_INSTANCE = 50;

# how to find the instance of each ARC header
my %ARC_HEADERS = (

    # i= comes first, and the rest is free text which may itself
    # contain "; i=" (RFC 8617 section 4.1.1)
    'arc-authentication-results' =>
      qr/^ARC-Authentication-Results:\s*i=(\d+)\s*;/i,

    # these are tag lists, so i= may be anywhere; this ugly pattern
    # matches header: field; field; ... i=N
    # (not (?:[^;]*;\s*)*, where whitespace after a ; can be taken by
    # either part, which is quadratic in a whitespace run)
    'arc-message-signature' =>
      qr/^ARC-Message-Signature:(?:[^;]*;)*\s*i=(\d+)/i,
    'arc-seal' => qr/^ARC-Seal:(?:[^;]*;)*\s*i=(\d+)/i,
);

# index the ARC headers by lowercased name and instance, keeping the
# first of each, so each lookup doesn't have to scan the whole header
sub _index_headers {
    my ( $self, $headers ) = @_;
    my %index;
    foreach my $hdr (@$headers) {
        next unless $hdr =~ /^ARC-/i;
        foreach my $h ( keys %ARC_HEADERS ) {
            next unless $hdr =~ $ARC_HEADERS{$h};
            ( my $i = $1 ) =~ s{^0+(?=\d)}{};
            $index{$h}{$i} = $hdr unless exists $index{$h}{$i};
        }
    }
    return \%index;
}

sub _output_indexed_header {
    my ( $self, $index, $h, $i ) = @_;
    my $hdr = $index->{ lc $h }{$i};
    return unless defined $hdr;
    $hdr =~ s/\015\012\z//s;
    $self->output( $self->canonicalize_header($hdr) . "\015\012" );
}

sub finish_header {
    my $self = shift;
    my %args = @_;

    my $i = $self->{Signature}->identity();
    return unless $i =~ m{^\d+$};    # don't waste time if i= is bogus
    $i =~ s{^0+(?=\d)}{};
    return if $i < 1 or $i > $MAX_INSTANCE;

    # the index is shared through HeaderIndex by every seal on the message
    my $index = $args{HeaderIndex} ? $args{HeaderIndex}{seal} : undef;
    unless ($index) {
        $index = $self->_index_headers( $args{Headers} );
        $args{HeaderIndex}{seal} = $index if $args{HeaderIndex};
    }

    my $chain = $args{Chain};
    $chain = $self->{Signature}->chain() if ! defined $chain;

    # we include the seal for everything else
    # if the previous status was pass
    if ( $chain eq 'pass' ) {
        foreach my $n ( 1 .. ( $i - 1 ) ) {
            $self->_output_indexed_header( $index, 'ARC-Authentication-Results', $n );
            $self->_output_indexed_header( $index, 'ARC-Message-Signature', $n );
            $self->_output_indexed_header( $index, 'ARC-Seal', $n );
        }
    }

    # always include this header set
    $self->_output_indexed_header( $index, 'ARC-Authentication-Results', $i );
    $self->_output_indexed_header( $index, 'ARC-Message-Signature', $i );

  # we don't add ARC-Seal at our index, because that is this signature, and it's
  # formed with standard DKIM style, so automatically appeneded
}

sub add_body {

    # no body add
}

1;
