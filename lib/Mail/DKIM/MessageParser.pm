package Mail::DKIM::MessageParser;
use strict;
use warnings;
# VERSION
# ABSTRACT: Signs/verifies Internet mail with DKIM/DomainKey signatures

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use Carp;

sub new_object {
    my $class = shift;
    return $class->TIEHANDLE(@_);
}

sub new_handle {
    my $class = shift;
    local *TMP;
    tie *TMP, $class, @_;
    return *TMP;
}

sub TIEHANDLE {
    my $class = shift;
    my %args  = @_;
    my $self  = bless \%args, $class;
    $self->init;
    return $self;
}

sub init {
    my $self = shift;

    my $buf = '';
    $self->{buf_ref}   = \$buf;
    $self->{in_header} = 1;
}

sub PRINT {
    my $self    = shift;
    my $buf_ref = $self->{buf_ref};

    if ( $$buf_ref eq '' ) {
        $self->{buf_ref} = $buf_ref = @_ == 1 ? \$_[0] : \join( '', @_ );
    } else {
        $$buf_ref .= @_ == 1 ? $_[0] : join( '', @_ );
    }

    if ( $self->{in_header} ) {
        my $pos = 0;
        my $len = length($$buf_ref);
        local $1;

        while ( $pos < $len ) {
            pos($$buf_ref) = $pos;
            if ( $$buf_ref !~ /\G(.*?\015\012)[^\ \t]/s ) {
                last;
            }
            if ( length($1) == 2 ) {
                # blank line = end of headers
                my $body_start = $pos + 2;
                $self->finish_header();
                $self->{in_header} = 0;

                # process completed body lines and buffer remainder
                my $j = rindex( $$buf_ref, "\015\012" );
                if ( $j >= $body_start ) {
                    $self->add_body( substr( $$buf_ref, $body_start,
                        $j + 2 - $body_start ) );
                    $$buf_ref = substr( $$buf_ref, $j + 2 );
                } else {
                    $$buf_ref = substr( $$buf_ref, $body_start );
                }
                return 1;
            }
            $self->add_header($1);
            $pos += length($1);
        }
        # buffer remaining header line
        $$buf_ref = $pos ? substr( $$buf_ref, $pos ) : '';
    }

    if ( !$self->{in_header} ) {
        my $j = rindex( $$buf_ref, "\015\012" );
        if ( $j >= 0 ) {
            # process completed body lines and buffer remainder
            $self->add_body( substr( $$buf_ref, 0, $j + 2 ) );
            $$buf_ref = substr( $$buf_ref, $j + 2 );
        }
    }
    return 1;
}

sub CLOSE {
    my $self    = shift;
    my $buf_ref = $self->{buf_ref};

    if ( $self->{in_header} ) {
        if ( $$buf_ref ne '' ) {

            # A line of header text ending CRLF would not have been
            # processed yet since before we couldn't tell if it was
            # the complete header. Now that we're in CLOSE, we can
            # finish the header...
            $$buf_ref =~ s/\015\012\z//s;
            $self->add_header("$$buf_ref\015\012");
        }
        $self->finish_header;
        $self->{in_header} = 0;
    }
    else {
        if ( $$buf_ref ne '' ) {
            $self->add_body($$buf_ref);
        }
    }
    $$buf_ref = '';
    $self->finish_body;
    return 1;
}

sub add_header {
    die 'add_header not implemented';
}

sub finish_header {
    die 'finish_header not implemented';
}

sub add_body {
    die 'add_body not implemented';
}

sub finish_body {

    # do nothing by default
}

sub reset {
    carp 'reset not implemented';
}

1;
