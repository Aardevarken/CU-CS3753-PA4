# File: Makefile
# By: Morgan Garske
# Project: CSCI 3753 Programming Assignment 4
# Creation Date: 04/25/2014
# Description:
#	This is the Makefile for PA4.

CC           = gcc

CFLAGSFUSE   = `pkg-config fuse --cflags`
LLIBSFUSE    = `pkg-config fuse --libs`
LLIBSOPENSSL = -lcrypto

CFLAGS = -c -g -Wall -Wextra
LFLAGS = -g -Wall -Wextra

ENCRYPTED_FS = pa4-encfs

.PHONY: all encrypted-fs clean

all: encrypted-fs

encrypted-fs: $(ENCRYPTED_FS)

pa4-encfs: pa4-encfs.o aes-crypt.o
	$(CC) $(LFLAGS) $^ -o $@ $(LLIBSFUSE) $(LLIBSOPENSSL)

pa4-encfs.o: pa4-encfs.c
	$(CC) $(CFLAGS) $(CFLAGSFUSE) $<

aes-crypt.o: aes-crypt.c aes-crypt.h
	$(CC) $(CFLAGS) $<

clean:
	rm -f $(ENCRYPTED_FS)
	rm -f *.o
	rm -f *~
