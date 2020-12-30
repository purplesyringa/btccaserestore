all: caserestore

caserestore: main.c base58.c libbase58.h sha256.c sha256.h
	clang main.c base58.c sha256.c -o caserestore -msse -msse2 -msse3 -msse4.1 -msse4.2 -mavx -mavx2 -O2 -fno-strict-aliasing
