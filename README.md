# btccaserestore

An utility to restore Bitcoin addresses when letter case is lost.

Example:

```shell
$ ./caserestore 1a1zp1ep5qgefi2dmptftl5slmv7divfna
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```

Restoring case takes an average of 1 second (up to 5 seconds) for most addresses, and only more than 30 seconds for 0.5% addresses. The runtime was measured on `Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz`.


## Build

```shell
$ make
```

An x86-architecture processor with AVX2 extension is required.


## Usage

```shell
$ ./caserestore 1a1zp1ep5qgefi2dmptftl5slmv7divfna  # simple address
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

$ ./caserestore 1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1  # ambiguous address
1AAAAaAaaaaaAaAaaaAaAaAaAaAAAAaaa1
1AAAaaAAaAaaAaaAAaaAaAAAaaAaAaAAA1

$ ./caserestore 12345678abcdefghijklmnopqrstuvwxyz  # impossible address

$ ./caserestore 1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  # invalid mask
Too long string.
[exit code 1]
```
