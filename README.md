cpuminer-sha3
==============

cpuminer for SHA3 based coins like Zen Protocol. Fully compatible with our sha3 pool at [pool.atomminer.com](https://pool.atomminer.com)
miner was built using multiple versions of various cpuminers.

Dependencies 
-----------------------------
+ libcurl
+ libjansson
+ libpthreads

Build
-----------------------------
Project was created and tested on Ubuntu 17.10 but should compile with no problem on other distros. Windows build shouldn't be a problem either. Open cpuminer-sha3.pro in Qt Creator and hit build or just go with 
```sh
$ make -j4
```
in the project folder.

Usage
-----------------------------
Usage: cpuminer-sha3 [OPTIONS]
Options:
  -u, --user=USERNAME   username for mining server
  -p, --pass=PASSWORD   password for mining server
  -t, --threads=N       number of miner threads (default: number of processors)
  -r, --retries=N       number of times to retry if a network call fails
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)
  -T, --timeout=N       timeout for stratum (default: 300 seconds)
  -V, --version         display version information and exit
  -h, --help            display this help text and exit

cpuminer connects and works only with sha3.pool.atomminer.com:4123 stratum endpoint.
No registration needed, just use your ZP wallet address as a login to start mining.

use -t swith to specify amount of mining threads.

Optionally, you can specify initial mining difficulty 'd=1' for diff==1 as a password:
```sh
$ ./cpuminer-sha3 -u zen1qnwls4fxx48yz92yyytmzpy5e4pk7qsh69hjgx06z6x4n5n6sp6usuhw3tv -p d=1 -t 4
```
