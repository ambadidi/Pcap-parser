# Pcap-parser
## Setup
To run this project:

```
$ cd parser/
$ cargo build
$ ./target/debug/parser ../mdf-kospi200.20110216-0.pcap > output_unsorted.txt
$ ./target/debug/parser -r ../mdf-kospi200.20110216-0.pcap > output_reordered.txt

```
