## BFT-MVBA

![build status](https://img.shields.io/github/actions/workflow/status/asonnino/hotstuff/rust.yml?style=flat-square&logo=GitHub&logoColor=white&link=https%3A%2F%2Fgithub.com%2Fasonnino%2Fhotstuff%2Factions)
[![golang](https://img.shields.io/badge/golang-1.21.1-blue?style=flat-square&logo=golang)](https://www.rust-lang.org)
[![python](https://img.shields.io/badge/python-3.9-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/release/python-390/)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

This repo provides a minimal implementation of the various mvba consensus protocol. The codebase has been designed to be small, efficient, and easy to benchmark and modify. It has not been designed to run in production but uses real cryptography (kyber), networking(native), and storage (nutsdb).

Say something about bft-mvba...

## Quick Start

lightDAG is written in Golang, but all benchmarking scripts are written in Python and run with Fabric. To deploy and benchmark a testbed of 4 nodes on your local machine, clone the repo and install the python dependencies:

```shell
git clone https://github.com/ac-dcz/BFT-MVBA
cd BFT-MVBA/benchmark
pip install -r requirements.txt
```

You also need to install tmux (which runs all nodes and clients in the background).
Finally, run a local benchmark using fabric:

```shell
fab local
```

This command may take a long time the first time you run it (compiling golang code in release mode may be slow) and you can customize a number of benchmark parameters in fabfile.py. When the benchmark terminates, it displays a summary of the execution similarly to the one below.

- [CKPS01-MVBA](https://eprint.iacr.org/2001/006)
```
Setting up testbed...
Running mvba
0 byzantine nodes
tx_size 250 byte, batch_size 500, rate 5000 tx/s
DDOS attack False
Waiting for the nodes to synchronize...
Running benchmark (30 sec)...
Parsing logs...

-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: mvba 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 5,000 tx/s
 Transaction size: 250 B
 Batch size: 500 tx/Batch
 Faults: 0 nodes
 Execution time: 30 s

 + RESULTS:
 Consensus TPS: 4,877 tx/s
 Consensus latency: 94 ms

 End-to-end TPS: 4,874 tx/s
 End-to-end latency: 586 ms
-----------------------------------------
```

- [VABA](https://dl.acm.org/doi/10.1145/3293611.3331612)
```
Setting up testbed...
Running vaba
0 byzantine nodes
tx_size 250 byte, batch_size 500, rate 5000 tx/s
DDOS attack False
Waiting for the nodes to synchronize...
Running benchmark (30 sec)...
Parsing logs...

-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: vaba 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 5,000 tx/s
 Transaction size: 250 B
 Batch size: 500 tx/Batch
 Faults: 0 nodes
 Execution time: 30 s

 + RESULTS:
 Consensus TPS: 4,962 tx/s
 Consensus latency: 76 ms

 End-to-end TPS: 4,953 tx/s
 End-to-end latency: 119 ms
----------------------------------------
```

- [SMVBA](https://eprint.iacr.org/2022/027)
```
Starting local benchmark
Setting up testbed...
Running smvba
0 byzantine nodes
tx_size 250 byte, batch_size 500, rate 5000 tx/s
DDOS attack False
Waiting for the nodes to synchronize...
Running benchmark (30 sec)...
Parsing logs...

-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: smvba 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 5,000 tx/s
 Transaction size: 250 B
 Batch size: 500 tx/Batch
 Faults: 0 nodes
 Execution time: 30 s

 + RESULTS:
 Consensus TPS: 5,140 tx/s
 Consensus latency: 70 ms
 
 End-to-end TPS: 5,130 tx/s
 End-to-end latency: 105 ms
-----------------------------------------
```

- Mercury

```
Starting local benchmark
Setting up testbed...
Running Mercury
0 byzantine nodes
tx_size 250 byte, batch_size 500, rate 5000 tx/s
DDOS attack False
Waiting for the nodes to synchronize...
Running benchmark (30 sec)...
Parsing logs...

-----------------------------------------
 SUMMARY:
-----------------------------------------
 + CONFIG:
 Protocol: Mercury 
 DDOS attack: False 
 Committee size: 4 nodes
 Input rate: 5,000 tx/s
 Transaction size: 250 B
 Batch size: 500 tx/Batch
 Faults: 0 nodes
 Execution time: 30 s

 + RESULTS:
 Consensus TPS: 15,780 tx/s
 Consensus latency: 121 ms

 End-to-end TPS: 15,748 tx/s
 End-to-end latency: 156 ms
-----------------------------------------
```

## Next Steps
The wiki documents the codebase, explains its architecture and how to read benchmarks' results, and provides a step-by-step tutorial to run benchmarks on Alibaba cloud across multiple data centers (WAN).