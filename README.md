# HNPFuzzer

HNPFuzzer is a high performance fuzzing framework designed for network applications. In HNPFuzzer, the test cases and response messages between the client and server are transmitted through the shared memory, guided by a precise synchronizer, rather than the socket interfaces. Moreover, HNPFuzzer provides a persistent mode attempting to fuzz a service instance more than one time by examining long term memory. For more information, please refer to our TDSC 2023 [paper](https://ieeexplore.ieee.org/document/10262045).

## ProFuzzBench

ProFuzzBench is a mainstream benchmark on protocol fuzzing, including 13 representative open-source network applications for 10 popular protocols and relevant tools to automate experimentation. Please note that several modifications are applied in our benchmark to adapt to HNPFuzzer, e.g., patches that prevent the server from forking child are removed in bftpd and pureftpd when activating persistent mode. More details can be found in [HNPFuzzer-ProFuzzBench](https://github.com/veltavid/HNPFuzzer-ProFuzzBench). 

## installation

### Prerequisties

```bash
sudo apt-get install clang llvm graphviz-dev libcap-dev
```

### Build

```bash
git clone https://github.com/veltavid/HNPFuzzer.git
cd HNPFuzzer
make clean all
cd llvm_mode && make
```

## Usage

HNPFuzzer can be run using the same command line options as AFLNet. However, there are different options shown as below.

- ***-Y***: (optional) disable synchronization based on shared memory
- ***-I***: (optional) disable message transmission based on shared memory
- ***-K***: (optional) disable persistent mode checking and send SIGTERM signal to gracefully terminate the server after consuming all request messages
- ***-b***: (optional) enable the additional crash check. Each time a crash occurs, the fuzzer will disactivate all the components of HNPFuzzer and rerun the target to verify the discovered crash sample. However, this consequently affects the fuzzer's performance.

