# TranProc
Transform CRIU images between different architectures for native binaries.

Refer to our [wiki](https://github.com/ssrg-vt/TranProc/wiki) for a tutorial on how to migrate binaries with TransProc.

TransProc supports live migration of natively compiled Linux applications across servers with CPUs of different architectures. TransProc not only supports live-migration on VMs but also on bare-metal. 

TransProc builds on top of [criu](https://github.com/checkpoint-restore/criu) to dump a running binary and then transforms the criu generated artifacts to support restoration on servers of different architecture. Currently TransProc supports migration on x86-64 and aarch64 CPUs. TransProc uses LLVM's stack maps to generate stack and register metadata and implements a stack and register transformation logic leveraging the generated metadata. It does this on criu dumped images and hence does not involve injecting transformation runtime within the binary image improving security.

This repository provides the CRIU wrapper and the compiler toolchain can be found on [this](https://github.com/ssrg-vt/popcorn-compiler/tree/stack_pop) branch of the popcorn compiler repository.