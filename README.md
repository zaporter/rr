# Overview of this project

This is a fork of rr which is designed for [librr_rs](https://github.com/zaporter/librr_rs). It will try to stay as close as possible to the original but is designed to be compiled into a dynamic library instead of an executable. 

This is a VERY immature repo. Do not use this for your own projects yet. 



# Overview of rr

rr is a lightweight tool for recording, replaying and debugging execution of applications (trees of processes and threads).
Debugging extends gdb with very efficient reverse-execution, which in combination with standard gdb/x86 features like hardware data watchpoints, makes debugging much more fun. More information about the project, including instructions on how to install, run, and build rr, is at [https://rr-project.org](https://rr-project.org). The best technical overview is currently the paper [Engineering Record And Replay For Deployability: Extended Technical Report](https://arxiv.org/pdf/1705.05937.pdf).

Or go directly to the [installation and building instructions](https://github.com/rr-debugger/rr/wiki/Building-And-Installing).

Please contribute!  Make sure to review the [pull request checklist](/CONTRIBUTING.md) before submitting a pull request.

If you find rr useful, please [add a testimonial](https://github.com/rr-debugger/rr/wiki/Testimonials).

rr development is sponsored by [Pernosco](https://pernos.co) and was originated by [Mozilla](https://www.mozilla.org).

# System requirements

* Linux kernel ≥ 3.11 is required (for `PTRACE_SETSIGMASK`).
* rr currently requires either:
  * An Intel CPU with [Nehalem](https://en.wikipedia.org/wiki/Nehalem_%28microarchitecture%29) (2010) or later microarchitecture.
  * Certain AMD Zen or later processors (see https://github.com/rr-debugger/rr/wiki/Zen)
  * Certain AArch64 microarchitectures (e.g. ARM Neoverse N1 or the Apple Silicon M-series)
* Running in a VM guest is supported, as long as the VM supports virtualization of hardware performance counters. (VMware and KVM are known to work; Xen does not.)
