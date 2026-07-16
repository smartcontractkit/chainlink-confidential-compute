## Enclave example: Ticker

This example uses [chrony](https://chrony-project.org/index.html) to discipline the enclave's system clock with a direct connection to its Nitro instance's PCH device, which is connected to [Amazon's Precision Time Protocol (PTP) infrastructure](https://aws.amazon.com/blogs/compute/its-about-time-microsecond-accurate-clocks-on-amazon-ec2-instances/).


To run: on a properly configured AWS Nitro instance (see [Hello Enclave](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html) for configuration), execute `./build-and-run.sh` to launch the enclave.


Security provided by this setup for using system time includes:
- The kvm-clock is used by default, which is implemented as a page inside the enclave's memory managed by the Nitro Hypervisor ([read more](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/#time)).
- The chrony daemon runs in the background and checks Amazon's PTP time every second, which it uses to adjust the enclave's system clock.
- A chrony tracking report is printed on every run. This report may be included in attestations produced by the enclave, such that dependent systems can require that the enclave clock stay synchronized with Amazon PTP time within some acceptable error threshold.

<br/>

Sample Output:
```
2025/05/16 20:35:44 Current clock source: kvm-clock
2025/05/16 20:35:44 Available clock sources: kvm-clock tsc
2025/05/16 20:30:22 Time: 1747427422 (formatted: 2025-05-16T20:30:22Z)
2025/05/16 20:30:22 Chrony sources: 
MS Name/IP address         Stratum Poll Reach LastRx Last sample               
===============================================================================
#* PHC0                          0   0   377     0     +5ns[  -16ns] +/-   31ns
2025/05/16 20:30:22 PTP time synchronization is active
2025/05/16 20:30:22 Chrony tracking update: 
Reference ID    : 50484330 (PHC0)
Stratum         : 1
Ref time (UTC)  : Fri May 16 20:30:21 2025
System time     : 0.000000018 seconds slow of NTP time
Last offset     : -0.000000021 seconds
RMS offset      : 0.006649632 seconds
Frequency       : 4.926 ppm slow
Residual freq   : -0.001 ppm
Skew            : 0.029 ppm
Root delay      : 0.000000001 seconds
Root dispersion : 0.000000733 seconds
Update interval : 1.0 seconds
Leap status     : Normal
```