# SyscallsExample

Simple project using syscalls (via [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)) to execute MessageBox shellcode in a target process.

This doesn't use Windows API calls to allocate memory, create the thread etc so bypasses some detections and can make it harder for investigators and reverse engineers to determine what is going on.

Accompanying blog post: https://jmpesp.me/malware-analysis-syscalls-example/
