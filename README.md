# tcpstat
A tool like ss that allows you to fetch TCP-info directly from the process by invoking sockstat() on its behalf

The program works only on x86_64 platform
If you encounter a error like:
'Warning: getsockopt failed with 23 pid 919643, skipping'
you will want to make sure that the stack of the target program is executable

cat /proc/<pid>/maps 
cat /proc/285699/maps |grep stack
7ffece0bb000-7ffece0d0000 rwxp 00000000 00:00 0                          [stack]

Here, the 'x' character means 'executable'
If the stack is not executable you can make it such (e.g. using execstack utility):
execstack -s /path/to/binary

