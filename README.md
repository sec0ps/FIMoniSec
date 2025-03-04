A python based file integrity management application -- trying for something a little more light weight, less complex and less problematic than some of the more popular applications out there.

For the PIM  module to work correctly, the user the management scripts are running as must have the following access:
username ALL=(ALL) NOPASSWD: /usr/bin/lsof, /bin/cat "/proc/*/exe", /bin/ps, /bin/netstat, /bin/ss
