A lightweight Python-based system integrity management application, designed to be simpler, more efficient, and less problematic than some of the more complex alternatives available.  

This initial version is built entirely in Python and is designed to run on any Linux-based system with Python installed. 

A Windows version is planned for a future release.  

To ensure proper functionality, the user running the management scripts must have sudo access to the following commands:  

username ALL=(ALL) NOPASSWD: /usr/bin/lsof, /bin/cat, /bin/ps, /bin/netstat, /bin/ss, /usr/bin/readlink
