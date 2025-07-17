# crab-doas
Doas port for silly crab language

Many features not implemented. Do not use this in production. Unlike certain developers, I'm not gonna pretend some little toy is production-ready, or even close.

Current implementation status: Works on my machine

External dependency: libpam0g-dev

# Features
* PAM authentication
* Logging
* Option: nopass
* Option: persist
* Option: nolog
* Option: cmd
* Lots of jank just waiting to be ironed out

Persist had to be implemented differently from the way it's done in opendoas, so I changed the location of the timestamps

# License
In the spirit of minimizing any potential legal issues, the license is updated to match the OpenDoas license and include the copyright notices from the repository I used as a reference.

# Testing after build
In order to test the binary, because it's a setuid program, you must make the owner `root:root` and set `u+s` with chmod, allowing it to run itself as root at least on Linux. Special bits can do different things on different systems.
