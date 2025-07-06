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
Currently displaying the MIT license in the LICENSE file. Not sure if MIT or BSD is more appropriate.

Currently not distributing a binary, so it shouldn't matter too much, despite Rust not having a stable ABI for dynamic linking.
