This is a raw socket networking library with the following design goals:
 - No dependencies
 - No unrepresentable data (If you can send it, you should be able to build it with this library)
 - Copy and paste works (Copy a packet, paste it into a Python REPL, and everything should just work)

Some non-goals:
 - Support for OSes other than Linux
 - Stable API

Some stretch goals:
 - Support for packet filtering
