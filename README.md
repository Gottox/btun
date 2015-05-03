BTUN 1 "May 2015" btun-0.1 "User Commands"
==========================================

NAME
----

btun - bidirectional tunnel through a webbrowser

SYNOPSIS
--------

**btun** [**-d**] [**-l** `local`] [**-s** `remote`] [**-t** `tundev`] [`bind_address`] `port`

**btun** [**-v**]

DESCRIPTION
-----------

**btun** establishes a bidirectional connection between two hosts
using one or more browsers as mediators.

	       host1        mediator       host2
	      +------+    +---------+    +------+
	  +---| btun |----| browser |----| btun |---+
	  |   +------+    +---------+    +------+   |
	 tunX                                      tunX

If multiple browsers are connected, every package is sent to all
mediators. The receiver takes the first package and drops the rest.

OPTIONS
-------

**-d**
prints debug messages

**-l** `local`
sets the local address for a websocket connection. If unspecified
Javascript tries to guess an address. This option has no effect
if **-s** is not specified

**-s** `remote`
enables server mode: an index is delivered which connects the
browser via websocket to `local` and `remote`. `local` is guessed
but can be set explicitly via the **-l** option.

EXAMPLES
--------

TODO

DIAGNOSTICS
-----------

Use tcpdump(1)m the **-d** flag and the debug tools of your browser to debug
network problems.

BUGS
----

Currently **btun** does not encrypt any data. Both, a passive attacker
and the mediator can read any data sent through btun.
