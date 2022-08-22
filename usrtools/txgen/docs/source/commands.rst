..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

.. _commands:

``*** TXGen ***``
Copyright &copy 2019-2022 Intel Corporation.

The txgen output display needs 132 columns and about 42 lines to display
currentlyt. I am using an xterm of 132x42, but you can have a larger display
and maybe a bit smaller. If you are displaying more then 4-6 lports then you
will need a wider display. TXGen allows you to view a set of lports if they
do not all fit on the screen at one time via the 'page' command.

Type 'help' at the 'TXGen>' prompt to see the complete TXGen command line
commands. TXGen uses VT100 control codes or escape codes to display the screens,
which means your terminal must support VT100. The Hyperterminal in windows is not
going to work for TXGen as it has a few problems with VT100 codes.

TXGen has a number of modes to send packets single, range, random, sequeue and
PCAP modes. Each mode has its own set of packet buffers and you must configure
each mode to work correctly. The single packet mode is the information displayed
at startup screen or when using the 'page main or page 0' command. The other
screens can be accessed using 'page seq|range|rnd|pcap|stats' command.

The txgen program as built can send up to 16 packets per lport in a sequence
and you can configure a lport using the 'seq' txgen command. A script file
can be loaded from the shell command line via the -f option and you can 'load'
a script file from within txgen as well.

TXGen command line directory format
====================================

-- TX-Gen 20.11.0  Powered by CNDP ---------------

Show the commands inside the ``txgen/bin`` directory::

	TXGen:/> ls
	[txgen]        [sbin]          copyright
	TXGen:/> ls txgen/bin
	off             on              debug           set
	stp             str             stop            start           disable
	enable          theme           page
	lport            restart         rst
	reset           cls             redisplay       save
	script          load            clr
	clear.stats     help
	TXGen:/>

Showin the ``1s`` command at root::

	TXGen:/> ls
	[txgen]        [sbin]          copyright
	TXGen:/> ls sbin
	env             dbg             path            hugepages       cmap
	sizes           more            history         quit            clear
	pwd             cd              ls              rm              mkdir
	chelp           sleep           delay
	TXGen:/>

The case of using ``ls -l`` in a subdirectory::

	TXGen:/> cd sbin
	TXGen:/sbin/>
	TXGen:/sbin/> ls -l
	  env              Command : Set up environment variables
	  dbg              Command : debug commands
	  path             Command : display the command path list
	  hugepages        Command : hugepages # display hugepage info
	  cmap             Command : cmap # display the core mapping
	  sizes            Command : sizes # display some internal sizes
	  more             Command : more <file> # display a file content
	  history          Command : history # display the current history
	  quit             Command : quit # quit the application
	  clear            Command : clear # clear the screen
	  pwd              Command : pwd # display current working directory
	  cd               Command : cd <dir> # change working directory
	  ls               Command : ls [-lr] <dir> # list current directory
	  rm               Command : remove a file or directory
	  mkdir            Command : create a directory
	  chelp            Command : CLI help - display information for CNDP
	  sleep            Command : delay a number of seconds
	  delay            Command : delay a number of milliseconds

	TXGen:/sbin/>
	TXGen:/sbin/> cd ..
	TXGen:/>

Show help using ``ls -l`` command in txgen directory::

	TXGen:/txgen/> cd bin
	TXGen:/txgen/bin/> ls -l
	  off              Alias : disable screen
	  on               Alias : enable screen
	  debug            Command : debug commands
	  set              Command : set a number of options
	  stp              Alias : stop all
	  str              Alias : start all
	  stop             Command : stop features
	  start            Command : start features
	  disable          Command : disable features
	  enable           Command : enable features
	  theme            Command : Set, save, show the theme
	  page             Command : change page displays
	  restart          Command : restart lport
	  rst              Alias : reset all
	  reset            Command : reset txgen configuration
	  cls              Alias : redisplay
	  redisplay        Command : redisplay the screen
	  save             Command : save the current state
	  script           Command : run a Lua script
	  load             Command : load command file
	  clr              Alias : clear.stats all
	  clear.stats      Command : clear stats
	  help             Command : help command

	TXGen:/txgen/bin/>


Runtime Options and Commands
============================

While the ``txgen`` application is running you will see a command prompt as
follows::

   TXGen:/>

From this you can get help or issue runtime commands::

   TXGen:/> help

   set <portlist> <xxx> value    - Set a few lport values
   save <path-to-file>           - Save a configuration file using the
                                   filename
   load <path-to-file>           - Load a command/script file from the
                                   given path
   ...


The ``page`` commands to show different screens::

   page <pages>                      - Show the lport pages or configuration or sequence page
       [0-7]                         - Page of different lports
       main                          - Display page zero

List of the ``enable/disable`` commands::

    enable|disable screen              - Enable/disable updating the screen and unlock/lock window
    off                                - screen off shortcut
    on                                 - screen on shortcut

List of the ``set`` commands::

   note: <portlist> - a list of lports (no spaces) e.g. 2,4,6-9,12 or the word 'all'
   set <portlist> count <value>       - number of packets to transmit
   set <portlist> size <value>        - size of the packet to transmit
   set <portlist> rate <percent>      - Packet rate in percentage
   set <portlist> burst <value>       - number of packets in a burst
   set <portlist> sport <value>       - Source lport number for TCP
   set <portlist> dport <value>       - Destination lport number for TCP
   set <portlist> src|dst mac <addr>  - Set MAC addresses 00:11:22:33:44:55 or 0011:2233:4455 format
   set <portlist> proto udp|tcp       - Set the packet protocol to UDP or TCP per lport
   set <portlist> pattern <type>      - Set the fill pattern type
                    type - abc        - Default pattern of abc string
                           none       - No fill pattern, maybe random data
                           zero       - Fill of zero bytes
                           user       - User supplied string of max 16 bytes
   set <portlist> user pattern <string> - A 16 byte string, must set 'pattern user' command
   set <portlist> [src|dst] ip ipaddr - Set IP addresses, Source must include network mask e.g. 10.1.2.3/24
   set ports_per_page <value>         - Set lports per page value 1 - 6


The ``start|stop`` commands::

    start <portlist>                   - Start transmitting packets
    stop <portlist>                    - Stop transmitting packets
    stp                                - Stop all lports from transmitting
    str                                - Start all lports transmitting

The odd or special commands::

    save <path-to-file>                - Save a configuration file using the filename
    load <path-to-file>                - Load a command/script file from the given path
    clear <portlist> stats             - Clear the statistics
    clr                                - Clear all Statistices
    reset <portlist>                   - Reset the configuration the lports to the default
    rst                                - Reset the configuration for all lports
    lports per page [1-6]               - Set the number of lports displayed per page
    restart <portlist>                 - Restart or stop a ethernet lport and restart

The ``theme`` commands::
    theme <item> <fg> <bg> <attr>      - Set color for item with fg/bg color and attribute value
    theme show                         - List the item strings, colors and attributes to the items
    theme save <filename>              - Save the current color theme to a file

Several commands take common arguments such as:

* ``portlist``: A list of lports such as ``2,4,6-9,12`` or the word ``all``.
* ``state``: This is usually ``on`` or ``off`` but will also accept ``enable``
  or ``disable``.

The ``set`` command can also be used to set the MAC address with a format like
``00:11:22:33:44:55`` or ``0011:2233:4455``::

   set <portlist> src|dst mac etheraddr

The ``set`` command can also be used to set IP addresses::

   set <portlist> src|dst ip ipaddr

save
----

The ``save`` command saves the current configuration of a file::

   save <path-to-file>


load
----

The ``load`` command loads a configuration from a file::

   load <path-to-file>

The is most often used with a configuration file written with the ``save``
command, see above.


lports per page
--------------

The ``lports per page`` (lports per page) command sets the number of lports displayed per
page::

   lports per page [1-6]
