# Repository for "Designing a better Browser for Tor with BLAST"

Logger and Pipelining implementation for TB-8.5
---
(blast-tbr-log.diff)

We implemented the BLAST logger by instrument Tor Browser.
We also re-implemented pipelining into TB-8.5. 
We present this as a diff file, applicable to
the git branch tor-browser-60.5.1esr-8.5-1
on https://git.torproject.org/tor-browser.git.

Runner
---
(runtor-tree.sh, top-200-tree)

This is the simple shell code and the site list we used to load our data set.
The shell code is unlikely to work for your computer since it is entirely
dependent on our setup; it is here for transparency. 

Analyzer
---
(logreader.py, logreader-dill.py, logreader-simdata.py)

logreader.py reads Tor Browser logs (from the Logger) and parses them, outputting dills. It includes the parent finding algorithm.
logreader-dill.py reads those dills and outputs some interesting information about them.
logreader-simdata.py re-parses dills into simdata for the Simulator.
Since they are designed for the researcher, a lot of stuff that shouldn't be hardcoded are, so it'll take some effort to get it to work with your setup. 

Simulator
---
(Sim-http2.py, pipelined-servers.txt, prefetch-res.dill)

The simulator reads simdata files (created from logreader-simdata.py) to generate trace-like objects in .simres.
It can also read lists of resources to (prefetch-res.dill) and which servers support pipelining (pipelined-servers.txt).

Implementation
---
(logger.zip)

Prototype implementation of the servers database and resource prefetching database can be found in logger.zip. 

Data sets
---
(logs.zip, simdata.zip)

<img align="left" src="http://home.cse.ust.hk/~taow/ndss20-table.png">

logs.zip contains some TB-8.5 logs. Full data available here: http://home.cse.ust.hk/~taow/tree/data/
simdata.zip contains some valid input files for the Simulator. You should be able to obtain them by parsing the logs.zip files with logreader.py and logreader-simdata.py too. 
