# Repository for "Designing a better Browser for Tor with BLAST"

Logger 
---
(blast-tor-log.diff, blast-tbr-log.diff)

We implemented the BLAST logger by instrument Tor and Tor Browser.
Therefore we present both of them as diff files
in blast-tor-log.diff and blast-tbr-log.diff respectively. 

Runner
---
(runtor-tree-4.sh, top-200-tree)

This is the simple shell code and the site list we used to load our data set.
The shell code is unlikely to work for your computer since it is entirely
dependent on our setup; it is here for transparency. 

Analyzer
---
(cutlog.py, parentreader.py, parentdata.txt, parentfinder.py, dillwriter.py)

cutlog.py turns .torlog files into .trlg files. 
parentreader.py reads files from a version of Tor Browser specifically designed to
load resources one by one, so parenthood is easier to determine.
It creates parentdata.txt, which we also included, so you don't have to run parentreader.py.
parentfinder.py determines parents and writes to simdata. 
dillwriter.py reads .tbrlog, .tdrlog, and .trlg files to parse all relevant information into a single dill file. 

Simulator
---
(Sim.py, Sim-better.py)

The simulator reads simdata files (created from parentfinder.py) to generate trace-like objects in .simdelay. 
Sim-better uses better pipelining (which isn't easy to modulate). Otherwise, all the other models
are optionals within both code. 

Data sets
---
(compare.zip, simdata.zip, simdelay.zip)
Simdata.zip contains some of our simdata files (described above).
simdelay.zip as well. 
compare.zip contains tbrlog files for comparison. 
Our full data is too large to be put here.
We will release them on our own website after publication. 
