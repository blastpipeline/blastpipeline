#new log.txt reader

#slight modification of logreader.py to output simdata instead.
#reads dills output by logreader.py. 

import time
import calendar
import re

##import parse

#change from tbrreader: Server contains both ent and ci, replacing them in Resources and Connection.

class Resource: #holds data for a HttpTransaction
    def __init__(self):
        self.ptr = ""
        self.URI = ""
        #self.methodname = ""
        self.countWritten = 0
        self.countRead = 0
        self.ind = None #used by printout of referrer
        self.Connection = None
        self.Server = None

        self.started = 0 #DispatchTransaction
        self.ended = 0 #mResponseIsComplete
        self.dispatched = 0 #how many times this was dispatched, in total. dropped count is this - 1
        self.pipelined = 0 #is this pipelined? (the first resource counts too)

        self.context = None
        self.parent = None #referrer is not necessarily parent
        self.parentind = None #useful for dill dumping
        self.parentrule = None #1-6
        self.parentwritten = None

        self.timeCreated = None #InitTransaction
        self.timeStarted = None #DispatchTransaction
        self.timeRead = None #first ReadRequestSegment
        self.timeWritten = None #first WriteRequestSegment
        self.timeEnded = None #mResponseIsComplete

        self.curActive = None #for steps 1 and 2: list of currently active resources when this started
        self.neighbors = [] #used for step 4
        self.lastwrite = None #used for step 5: last resource written to (of a lower index)

        self.mUsingSpdy = 0 #was this using http/1.1 (0) or http/2 (1)?
        
    def __str__(self):
        string = ""
        name = self.URI
        if len(name) > 100:
            name = name[:97] + "..."
        string += name
        string += " at ptr " + self.ptr
        if self.Connection != None:
            string += " on Connection " + self.Connection.ptr
        else:
            string += " on Connection (None) "
        return string
    def __repr__(self):
        return str(self)

class Connection:
    def __init__(self):
        self.ptr = ""
        self.Transactions = []
        self.SocketIn = None
        self.SocketOut = None
        self.Server = None

        self.timeCreated = None #creation
        self.timeNPN = None #npn negotiation completed
        self.timeSPDY = None #earliest use of spdy
        self.timeClosed = None #if closed. 
        self.ind = None #index in Connections
        
    def __str__(self):
        if self.Transactions != []:
            string = "Connection {} carrying Transaction {} on Socket {} {}".format(
                self.ptr, self.Transactions, self.SocketIn.ptr, self.SocketOut.ptr)
        else:
            string = "Connection {} carrying Transaction (None) on Socket {} {}".format(
                self.ptr, self.SocketIn.ptr, self.SocketOut.ptr)
        return string
    def __repr__(self):
        return str(self)

class Socket:
    def __init__(self):
        self.ptr = ""
        self.Connection = None
        self.totalInc = 0
        self.totalOut = 0
    def __str__(self):
        string = "Socket {} ({} out, {} inc)".format(
            self.ptr, self.totalOut, self.totalInc)
        return string
    def __repr__(self):
        return str(self)

class Server:
    def __init__(self):
        self.ptr = None
        self.ci = ""
        self.is_tls = None
        self.is_http2 = None
        self.is_pipelined = None
        self.cert_length = None
        self.rec_length = 0
        self.events = []

    def printevents(self):
        print "Events for " + repr(self)
        for e in self.events:
            print e

    def __str__(self):
        return "Server [ci={}, ptr={}]".format(self.ci, self.ptr)

    def __repr__(self):
        return str(self)

def str_to_epochs(string):
#   string is like: "2019-06-10 12:40:46.289654 UTC"
    string = string.strip()
    string = string[:-4] #cut off UTC
    milli = float("0." + string.split(".")[1]) #grab milliseconds separately
    string = string.split(".")[0]
    a = time.strptime(string, "%Y-%m-%d %H:%M:%S") #construct struct_time
    t = calendar.timegm(a) + milli
    return t

def epochs_to_str(t):
    #converts unix epochs back to string
    milli = repr(t).split(".")[1]
    while len(milli) < 6:
        milli += "0"
    s = time.gmtime(t)
    string = "{}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{} UTC".format(
        s.tm_year, s.tm_mon, s.tm_mday,
        s.tm_hour, s.tm_min, s.tm_sec, milli)
    return string

def parse(line):
    time = str_to_epochs(line.split(" - ")[0])
    line = line.split(" - ")[1].split("]: ")[1]
    if OLD_LOG == 0:
        line = " ".join(line.split(" ")[1:])
    line = line.strip()
    params = {"t":time}
    try:
        li = line.split("\t")
        for l in li:
            if not "=" in l:
                params["text"] = l
            else:
                params[l.split("=")[0]] = l.split("=")[1]
    except:
        params["text"] = line
    return params

def URI_format(URI):
    #remove fragment identifier because they don't matter on the wire
    if ("#" in URI):
        URI = URI.split("#")[0]
    return URI

def ci_to_URI(ci):
    return ci.split(":")[0][7:]

    
import numpy
import dill
fold = "data/treebatch-new/"
outfold = "data/treebatch-new/simdata/"

fnames = ["comp-small.dill", "comp-large.dill", "comp-open.dill",
          "pipe-small.dill", "pipe-large.dill", "pipe-open.dill"]

rets = {} #dictionary of file name: relevant returns, just like the dill itself
results = []
for fname in fnames:
    print "Loading dill..."
    f = open(fold + fname, "r")
    results = dill.load(f)
    f.close()
##    sys.exit(-1)
    print "Processing dill..."
    for k in results.keys():
        [Resources, Connections, Servers, Sockets] = results[k]
        fname = k.split("/")[-1]
        fname = fname[:fname.index(".")]
        outfname = outfold + fname + ".simdata"
        fout = open(outfname, "w")
        for r in Resources:
            if r.countRead == 0:
                r.countRead = 400
            data = [r.URI, r.countRead, r.countWritten, r.parentwritten]
            if r.Server == None:
                data.append("None")
            else:
                data.append(Servers.index(r.Server))
            data.append(r.parentind)
            fout.write("\t".join([str(d) for d in data]))
            fout.write("\n")
        fout.write("---\n")
        for s in Servers:
            if s.ci == "":
                s.ci = "None"
            data = [s.ci, s.is_tls, s.is_http2]
            fout.write("\t".join([str(d) for d in data]))
            fout.write("\n")
        fout.close()
    del results

