#logreader.py produces 3 dill files "-small" "-large" "-open"
#this file reads them to get results

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
        self.parentrule = None #1-6
        self.parentwritten = None

        self.timeCreated = None #InitTransaction
        self.timeStarted = None #DispatchTransaction
        self.timeRead = None #first ReadRequestSegment
        self.timeWritten = None #first WriteRequestSegment
        self.timeEnded = None #mResponseIsComplete

        self.curActive = None #for steps 1 and 2: list of currently active resources when this staretd
        self.neighbors = [] #used for step 4
        self.lastwrites = [] #used for steps 5 and 6: last resources written to (within 0.2s)

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

def proc_data(rets, results):
    for k in results.keys():
        [Resources, Connections, Servers, Sockets] = results[k]

##        if "comp0" in k and not "3-35-comp0.tbrlog" in k:
##            spdyServers = [0] * len(Servers)
##            countServers = [0] * len(Servers)
##            for r in Resources:
##                if r.mUsingSpdy == 1 and r.Server != None:
##                    spdyServers[Servers.index(r.Server)] = 1
##                if r.Server != None:
##                    countServers[Servers.index(r.Server)] += 1
##                    
##
##            for i in range(len(Servers)):
##                if spdyServers[i] == 0:
##                    if countServers[i] > 20:
##                        print k
##                        for r in Resources:
##                            if Servers.index(r.Server) == i:
##                                print r.timeCreated, r.timeStarted,
##                                print r.timeRead, r.timeWritten,
##                                print r.timeEnded, r.ptr, r.URI
##                        sys.exit(-1)
                
        
        if len(Resources) == 0:
            continue
        
##        for r in Resources:
##            #tempfix for possible time issues
##            r_times = [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded]
##            for i in reversed(range(4)):
##                if r_times[i] > r_times[i+1]:
##                    r_times[i] = r_times[i+1]
##            [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded] = r_times


##        this_rets = []
##        for r in Resources:
##            this_rets.append([r.dispatched, r.mUsingSpdy])
##        if not k in rets.keys():
##            rets[k] = {}
##        rets[k]["res.dispatch"] = this_rets
        

        #PAGE LOAD TIME AND RES COUNT
        sResources = []
        for r in Resources:
            if r.timeEnded != None:
                sResources.append(r)
        sResources = sorted(sResources, key = lambda r:r.timeEnded)
        eind = int(len(sResources) * 0.95)
        endtime = sResources[eind].timeEnded
        starttime = Resources[0].timeCreated
        for r in Resources:
            if r.timeCreated != None:
                if starttime == None:
                    starttime = r.timeCreated
                starttime = min(r.timeCreated, starttime)
        if (endtime != None and starttime != None):
            if not k in rets.keys():
                rets[k] = {}
            rets[k]["page.t"] = endtime-starttime
            rets[k]["res.count"] = len(Resources)

        #Resource server ids and using spdy

        this_rets = []
        for r_i in range(len(Resources)):
            if Resources[r_i].Server != None:
                this_rets.append([Resources[r_i].mUsingSpdy, Servers.index(Resources[r_i].Server)])
        rets[k]["res.spdy"] = this_rets
        if len(this_rets) != 0:
            count = 0
            for i in range(len(this_rets)):
                if this_rets[i][0] == 1:
                    count += 1
            rets[k]["page.spdypct"] = float(count)/float(len(this_rets))
        else:
            rets[k]["page.spdypct"] = 0

##        if rets[k]["page.spdypct"] != 0:
##            print rets[k]["page.spdypct"]

        pagesize = 0
        for r in Resources:
            if r.timeEnded != None:
                pagesize += r.countWritten
        if not k in rets.keys():
            rets[k] = {}
        rets[k]["page.size"] = pagesize
        
        
        #TOTAL LOAD TIMES
        sResources = sorted(Resources, key = lambda r:r.timeEnded)
        eind = int(len(Resources) * 0.95)
        er = sResources[eind]

        listr = []
        cr = er
        while cr.parentind != -1:
            listr.append(cr)
            if cr.parentind >= Resources.index(cr):
                print "Warning:", k, "has parent greater than child"
                break
            cr = Resources[cr.parentind]
        listr.append(Resources[0]) #root was not included in above
        listr = listr[::-1] #list of "critical" resources
        this_times = [0, 0, 0, 0]

        rtt = 0
        for rind in range(len(listr)):
            r = listr[rind]
            if rind == len(listr) - 1:
                nexttime = r.timeEnded
            else:
                nexttime = listr[rind+1].timeCreated
            if nexttime == None:
                continue
            r_times = [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded]
            if r_times[4] == None: #sometimes a resource does not declare itself finished
                r_times[4] = nexttime
            if not (None in r_times):
                for i in range(4):
                    diff = min(r_times[i+1] - r_times[i], nexttime - r_times[i])
                    if diff < 0:
                        diff = 0
                    this_times[i] += diff

        rets[k]["page.tcat"] = this_times

            #RTT counting
            #the following incur RTT:
            #default = 1 RTT
            #new connection = 1 RTT, 2 RTT if HTTPS
        seenConnections = []
        for r in listr:
            rtt += 1
            if not (r.Connection in seenConnections):
                seenConnections.append(r.Connection)
                rtt += 1
                if len(r.URI) > 5 and r.URI[:5] == "https":
                    rtt += 1 #another one

        rets[k]["page.rtt"] = rtt

##        #RESOURCE LOAD TIMES
##        this_rets = []
##        for r in Resources:
##            r_times = [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded]
##            r_rets = []
##            if not (None in r_times):
##                for i in range(4):
##                    r_rets.append(r_times[i+1] - r_times[i])
##            this_rets.append(r_rets)
##        if not (k in rets.keys()):
##            rets[k] = {}
##        rets[k]["res.t"] = this_rets
##
##        #SLOW RESOURCE LOAD TIMES
##        this_rets = []
##        for r in Resources:
##            if r.mUsingSpdy == 0:
##                continue
##            accept = 0
##            for r2 in Resources:
##                if r != r2:
##                    if r.Connection == r2.Connection:
##                        if r2.timeWritten < r.timeCreated and \
##                           r2.timeEnded > r.timeCreated:
##                            accept = 1
##            if accept == 0:
##                continue
##            r_times = [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded]
##            r_rets = []
##            if not (None in r_times):
##                for i in range(4):
##                    r_rets.append(r_times[i+1] - r_times[i])
##            this_rets.append(r_rets)
##        if not (k in rets.keys()):
##            rets[k] = {}
##        rets[k]["res.slowt"] = this_rets

        generations = [0] * len(Resources)
        for rind in range(len(Resources)):
            r = Resources[rind]
            if r.parentind == -1:
                generations[rind] = 0
            else:
                generations[rind] = generations[r.parentind] + 1
        if not (k in rets.keys()):
            rets[k] = {}
        rets[k]["page.gencount"] = max(generations)

        r = Resources[0]
        r_times = [r.timeCreated, r.timeStarted, r.timeRead, r.timeWritten, r.timeEnded]
        r_rets = []
        if not (None in r_times):
            for i in range(4):
                r_rets.append(r_times[i+1] - r_times[i])
        rets[k]["firstrestimes"] = r_rets

        #RESOURCE TRANSFER RATES
        this_rets = []
        for r in Resources:
            if r.timeWritten != None and r.timeEnded != None:
                this_rets.append([r.countWritten, r.timeEnded - r.timeWritten, r.mUsingSpdy])
        rets[k]["res.writetimes"] = this_rets

            #DISPATCHED count
##            this_rets = []
##            for r in Resources:
##                if r.timeEnded != None:
##                    this_rets.append([Servers.index(r.Server), r.pipelined, r.dispatched])
##            rets.append(this_rets)
##            for rind in range(len(Resources)):
##                r = Resources[rind]
                #find simultaneously dispatched previous resources
##                waittime = 0
##                for sind in range(rind):
##                    s = Resources[sind]
##                    if r.Server == s.Server and \
##                       r.timeStarted != None and \
##                       s.timeStarted != None and \
##                       s.timeEnded != None and\
##                       s.timeWritten != None and \
##                       abs(r.timeStarted - s.timeStarted) < 0.01:
##                        if r.timeEnded > s.timeStarted:
##                            waittime += s.timeEnded - s.timeWritten
##                rets.append(waittime)
##                
##                for r in Resources:
##                    if not (None in [r.timeCreated, r.timeStarted,
##                                     r.timeRead, r.timeWritten, r.timeEnded]):
##                        this_times[-1].append([r.timeStarted - r.timeCreated,
##                                           r.timeRead - r.timeStarted,
##                                           r.timeWritten - r.timeRead,
##                                           r.timeEnded - r.timeWritten])
##
##                dispatchtimes = [None] * len(Connections)
##                for r in Resources:
##                    if r.Connection != None:
##                        conind = Connections.index(r.Connection)
##                        if dispatchtimes[conind] == None:
##                            dispatchtimes[conind] = r.timeStarted
##                        else:
##                            dispatchtimes[conind] = min(dispatchtimes[conind],
##                                                        r.timeStarted)
##                for cind in range(len(Connections)):
##                    c = Connections[cind]
##                    if dispatchtimes[cind] != None and c.timeCreated != None:
##                        rets.append(dispatchtimes[cind] - c.timeCreated)
##                print generations
##                starttime = None
##                for r in Resources:
##                    if r.timeCreated != None:
##                        starttime = r.timeCreated
##                        break
##                for r in Resources:
##                    if r.timeCreated < starttime:
##                        starttime = r.timeCreated
##                endtimes = []
##                for r in Resources:
##                    if r.timeEnded != None:
##                        endtimes.append(r.timeEnded)
##                ind = int(len(endtimes) * 0.95)
##                endtime = endtimes[ind]
##                this_times.append(endtime-starttime)
##            Server_sizes = [0]*len(Servers)
##            for r in Resources:
##                if r.Server != None:
##                    Server_ind = Servers.index(r.Server)
##                    Server_sizes[Server_ind] += 1
##            rets.append(max(Server_sizes))
##        if len(this_times) == 5:
##            times.append(this_times)
            
    return rets
    
import numpy
count = 0
rcount = 0
rsize = 0
rsizes = [0]*1000000

fold = "data/treebatch-new/"
fnames = ["comp-all-0.dill", "comp-all-1.dill", "comp-all-2.dill"]

rets = {} #dictionary of file name: relevant returns, just like the dill itself
results = []
for fname in fnames:
    print "Loading dill..."
    f = open(fold + fname, "r")
    results = dill.load(f)
    f.close()
    print "Processing dill..."
    proc_data(rets, results)
    del results

rfnames = []
sfnames = []
word = "comp"
for i in range(10):
    for j in range(50):
        rfnames.append(fold + "{}-{}-{}".format(i, j, word))
for i in range(200):
    for j in range(5):
        rfnames.append(fold + "{}-{}-{}".format(i, j, word))
for i in range(1000):
    rfnames.append(fold + "{}-{}".format(i+200, word))
    sfnames.append(fold + "{}-{}".format(i+200, word))

##grfnames = []
##rfnames = []
##for i in range(10):
##    for j in range(50):
##        rfnames.append(fold + "{}-{}-{}".format(i, j, word))
##grfnames.append(rfnames)
##rfnames = []
##for i in range(200):
##    for j in range(5):
##        rfnames.append(fold + "{}-{}-{}".format(i, j, word))
##grfnames.append(rfnames)
##rfnames = []
##for i in range(1000):
##    rfnames.append(fold + "{}-{}".format(i+200, word))
##grfnames.append(rfnames)

rts = []
for k in range(3):
    totalWritten = 0
    totalt = 0
    spdyWritten = 0
    spdyt = 0
    totalCount = 0
    spdyCount = 0
    for rfname in rfnames:
        fname = rfname + str(k) + ".tbrlog"
        if fname in rets.keys():
            this_rets = rets[fname]["res.writetimes"]
            for r in this_rets:
                if r[0] > 500000:
                    totalWritten += r[0]
                    totalt += r[1]
                    totalCount += 1
                    if k == 0:
                        rts.append([r[0], r[1]])
                    if r[2] == 1:
                        spdyWritten += r[0]
                        spdyt += r[1]
                        spdyCount += 1
##                    print totalWritten, totalt, totalCount, totalWritten/totalt
    print totalWritten, totalt, totalCount
##    print spdyWritten, spdyt, spdyCount

##fout = open("rtt-time.txt", "w")
##for k in range(3):
##    for rfname in rfnames:
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
##            fout.write("\t".join(str(a) for a in [k, rets[fname]["page.rtt"], rets[fname]["page.t"]]) + "\n")
##fout.close()

##for k in range(3):
##    totallen = 0
##    totaltime = 0
##    count = 0
##    for rfname in rfnames:
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
##            for s in rets[fname]["res.writetimes"]:
##                if s[0] > 50000 and s[2] == 1:
##                    count += 1
##                    totallen += s[0]
##                    totaltime += s[1]
##    print count, totallen, totaltime, totallen/totaltime

##for k in range(4):
##    for m in range(4):
##        print times[k][m]/counts[k]

##f = open("features.txt", "w")
##for rfname in rfnames:
##    feats = []
##    for k in range(2):
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
##            feats.append([rets[fname]["page.t"],
##                 rets[fname]["page.size"],
##                 rets[fname]["page.gencount"],
##                 rets[fname]["page.spdypct"],
##                 rets[fname]["res.count"]])
##        else:
##            break
##    if len(feats) == 2:
##        combfeats = []
##        for i in range(5):
##            combfeats.append(feats[0][i] - feats[1][i])
##        for i in range(5):
##            combfeats.append((feats[0][i] + feats[1][i])/2.0)
##        f.write("\t".join([str(fs) for fs in combfeats]) + "\n")
##f.close()

##counts = [0, 0, 0, 0]
##times = []
##slowtimes = []
##for k in range(4):
##    times.append([0, 0, 0, 0])
##    slowtimes.append([0, 0, 0, 0])
##for rfname in rfnames:
##    for k in range(4):
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
####            for r in rets[fname]["res.t"]:
####                if len(r) == 4:
####                    for m in range(4):
####                        times[k][m] += r[m]
####                    counts[k] += 1
##                    
##            for r in rets[fname]["res.slowt"]:
##                if len(r) == 4:
##                    for m in range(4):
##                        slowtimes[k][m] += r[m]
##                    counts[k] += 1
##
##for k in range(4):
##    for m in range(4):
####        print times[k][m]/counts[k]
##        print slowtimes[k][m]/counts[k]

##countpos = 0
##countneg = 0
##for rfname in rfnames:
##    k = 0
##    fname = rfname + str(k) + ".tbrlog"
##    if fname in rets.keys():
##        for r in rets[fname]["res.spdy"]:
##            if r[0] == 1:
##                countpos += 1
##            if r[0] == 0:
##                countneg += 1
##
##haspos = 0
##hasneg = 0
##for rfname in rfnames:
##    k = 0
##    fname = rfname + str(k) + ".tbrlog"
##    if fname in rets.keys():
##        foundpos = 0
##        for r in rets[fname]["res.spdy"]:
##            if r[0] == 1:
##                foundpos = 1
##        if foundpos == 1:
##            haspos += 1
##        else:
##            hasneg += 1

##diffs = []
##for rfname in rfnames:
##    this_times = []
##    for k in range(2):
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
##            this_times.append(rets[fname]["page.t"])
##        else:
##            break
##    if len(this_times) == 2:
##        diffs.append([rfname, this_times[1] - this_times[0]])
##for time in times:
##    print time/count


for rfnames in grfnames:    
    times = []
    count = 0
    for i in range(1, 2):
        times.append([0, 0, 0, 0])
    for rfname in rfnames:
        this_times = []
        for k in range(1, 2):
            fname = rfname + str(k) + ".tbrlog"
            if fname in rets.keys():
                this_times.append(rets[fname]["page.tcat"])
            else:
                continue
        if len(this_times) == 1:
            for k in range(0, 1):
                for m in range(4):
                    times[k][m] += this_times[k][m]
            count += 1
    c = 0
    for t in times:
        for a in t:
            c += a/count
    print c

##tars = [18.371, 17.641, 18.7]
##for time in times:
##    c = 0
##    for m in range(4):
##        c += time[m]/count
##        print c,
##    print tars[times.index(time)] - c, ""

##times = [0, 0, 0, 0]
##count = 0
##for rfname in rfnames:
##    this_times = []
##    for k in range(4):
##        fname = rfname + str(k) + ".tbrlog"
##        if fname in rets.keys():
##            this_times.append(rets[fname]["page.t"])
##        else:
##            break
##    if len(this_times) == 4:
##        for k in range(4):
##            times[k] += this_times[k]
##        count += 1
##for time in times:
##    print time/count


#for pipelining size experiment
#first, re-sort
##time_sizes = [[], [], [], []]
##for rets in total_rets:
##    if len(rets) != 5:
##        continue
##    for i in range(4):
##        time_sizes[i].append(rets[i+1])
##
##for i in range(4):
##    ts = time_sizes[i]
##    ts = sorted(ts, key = lambda k:k[1])
##    for j in range(4):
##        start = int(j/4.0 * len(ts))
##        end = min(int((j+1)/4.0 * len(ts)), len(ts) - 1)
##        print numpy.mean([t[0] for t in ts[start:end]])

##goodservercount = 0
##badservercount = 0
##for page in rets:
##    maxserver_ind = 0
##    for res in page:
##        [server_ind, is_pipeline, dispatchcount] = res
##        maxserver_ind = max(maxserver_ind, server_ind)
##    goodservers = [-1] * (maxserver_ind+1)
##    for res in page:
##        [server_ind, is_pipeline, dispatchcount] = res
##        if is_pipeline == 1:
##            if goodservers[server_ind] == -1:
##                goodservers[server_ind] = 1
##            if dispatchcount > 1:
##                goodservers[server_ind] = 0
##    goodservercount += goodservers.count(1)
##    badservercount += goodservers.count(0)

##times = [0, 0, 0, 0, 0]
##for x in total_rets:
##    for i in range(5):
##        times[i] += x[i]
##for t in times:
##    print t/float(len(total_rets))

#code for getting transfer times
##times = [0, 0, 0, 0]
##for x in total_rets:
##    for i in range(4):
##        times[i] += x[i]
##c = 0
##for i in range(4):
##    c += times[i]/len(total_rets)
##    print c
##    print times[i]/len(total_rets)
