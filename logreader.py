#new log.txt reader

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

def parse_log(fname):
    
    f = open(fname, "r")
    lines = f.readlines()
    f.close()

    if len(lines) == 0:
        return [None, None, None, None]

    if not ("\n" in lines[-1]):
        return [None, None, None, None] #this log was not completed for some reason

    start = -1
    firstwrote = -1

    Resources = []
    initResources = [] #list of resources by init. used for parse indexing.
    #initResources order/contents must never be changed
    Connections = []
    Sockets = []
    Servers = []
    Resources_search = {} #table for the right resources
    Connections_dict = {} #to get objects with pointers
    Sockets_dict = {}
    ent_ci_dict = {}
    Servers_dict = {}

    lastwrites = [] #what resources were written to (in 0.02s) recently?
    #lastwrites[i] = [resource, last write time, countWritten]

    for line in lines:
        try:
            params = parse(line)
        except Exception as e:
            print e
            print line
            print "Warning: could not parse line {} of {}, breaking".format(lines.index(line), len(lines))
            return [None, None, None, None]
        if not("f" in params.keys()):
            continue
        
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resource()
            r.URI = URI_format(params["origin"] + params["URI"])
            if OLD_LOG == 0:
                if params["ptr"][:2] == "0x":
                    r.ptr = params["ptr"]
                else:
                    r.ptr = "0x" + params["ptr"] #why did this happen?
            else:
                r.ptr = params["ptr"]
            #r.methodname = params["methodname"]
            r.channel = params["channel"]
            r.timeCreated = float(params["t"])
            r.num = len(Resources)
            if start == -1:
                start = r.timeCreated

            #set r.neighbors based on lastwrites here
            #neighbors are parent candidates.
            #parent candidates are: the last write, plus any write within 0.05 of that write

            if len(lastwrites) > 0:
                lasttime = lastwrites[-1][1]
                for s in reversed(lastwrites):
                    if abs(s[1] - lasttime) < 0.05:
                        if not (s[0] in r.neighbors):
                            r.neighbors.append(s[0])
                    else:
                        break
            
            Resources.append(r)
            initResources.append(r)
            Resources_search["ptr=" + r.ptr] = r
            
        if params["f"] == "nsHttpConnection::Init":
            c = Connection()
            c.ptr = params["this"]
            c.timeCreated = params["t"]

            si = Socket()
            si.ptr = params["mSocketIn"]
            si.Connection = c
            c.SocketIn = si

            so = Socket()
            so.ptr = params["mSocketOut"]
            so.Connection = c
            c.SocketOut = so

            Connections.append(c)
            Sockets.append(si)
            Sockets.append(so)
            Connections_dict[c.ptr] = c
            Sockets_dict[si.ptr] = si
            Sockets_dict[so.ptr] = so

        if params["f"] == "nsHttpConnectionMgr::ProcessPendingQForEntry called":
            Servers_dict[params["ent"]].ci = params["ci"]

        if params["f"] == "nsHttpConnectionMgr::DispatchTransaction":
            c = None
            r = None
            s = None
            try:
                r = Resources_search["ptr=" + params["trans"]]
            except:
                print "Error: Could not find transaction being dispatched", params["trans"]
            try:
                c = Connections_dict[params["conn"]]
            except:
                print "Error: Could not find connection used for dispatch", line
            try:
                s = Servers_dict[params["ent"]]
            except:
                print "Error: Could not find server used for dispatch"
            if c != None and r != None and s != None:
                c.Transactions.append(r)
                r.Connection = c
                r.Server = s
                c.Server = s
                r.started = 1
                r.dispatched += 1
                r.pipelined = 0
                r.timeStarted = params["t"]
                if c.timeSPDY == None and params["conn->UsingSpdy"] == "1":
                    c.timeSPDY = params["t"]
                if params["trans"] == "0x7fc862185c00":
                    print line
                r.timeRead = None #multiple dispatch causing error bug

        if params["f"] == "nsHttpConnectionMgr::TryDispatchTransaction":
            r = Resources_search["ptr=" + params["trans"]]
            s = Servers_dict[params["ent"]]
            r.Server = s

        if params["f"] == "nsHttpConnectionMgr::DispatchTransaction UsingSpdy":
            r = Resources_search["ptr=" + params["trans"]]
            r.pipelined = 0
            r.mUsingSpdy = 1 #the connection/server links have already been established            

        if params["f"] == "nsConnectionEntry::nsConnectionEntry":
            s = Server()
            s.ptr = params["this"]
            Servers.append(s)
            Servers_dict[s.ptr] = s

        if params["f"] == "nsHttpConnectionMgr::AddToBestPipeline":
            r = Resources_search["ptr=" + params["trans"]]
            c = Connections_dict[params["conn"]]
            c.Transactions.append(r)
            r.Server = c.Server
            for t in c.Transactions:
                t.pipelined = 1
            if r.started == 1:
                #this happens because the connection has dropped this transaction
                #also, the connection close comes a little later, so we need to handle it here
                r.Connection.Transactions.remove(r)
            r.dispatched += 1
            r.started = 1
            r.timeStarted = params["t"]
            r.Connection = c
            r.timeRead = None #multiple dispatch causing error bug

        if params["f"] == "nsHttpConnection::EnsureNpnComplete":
            Connections_dict[params["this"]].timeNPN = params["t"]

        if params["f"] == "nsHttpTransaction::ReadRequestSegment":
            r = Resources_search["ptr=" + params["ptr"]]
            if r.timeRead == None:
                r.timeRead = params["t"]
                r.countRead += int(params["countRead"])
                
        if params["f"] == "nsHttpTransaction::WritePipeSegment":
            r = Resources_search["ptr=" + params["ptr"]]
            if r.timeWritten == None:
                r.timeWritten = params["t"]
            if firstwrote == -1:
                firstwrote = r.timeWritten
            r.countWritten += int(params["countWritten"])
            lastwrites.append([r, float(params["t"]), int(params["countWritten"])])
        
        if params["f"] == "nsHttpTransaction::HandleContent mResponseIsComplete":
            r = Resources_search["ptr=" + params["ptr"]]
            r.timeEnded = params["t"]
            r.ended = 1
            c = r.Connection
            if c == None:
                print "Warning: {} has no connection".format(r)
            else:
                c.Transactions.remove(r)

        if params["f"] == "nsHttpConnection::Close":
            #we actually want this to do nothing because it's in the wrong order
            c = Connections_dict[params["this"]]
            c.timeClosed = params["t"]
##            for r in c.Transactions:
##                r.started = 0
##                r.timeStarted = None
##                r.dropped += 1
##                r.Connection = None
##            c.Transactions = []
##            c.ended = 1

##    for i in range(len(closenums)):
##        print i, closenums[i], lasttimes[i]
##
##    for i in range(len(Resources)):
##        print i, Resources[i].neighbors, Resources[i].ptr, Resources[i].URI
    #second parse to get ent events
    Resources_search = {} #table for the right resources
    Connections_dict = {} #to get objects with pointers
    Servers_dict = {}
    Resources_ind = 0
    Connections_ind = 0
    Servers_ind = 0
            
    for line_i in range(len(lines)):
        line = lines[line_i]
        try:
            params = parse(line)
        except:
            print "Warning: could not parse line {} of {}, breaking".format(lines.index(line), len(lines))
            break #this can happen at end of file, for example
        if not("f" in params.keys()):
            continue

        #the dictionary trackers
        if (params["f"] == "nsHttpTransaction::Init"):                
            if OLD_LOG == 0:
                if params["ptr"][:2] == "0x":
                    this_ptr = params["ptr"]
                else:
                    this_ptr = "0x" + params["ptr"] #why did this happen?
            else:
                this_ptr = params["ptr"]
                
            Resources_search["ptr=" + this_ptr] = initResources[Resources_ind]
            initResources[Resources_ind].ind = Resources_ind
            Resources_ind += 1
            tstr = epochs_to_str(params["t"])
            if r.Server != None:
                r.Server.events.append("{}: Res {} created [ptr={}]".format(tstr, r.ind, params["ptr"]))
            
        if (params["f"] == "nsHttpConnection::Init"):
            Connections_dict[params["this"]] = Connections[Connections_ind]
            Connections[Connections_ind].ind = Connections_ind
            Connections_ind += 1   
            tstr = epochs_to_str(params["t"])
            if c.Server != None:
                c.Server.events.append("{}: Con {} created [ptr={}]".format(tstr, c.ind, params["this"]))     

        if params["f"] == "nsConnectionEntry::nsConnectionEntry":
            Servers_dict[params["this"]] = Servers[Servers_ind]
            Servers_ind += 1

        if (params["f"] == "nsHttpConnection::Close"):
            c = Connections_dict[params["this"]]
            tstr = epochs_to_str(params["t"])
            if c.Server != None:
                c.Server.events.append("{}: Con {} closed [ptr={}]".format(tstr, c.ind, params["this"]))

        if (params["f"] == "nsHttpConnectionMgr::OnMsgReclaimConnection"):
            #a good way to set server
            c = Connections_dict[params["conn"]]
            s = Servers_dict[params["ent"]]
            c.Server = s

        if (params["f"] == "nsHttpConnectionMgr::ProcessPendingQForEntry called"):
            s = Servers_dict[params["ent"]]
            #we're going to have to lookahead
            line_j = line_i
            tstr = epochs_to_str(params["t"])

            [pC, hoC, aC, iC] = [0, 0, 0, 0] #pending trans, half-open c, active c, idle c
            while (True):
                line_j += 1
                if line_j >= len(lines):
                    break
                try:
                    this_params = parse(lines[line_j])
                except:
                    print "Warning: could not parse line {} of {}, breaking".format(lines.index(line), len(lines))
                    break #this can happen at end of file, for example
                if not("q" in this_params.keys()):
                    break
                
                if this_params["q"] == "mPendingTrans":
                    if "text" in this_params.keys():
                        pC = len(this_params["text"].split(" "))
                if this_params["q"] == "mActiveConns":
                    aC += 1
                if this_params["q"] == "mIdleConns":
                    iC += 1
                if this_params["q"] == "mHalfOpens":
                    hoC += 1
            #do not add if same as last update
            willadd = 1
            event = "[pT={}, hC={}, aC={}, iC={}]".format(pC, hoC, aC, iC)
            index = len(s.events) - 1
            lastevent = None
            while index >= 0:
                if "ProcessPendingQ" in s.events[index]:
                    lastevent = "[" + s.events[index].split("[")[1]
                    break
                index -= 1
            if lastevent == event:
                willadd = 0

            if willadd == 1:    
                s.events.append("{}: ProcessPendingQ {}".format(tstr, event))

        
        if params["f"] == "nsHttpTransaction::HandleContent mResponseIsComplete":
            r = Resources_search["ptr=" + params["ptr"]]
            tstr = epochs_to_str(params["t"])
            if r.Server != None:
                r.Server.events.append("{}: Res {} done [ptr={}]".format(tstr, r.ind, params["ptr"]))

        if params["f"] == "nsHttpConnection::EnsureNpnComplete":
            tstr = epochs_to_str(params["t"])
            c = Connections_dict[params["this"]]
            if c.Server != None:
                c.Server.events.append("{}: Con {} NPN [ptr={}]".format(tstr, c.ind, params["this"]))

        if params["f"] == "nsHttpConnectionMgr::MakeNewConnection CreateTransport":
            s = Servers_dict[params["ent"]]
            r = Resources_search["ptr=" + params["trans"]]
            tstr = epochs_to_str(params["t"])
            s.events.append("{}: Make new connection for Res {}".format(tstr, r.ind))

        if params["f"] == "nsHttpConnectionMgr::DispatchTransaction":
            r = Resources_search["ptr=" + params["trans"]]
            c = Connections_dict[params["conn"]]
            tstr = epochs_to_str(params["t"])
            this_str = "{}: Res {} dispatched on Con {}".format(tstr, r.ind, c.ind)
            if r.Server != None:
                if r.mUsingSpdy == 1:
                    r.Server.events.append(this_str + " " + "(SPDY)")
                else:
                    r.Server.events.append(this_str)

    #Step -1: The first resource has no parent (parentrule written as -1, not None)
    Resources[0].parentrule = -1
    Resources[0].parent = None

    #Any resource that has NO neighbors is discarded (it was not loaded correctly)
    keeps = [1] * len(Resources)
    for i in range(1, len(Resources)):
        if len(Resources[i].neighbors) == 0:
            keeps[i] = 0
    newResources = []
    for i in range(len(Resources)):
        if keeps[i] == 1:
            newResources.append(Resources[i])
    Resources = newResources

    #Step 0: If there is only one recent write, that is the parent.
    parents = [] #used in step 1
    for r in Resources:
        if r.parentrule != None:
            continue
        if len(r.neighbors) == 1:
            r.parent = r.neighbors[0]
            r.parentrule = 0
            parents.append(r.parent)

    #Step 1: If one candidate is a known rule 0 parent, it should be a rule 1 parent
    #(tie broken by recency)
    for r in Resources:
        if r.parentrule != None:
            continue
        for n in r.neighbors:
            if n in parents:
                r.parent = n
                r.parentrule = 1
                break

    #Step 2: Choose a candidate from the same server
    for r in Resources:
        if r.parentrule != None:
            continue
        for n in r.neighbors:
            if n.Server == r.Server:
                r.parent = n
                r.parentrule = 2
                break

    #Step 3: Choose the first candidate (the most recent write)
    for r in Resources:
        if r.parentrule != None:
            continue
        r.parent = r.neighbors[0]
        r.parentrule = 3

    #determine is_tls
    for s in Servers:
        if len(s.ci) > 2:
            if s.ci[1] == "S":
                s.is_tls = 1

    #determine is_http2
    for s in Servers:
        isSpdy = 0
        for r in Resources:
            if r.Server == s and r.mUsingSpdy == 1:
                isSpdy = 1
        s.is_http2 = isSpdy

    #do another loop to determine parentwritten
    for r in Resources:
        r.countWritten = 0
    r_ind = 0
    for line in lines:
        params = parse(line)
        if not("f" in params.keys()):
            continue
        if params["f"] == "nsHttpTransaction::WritePipeSegment": #writes to socket
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countWritten += int(params["countWritten"])
            else:
                print "Cannot find resource for", line
                
        if (params["f"] == "nsHttpTransaction::Init"):
            if OLD_LOG == 0:
                if params["ptr"][:2] == "0x":
                    this_ptr = params["ptr"]
                else:
                    this_ptr = "0x" + params["ptr"] #why did this happen?
            else:
                this_ptr = params["ptr"]
                
            r = initResources[r_ind]
            assert (r.ptr == this_ptr)
            Resources_search["ptr=" + r.ptr] = r
            r_ind += 1
            if r.parent != None:
                rpar = Resources_search["ptr=" + r.parent.ptr]
                r.parentwritten = rpar.countWritten

    #decide if pipelining works

    dispatchcounts = [0] * len(Servers)
    for r in Resources:
        if r.dispatched > 0 and r.Server != None:
            dispatchcounts[Servers.index(r.Server)] += (r.dispatched - 1)
        if r.pipelined == 1:
            if r.Server != None:
                r.Server.is_pipelined = 1

    for c in range(len(dispatchcounts)):
        if dispatchcounts[c] >= 2 and r.Server != None: #2 errors or above
            r.Server.is_pipelined = 0
    
    for s in Servers:
        if s.is_pipelined == None:
            s.is_pipelined = 0

    #delete some things because they cause recursion problems
    for r in Resources:
        if r.parent != None:
            r.parentind = Resources.index(r.parent)
        else:
            r.parentind = -1
        r.neighbors = []
        r.curActive = []
##        r.lastwrite = None
        r.parent = None

    return [Resources, Connections, Servers, Sockets]

import numpy
import dill

OLD_LOG = 0

fold = "data/treebatch-new/"
word = "comp"

fnames = []
for i in range(10):
    for j in range(50):
        fnames.append(fold + "{}-{}-{}".format(i, j, word))
for i in range(200):
    for j in range(5):
        fnames.append(fold + "{}-{}-{}".format(i, j, word))
for i in range(1000):
    fnames.append(fold + "{}-{}".format(i, word))
results = {}
for k in range(0, 3):
    if k == 2 or k == 3:
        OLD_LOG = 1
    if k == 0 or k == 1:
        OLD_LOG = 0
    results = {}
    for fname in fnames:
        this_fname = fname + str(k) + ".tbrlog"
        print this_fname
        try:
            [Resources, Connections, Servers, Sockets] = parse_log(this_fname)
        except Exception as e:
            print e
            continue
        if Resources == None or Resources == []:
            continue
        countEnded = 0
        for r in Resources:
            if r.timeEnded != None:
                countEnded += 1
        if (countEnded < 2):
            continue
        results[this_fname] = [Resources, Connections, Servers, Sockets]

    fout = open(fold + "{}-all-{}.dill".format(word, k), "w")
    dill.dump(results, fout)
    fout.close()
    del results

##sys.exit(-1)
##
##fnames_sets = [[], [], []]
##fnames_names = ["small", "large", "open"]
##for i in range(10):
##    for j in range(50):
##        fnames_sets[0].append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(200):
##    for j in range(5):
##        fnames_sets[1].append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(1000):
##    fnames_sets[2].append(fold + "{}-{}".format(i, word))
##
##for ind in range(3):
##    fnames = fnames_sets[ind]
##    results = {}
##    for fname in fnames:
##        for k in range(0, 4):
##            if k == 2 or k == 3:
##                OLD_LOG = 1
##            if k == 0 or k == 1:
##                OLD_LOG = 0
##            this_fname = fname + str(k) + ".tbrlog"
##            print this_fname
##            try:
##                [Resources, Connections, Servers, Sockets] = parse_log(this_fname)
##            except Exception as e:
##                print e
##                continue
##            if Resources == None or Resources == []:
##                continue
##            countEnded = 0
##            for r in Resources:
##                if r.timeEnded != None:
##                    countEnded += 1
##            if (countEnded < 2):
##                continue
##            results[this_fname] = [Resources, Connections, Servers, Sockets]
##
##    fout = open(fold + "{}-{}.dill".format(word, fnames_names[ind]), "w")
##    dill.dump(results, fout)
##    fout.close()
##    del results
##
##word = "pipe"
##
##fnames = []
##for i in range(10):
##    for j in range(50):
##        fnames.append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(200):
##    for j in range(5):
##        fnames.append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(1000):
##    fnames.append(fold + "{}-{}".format(i, word))
##results = {}
##for k in range(1, 6):
##    OLD_LOG = 0
##    results = {}
##    for fname in fnames:
##        this_fname = fname + str(k) + ".tbrlog"
##        print this_fname
##        try:
##            [Resources, Connections, Servers, Sockets] = parse_log(this_fname)
##        except Exception as e:
##            print e
##            continue
##        if Resources == None or Resources == []:
##            continue
##        countEnded = 0
##        for r in Resources:
##            if r.timeEnded != None:
##                countEnded += 1
##        if (countEnded < 2):
##            continue
##        results[this_fname] = [Resources, Connections, Servers, Sockets]
##
##    fout = open(fold + "{}-all-{}.dill".format(word, k), "w")
##    dill.dump(results, fout)
##    fout.close()
##    del results
##
##fnames_sets = [[], [], []]
##fnames_names = ["small", "large", "open"]
##for i in range(10):
##    for j in range(50):
##        fnames_sets[0].append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(200):
##    for j in range(5):
##        fnames_sets[1].append(fold + "{}-{}-{}".format(i, j, word))
##for i in range(1000):
##    fnames_sets[2].append(fold + "{}-{}".format(i, word))
##
##for ind in range(3):
##    fnames = fnames_sets[ind]
##    results = {}
##    for fname in fnames:
##        for k in range(1, 6):
##            OLD_LOG = 0
##            this_fname = fname + str(k) + ".tbrlog"
##            print this_fname
##            try:
##                [Resources, Connections, Servers, Sockets] = parse_log(this_fname)
##            except Exception as e:
##                print e
##                continue
##            if Resources == None or Resources == []:
##                continue
##            countEnded = 0
##            for r in Resources:
##                if r.timeEnded != None:
##                    countEnded += 1
##            if (countEnded < 2):
##                continue
##            results[this_fname] = [Resources, Connections, Servers, Sockets]
##
##    fout = open(fold + "{}-{}.dill".format(word, fnames_names[ind]), "w")
##    dill.dump(results, fout)
##    fout.close()
##    del results
