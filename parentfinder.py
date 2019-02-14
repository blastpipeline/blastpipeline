#1. If there is only one active transaction
#2. If there is only one valid active transaction
#3. If we can find both child and parent in the database
#4. If another request with the same server was opened recently, and it has a parent from 1-3, then this inherits that parent
#5. If only a single write was done recently before, then that is the parent
#6. Simply use the last write

class Resource: #holds data for a HttpTransaction
    def __init__(self):
        self.ptr = ""
        self.URI = ""
        self.methodname = ""
        self.countWritten = 0
        self.countRead = 0
        self.num = -1 #used by printout of referrer
        self.Connection = None

        self.started = 0 #DispatchTransaction
        self.ended = 0 #mResponseIsComplete

        self.context = None
        self.parent = None #referrer is not necessarily parent
        self.parentrule = None #1-6
        self.parentwritten = None
        self.requestsize = None 

        self.timediff = None
        self.starttime = None

        self.curActive = None #for steps 1 and 2
        self.neighbors = [] #used for step 4
        self.lastwrites = [] #used for steps 5 and 6
        self.lastwrittenr = None #what resource was last written when i was created?

        self.ent = None #ent and ci (ptr, string) inherited from connection upon dispatch
        self.ci = None
        self.server = None

        self.pipelined = False
        
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
        self.Transaction = None
        self.SocketIn = None
        self.SocketOut = None
        self.ent = None
        self.ci = None
        self.closed = 0
    def __str__(self):
        if self.Transaction != None:
            string = "Connection {} carrying Transaction {} on Socket {} {}".format(
                self.ptr, self.Transaction.ptr, self.SocketIn.ptr, self.SocketOut.ptr)
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
        self.is_pipelining = None
        self.cert_length = None
        self.rec_length = 0

def tbrparse(line):
    if ("=") in line:
        params = {}
        line = line[:-1] #remove trailing \n
        li = line.split("\t")
        for p_i in range(0, len(li)):
            w = li[p_i].split("=")[0]
            q = "=".join(li[p_i].split("=")[1:]) #there may be = in string
            params[w] = q
        return params
    else:
        return {}

def URI_format(URI):
    #remove fragment identifier because they don't matter on the wire
    if ("#" in URI):
        URI = URI.split("#")[0]
    return URI

def ci_to_URI(ci):
    return ci.split(":")[0][7:]

##import sys
##if len(sys.argv) < 4:
##    print sys.argv
##    print "python parentfinder.py <site> <inst> <subinst>"
##else:
##    site = int(sys.argv[1])
##    inst = int(sys.argv[2])
##    subinst = int(sys.argv[3])

f = open("parentdata.txt", "r")
lines = f.readlines()
f.close()
parentdata = []
parentkeys = []
for line in lines:
    line = line.strip()
    li = line.split("\t")
    if len(li) == 4:
        if li[2] == li[3]:
            continue
        parentdata.append(li)
        parentkeys.append(li[2])

import os
fold = "data/treebatch-nopipeline/"

fnames = []
for i in range(0, 200):
    for j in range(0, 2):
        for k in range(1, 6):
            fname = "{}-{}-{}".format(i, j, k)
            if os.path.exists(fold + fname + ".tbrlog"):
                fnames.append(fname)

##fnames = ["3-2-1"]
for fname in fnames:
    print fname
    f = open(fold + fname + ".tbrlog", "r")
    lines = f.readlines()
    f.close()

    Resources = []
    Connections = []
    Sockets = []
    Resources_search = {} #table for the right resources
    Connections_dict = {} #to get objects with pointers
    Sockets_dict = {}
    ent_ci_dict = {}
    uri_certlength_dict = {}

    lastwrites = []
    lastwrittenr = None #the last resource that wrote

    for line in lines:
        params = tbrparse(line)
        if not("f" in params.keys()):
            if "mPendingQ" in line:
                r = Resources_search["ptr=" + params["trans"]]
                if r.ent == None and params["ent"] in ent_ci_dict.keys():
                    r.ent = params["ent"]
                    r.ci = ent_ci_dict[params["ent"]]
            continue
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resource()
            r.URI = URI_format(params["origin"] + params["URI"])
            r.ptr = URI_format(params["ptr"])
            r.methodname = params["methodname"]
            r.channel = params["channel"]
            r.starttime = float(params["t"])
    ##        if (r.methodname != "GET"):
    ##            print "E:", r.URI, "has methodname", r.methodname
            r.num = len(Resources)
            r.lastwrittenr = lastwrittenr

            #fix lastwrite here. remove every resource that is too old, but don't remove the last one.
    ##        keep_lastwrite = [1] * len(lastwrites)
    ##        for ind in range(0, len(lastwrites)-1): #off by one
    ##            lastwrite = lastwrites[ind]
    ##            if abs(float(params["t"]) - lastwrite[1]) > 0.02:
    ##                keep_lastwrite[ind] = 0
    ##        newlastwrites = []
    ##        for ind in range(0, len(lastwrites)):
    ##            write = lastwrites[ind]
    ##            if keep_lastwrite[ind] == 1:
    ##                newlastwrites.append(write)
    ##        lastwrites = newlastwrites
    ##        r.lastwrites = list(lastwrites)
    ##        r.sURI = URI_format(params["URI"])
            Resources.append(r)
            Resources_search["ptr=" + r.ptr] = r
            if r.methodname == "GET":
                if not ("GETURI=" + URI_format(r.URI)) in Resources_search.keys():
                    Resources_search["GETURI=" + URI_format(r.URI)] = r
            if r.methodname == "POST":
                if not ("POSTURI=" + URI_format(r.URI)) in Resources_search.keys():
                    Resources_search["POSTURI=" + URI_format(r.URI)] = r
            curActive = []
            for tr in Resources:
                if tr.started == 1 and tr.ended == 0:
                    curActive.append(tr) #better than messing with another function? 
            r.curActive = curActive
            
        if params["f"] == "nsHttpConnection::Init":
            c = Connection()
            c.ptr = params["this"]

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

        if params["f"] == "nsHttpConnectionMgr::OnMsgReclaimConnection made conn idle":
            Connections_dict[params["conn"]].ent = params["ent"]
            Connections_dict[params["conn"]].ci = ent_ci_dict[params["ent"]]

        if params["f"] == "nsHttpConnectionMgr::ProcessPendingQForEntry called":
            ent_ci_dict[params["ent"]] = params["ci"]

        if params["f"] == "nsHttpConnectionMgr::DispatchTransaction":
            c = None
            r = None
            try:
                r = Resources_search["ptr=" + params["trans"]]
            except:
                print "Error: Could not find transaction being dispatched", params[trans]
            try:
                c = Connections_dict[params["conn"]]
            except:
                if r != None:
                    print "Could not find connection for", r
                else:
                    print "Could not find connection and transaction", params["conn"], params["trans"]
            if c != None and r != None:
                c.Transaction = r
                r.Connection = c
            if r.ent == None:
                r.ent = c.ent
                r.ci = c.ci

        if params["f"] == "nsHttpTransaction::ReadRequestSegment": #writes to socket
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countRead += int(params["countRead"])
                if r.requestsize == None:
                    r.requestsize = int(params["countRead"])
            else:
                print "Cannot find resource for", line

        if params["f"] == "nsHttpTransaction::WritePipeSegment": #writes to socket
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countWritten += int(params["countWritten"])
                r.started = 1
                lastwrittenr = r
            else:
                print "Cannot find resource for", line

        if params["f"] == "nsHttpConnectionMgr::AddToBestPipeline":
            try:
                r = Resources_search["ptr=" + params["trans"]]
                c = Connections_dict[params["conn"]]
                if r.Connection != None:
                    print "Error: While adding to best pipeline, r had connection"
                r.Connection = c
                if r.ent == None:
                    r.ent = c.ent
                    r.ci = c.ci
                r.pipelined = True
            except Exception as e:
                print e
                print "Error: Could not find pipeline to add", params["trans"], params["conn"]

        if params["f"] == "nsHttpTransaction::HandleContent mResponseIsComplete":
            Resources_search["ptr=" + params["ptr"]].ended = 1
    ##        print "Ending", Resources_search["ptr=" + params["ptr"]].num, "..."
    ##
    ##        for r_i in range(len(Resources)):
    ##            r = Resources[r_i]
    ##            if r.started == 1 and r.ended == 0:
    ##                print r_i, "not ended"

        if params["f"] == "nsHttpConnectionMgr::TryDispatchTransaction":
            if "context" in params.keys():
                r = Resources_search["ptr=" + params["trans"]]
                r.context = params["context"]

        if params["f"] == "ssl3_HandleHandshakeMessage":
            uri = params["url"]
            if params["msgtype"] == "11": #server certificate
                uri_certlength_dict[uri] = int(params["length"])

        if params["f"] == "nsHttpConnection::Close":
            c = Connections_dict[params["this"]]
            c.closed = 1
            for r in Resources:
                if r.started == 1 and r.ended == 0 and r.Connection == c:
                    r.ended = 1

    ##print "Resources not started:"
    ##for r in Resources:
    ##    if r.started != 1:
    ##        print Resources.index(r)
    ##
    ##print "Resources not ended:"
    ##for r in Resources:
    ##    if r.ended != 1:
    ##        print Resources.index(r)

    #Determine neighbors for parent finding
    #resources of the same server are neighbors of each other
    #neighbors = [list of [other resource, time difference of initiation]]
    for r in Resources:
        for r2 in Resources:
            if r.ent == r2.ent and r.ci == r2.ci:
                r.neighbors.append(r2)

    #Determine the dominant context
    #Objects outside of the dominant context "do not exist"
    res_ptrs = []
    res_counts = []

    for r in Resources:
        if r.context != None:
            if not (r.context in res_ptrs):
                res_ptrs.append(r.context)
                res_counts.append(0)
            res_counts[res_ptrs.index(r.context)] += 1

    truecontext = res_ptrs[res_counts.index(max(res_counts))]

    #Step -1: The first resource has no parent (parentrule written as -1, not None)
    Resources[0].parentrule = -1

    #Step 0: If there is no active transaction, the last written r is the parent.
    for r in Resources:
        if r.parentrule != None:
            continue
        if len(r.curActive) == 0:
            r.parent = r.lastwrittenr
            r.parentrule = 0

    #Then, we choose between active transactions.
    #Step 1: If there is only one active transaction, that is it
    for r in Resources:
        if r.parentrule != None:
            continue
        if len(r.curActive) == 1:
            r.parent = r.curActive[0]
            r.parentrule = 1

    #Step 2: Search the database
    for r in Resources:
        if r.parentrule != None:
            continue
        if r.URI in parentkeys:
            for r2 in r.curActive:
                if r2.URI == parentdata[parentkeys.index(r.URI)][3]:
                    r.parent = r2
                    r.parentrule = 2

    #Step 4: Consider neighbor requests from the same server
    for r in Resources:
        if r.parentrule != None:
            continue
        for r2 in r.neighbors:
            if abs(r2.starttime - r.starttime) < 0.02:
                if r2.parentrule != None:
                    if r2.parent in r.curActive:
                        r.parentrule = 4
                        r.parent = r2.parent
                        break

    #Step 5: Just pick the FIRST active resource.
    for r in Resources:
        if r.parentrule != None:
            continue
        r.parent = r.curActive[0]
        r.parentrule = 5

    ###Step 5: Only one write recently (multiple writes to the same resource is OK)
    ##for r in Resources:
    ##    if r.parentrule != None:
    ##        continue
    ##    onewrite = 1
    ##    for write in r.lastwrites:
    ##        if write[0] != r.lastwrites[0][0]: #[0] is the resource
    ##            onewrite = 0
    ##    if abs(r.lastwrites[-1][1] - r.starttime) > 0.02:
    ##        onewrite = 0
    ##    if onewrite == 1:
    ##        r.parentrule = 5
    ##        r.parent = r.lastwrites[-1][0]

    #Printout:
##    for r in Resources:
##        print Resources.index(r), "<-",
##        if r.parent != None:
##            print Resources.index(r.parent),
##        else:
##            print "/",
##        print r.parentrule, r.URI

    #do another loop to determine parentwritten

    for r in Resources:
        r.countWritten = 0
    r_ind = 0
    for line in lines:
        params = tbrparse(line)
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
            r = Resources[r_ind]
            assert (r.ptr == params["ptr"])
            Resources_search["ptr=" + r.ptr] = r
            r_ind += 1
            if r.parent != None:
                rpar = Resources_search["ptr=" + r.parent.ptr]
                r.parentwritten = rpar.countWritten


    #(ent, ci) is a unique identifier for a server
    entcis = []
    Servers = []
    for r in Resources:
        entci = [r.ent, r.ci]
        if not (entci in entcis):
            entcis.append(entci)
            s = Server()
            s.ent = r.ent
            s.ci = r.ci
            if r.pipelined == True:
                s.is_pipelining = 1
            else:
                s.is_pipelining = 0 #this is conservative
                #just because a server didn't pipeline doesn't mean it couldn't have (even with the same resources)
                #that is very rare, though
            if s.ci != None:
                if s.ci[1] == "S":
                    s.is_tls = 1
                    uri = ci_to_URI(s.ci)
                    if (uri in uri_certlength_dict.keys()):
                        s.cert_length = uri_certlength_dict[uri]
                    else:
                        print "Warnning: cannot find handshake for", uri
                else:
                    s.is_tls = 0
            else:
                s.is_tls = 0
            Servers.append(s)    
        r.server = Servers[entcis.index(entci)]
    ##    print ci_to_URI(entci[1])

    foutname = fold + fname + ".simdata"
    fout = open(foutname, "w")
    for r in Resources:
        if r.requestsize == None:
            towrite_requestsize = 400
        else:
            towrite_requestsize = r.requestsize
        if r.parent == None:
            data = [r.URI, towrite_requestsize, r.countWritten, r.parentwritten, Servers.index(r.server), "None"]
        else:
            data = [r.URI, towrite_requestsize, r.countWritten, r.parentwritten, Servers.index(r.server), Resources.index(r.parent)]
        fout.write("\t".join([str(d) for d in data]))
        fout.write("\n")
    fout.write("---\n")
    for s in Servers:
        data = [s.ci, s.is_tls, s.is_pipelining, s.cert_length, s.rec_length]
        fout.write("\t".join([str(d) for d in data]))
        fout.write("\n")
    fout.close()


