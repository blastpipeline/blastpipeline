#This code is basically taken from linker.py.

def string_to_hex(string):
    hexstring = ""
    for s in string:
        hexstring += hex(ord(s))[2:]
    return hexstring

def hex_to_string(hexstring):
    if len(hexstring) % 2 != 0:
        return None
    st = ""
    for i in range(0, len(hexstring)/2):
        chrnum = int("0x" + hexstring[i*2:i*2+2], 16)
        st += chr(chrnum)
    return st

def phex_to_string(hexstring):
    if len(hexstring) % 2 != 0:
        return None

    goodrange = range(32, 127)
    goodrange.append(10)
    st = ""
    for i in range(0, len(hexstring)/2):
        chrnum = int("0x" + hexstring[i*2:i*2+2], 16)
        if chrnum in goodrange:
            st += chr(chrnum)
        else:
            st += "."
    return st

def URI_format(URI):
    #remove fragment identifier because they don't matter on the wire
    if ("#" in URI):
        URI = URI.split("#")[0]
    return URI

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

class tbrdata:
    def __init__(self, time=0, di=0):
        self.data = "" #recorded as a string
        #beware: this length is twice of actual data byte length
        self.time = float(time)
        self.di = di
        self.circ = None #circuit number for pells and cells, socket pointer for records
        self.fass = [] #front association down to Tor cells
        self.bass = [] #back association up to TBR segments (segments have bass of Resources)
        self.fassinds = []
        self.bassinds = []
        self.fassranges = []
        self.bassranges = []
        
        self.len = -1 #used for segments
        
        self.type = None #segment, record, pell, or cell
        self.is_enc = None #decide if segments or records contain encrypted data
        #SSL records (parsed from dpells) are always encrypted, but plaintext in dpells are also called records
    def parse_data(self, lines):
        data = ""
        for line in lines:
            line = line.strip("\n")
            line = line.strip(" ")
            data += line
        self.data = data
    def is_ssl_data(self):
        if self.type == "record":
            if int("0x" + self.data[:2], 16) == 23:
                return 1
        return 0
    def __repr__(self):
        st =  "tbrdata at time {}, di {}, data:\n".format(self.time, self.di)
        if (self.type == "record" and self.is_enc == 0) or \
           (self.type == "segment"):
            st += hex_to_string(self.data)
        else:
            st += self.data
        return st
    def __len__(self):
        if self.len == -1:
            return len(self.data)
        else:
            return self.len
        

class tbrpell(tbrdata):
    def __init__(self, time=0, di=0):
        tbrdata.__init__(self, time, di)
        self.htype = -1
        self.header = ""
        
    def parse_cell(self):
        #called after data is loaded in with parse_data
        self.htype = int("0x" + self.data[0:2], 16)
        length = int("0x" + self.data[18:22], 16)
        self.header = self.data[:22]
        self.data = self.data[22:22+length*2]
        
    def __repr__(self):
        st =  "tbrdata at time {}, di {}, type {}, data:\n".format(self.time, self.di, self.type)
        st += self.data
        return st

#Resource (= Transaction), Connection, Socket
#They have links to each other
#Each transaction should probably belong only to one connection
#Each connection should probably belong only to one socket
#Check if any transaction/connection/socket is not properly connected

class Resource: #holds data for a HttpTransaction
    def __init__(self):
        self.ptr = ""
        self.length = 0
        self.URI = ""
        self.referrer = None
        self.methodname = ""
        self.channel = "" #currently unused
        self.Connection = None
        self.countWritten = 0
        self.countRead = 0
        self.num = -1 #used by printout of referrer
        self.fass = [] #front association to segments
        self.fassinds = []
        self.cells = []
        self.cellinds = []

        self.started = 0
        self.ended = 0

        self.context = None
        self.parent = None #referrer is not necessarily parent

        self.data = ["", ""]
        self.hexdata = ["", ""]

        self.sURI = ""
        self.timediff = None
        
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
        string += " with length " + str(self.length)
        return string
    def __repr__(self):
        return str(self)

class Connection:
    def __init__(self):
        self.ptr = ""
        self.Transaction = None
        self.SocketIn = None
        self.SocketOut = None
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

#=== Parses resources to build resource tree ===
import os
SITE_NUM = 200
INST_NUM = 12
DATA_LOC = "data/treebatch/"
fout = open("parentdata.txt", "w")
fout.close()
fnames = []
for i in range(0, SITE_NUM):
    for j in range(0, INST_NUM):
        fname = "{}{}-{}-0".format(DATA_LOC, i, j)
        if os.path.exists(fname + ".tbrlog"):
            fnames.append(fname)

progind = 0
progcount = 0
for fname in fnames:
    if progcount*100/len(fnames) > progind:
        progind += 1
        print "{}% done ({}/{})".format(progind, progcount, len(fnames))
    progcount += 1
    tbr_infile = fname + ".tbrlog"
    f = open(tbr_infile, "r")
    lines = f.readlines()
    f.close()

    Resources = []
    Connections = []
    Sockets = []
    Resources_search = {} #table for the right resources
    Connections_dict = {} #to get objects with pointers
    Sockets_dict = {}
    for line in lines:
        params = tbrparse(line)
        if not("f" in params.keys()):
            continue
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resource()
            r.URI = URI_format(params["origin"] + params["URI"])
            r.ptr = URI_format(params["ptr"])
            r.methodname = params["methodname"]
            r.channel = params["channel"]
    ##        if (r.methodname != "GET"):
    ##            print "E:", r.URI, "has methodname", r.methodname
            r.num = len(Resources)
            r.sURI = URI_format(params["URI"])
            Resources.append(r)
            Resources_search["ptr=" + r.ptr] = r
            if r.methodname == "GET":
                if not ("GETURI=" + URI_format(r.URI)) in Resources_search.keys():
                    Resources_search["GETURI=" + URI_format(r.URI)] = r
            if r.methodname == "POST":
                if not ("POSTURI=" + URI_format(r.URI)) in Resources_search.keys():
                    Resources_search["POSTURI=" + URI_format(r.URI)] = r
            
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
                r.started = 1

        if params["f"] == "nsHttpTransaction::ReadRequestSegment": #writes to socket
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countRead += int(params["countRead"])
            else:
                print "Cannot find resource for", line
    ##        seg = segments[possegmentsinds[possegmentsptr]]
    ##        if seg.time != float(params["t"]):
    ##            raise Exception("Pos segment time mismatch", possegmentsptr, seg.time, float(params["t"]))
    ##        seg.bass.append(r)
    ##        seg.bassinds.append(r.num)
    ##        r.fass.append(seg)
    ##        r.fassinds.append(possegmentsinds[possegmentsptr])
    ##        possegmentsptr += 1

        if params["f"] == "nsHttpTransaction::WritePipeSegment": #writes to socket
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countWritten += int(params["countWritten"])
            else:
                print "Cannot find resource for", line
    ##        seg = segments[negsegmentsinds[negsegmentsptr]]
    ##        if seg.time != float(params["t"]):
    ##            raise Exception("Neg segment time mismatch", negsegmentsptr, seg.time, float(params["t"]))
    ##        seg.bass.append(r)
    ##        seg.bassinds.append(r.num)
    ##        r.fass.append(seg)
    ##        r.fassinds.append(negsegmentsinds[negsegmentsptr])
    ##        negsegmentsptr += 1

        if params["f"] == "nsHttpConnectionMgr::AddToBestPipeline":
            try:
                r = Resources_search["ptr=" + params["trans"]]
                c = Connections_dict[params["conn"]]
                if r.Connection != None:
                    print "Error: While adding to best pipeline, r had connection"
                r.Connection = c
            except:
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

    #let us determine the dominant referrer
    res_ptrs = []
    res_counts = []

    for r in Resources:
        if r.context != None:
            if not (r.context in res_ptrs):
                res_ptrs.append(r.context)
                res_counts.append(0)
            res_counts[res_ptrs.index(r.context)] += 1

    truecontext = res_ptrs[res_counts.index(max(res_counts))]

    #We use a second loop to determine referrers
    #The referrer is the last WritePipeSegment when this transaction was created
    #But this only counts the ones with true context

    count = 0
    lastr = None
    lasttime = None
    for line in lines:
        params = tbrparse(line)
        if not("f" in params.keys()):
            continue
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resources[count]
            count += 1
            Resources_search["ptr=" + r.ptr] = r
            if r.ptr != params["ptr"]:
                print "Error: ptr mismatch", count
                sys.exit(-1)
            r.parent = lastr
            if lasttime != None:
                r.timediff = float(params["t"]) - lasttime #time between last write pipe segment and this init
        if (params["f"] == "nsHttpTransaction::WritePipeSegment"):
            r = Resources_search["ptr=" + params["ptr"]]
            if r.context == truecontext:
                lastr = r
                lasttime = float(params["t"])

##    for r in Resources:
##        if r.context != truecontext:
##            continue
##        print r.num,
##        print r.timediff,
##        curr = r
##        while curr.parent != None:
##            print "<-" + str(curr.parent.num),
##            curr = curr.parent
##        print r.URI

    fout = open("parentdata.txt", "a")
    for r in Resources:
        if r.context == truecontext:
            if r.parent == None:
                parentname = "None"
            else:
                parentname = r.parent.URI
            st = "\t".join([tbr_infile, str(r.timediff), r.URI, parentname]) + "\n"
            fout.write(st)
    fout.close()

##def dechunk(data):
##    pdata = ""
##    while len(data) > 0:
##        #for some reason it doesn't seem to always end with \r\n
##        
####        print len(data)
##        header = data[:data.index("\r\n")]
##        if header == "0":
##            break
##        data = data[data.index("\r\n"):][2:]
##        if ";" in header:
##            header = header.split(";")[0]
##        chunksize = int("0x" + header, 16)
##        pdata += data[:chunksize]
##        data = data[chunksize+2:]
##    return pdata
##
###== reads in real data for each resource ==
##
##tdr_infile = tbr_infile[:-6] + "tdrlog"
##f = open(tbr_infile, "r")
##lines = f.readlines()
##f.close()
##reads = []
##read_times = []
##writes = []
##write_times = []
##
##count = 0
##for line in lines:
##    params = tbrparse(line)
##    if not("f" in params.keys()):
##        continue
##    if (params["f"] == "nsHttpTransaction::Init"):
##        r = Resources[count]
##        count += 1
##        Resources_search["ptr=" + r.ptr] = r
##        if r.ptr != params["ptr"]:
##            print "Error: ptr mismatch", count
##            sys.exit(-1)
##    if params["f"] == "nsHttpTransaction::ReadRequestSegment":
##        reads.append(Resources_search["ptr=" + params["ptr"]])
##        read_times.append(params["t"])
##    if params["f"] == "nsHttpTransaction::WritePipeSegment":
##        writes.append(Resources_search["ptr=" + params["ptr"]])
##        write_times.append(params["t"])
##
##
##f = open(tdr_infile, "r")
##lines = f.readlines()
##f.close()
##
###use time as a unique pointer here
##tar_r = None
##tar_dir = None
##data = ""
##for line in lines:
##    readheader = 0
##    if len(line) > 2:
##        if line[:2] == "f=":
##            params = tbrparse(line)
##            readheader = 1
##            if tar_r != None:
##                tar_r.hexdata[tar_dir] += data
##                data = ""
##            if params["f"] == "nsHttpTransaction::WritePipeSegment":
##                time = params["t"]
##                if time in write_times:
##                    tar_r = writes[write_times.index(time)]
##                    tar_dir = 1 #it's incoming
##                else:
##                    tar_r = None
##                    tar_dir = None
##            if params["f"] == "nsHttpTransaction::ReadRequestSegment":
##                time = params["t"]
##                if time in read_times:
##                    tar_r = reads[read_times.index(time)]
##                    tar_dir = 0 #it's outgoing
##                else:
##                    tar_r = None
##                    tar_dir = None
##    if readheader == 0:
##        line = "".join(line.split(" "))
##        line = line.strip()
##        data += line
##
##import brotli
##
##def getheader(i):
##    if "0d0a0d0a" in Resources[i].hexdata[1]:
##        return hex_to_string(Resources[i].hexdata[1].split("0d0a0d0a")[0])
##    else:
##        return ""
##def getcontents(i):
##    if "0d0a0d0a" in Resources[i].hexdata[1]:
##        return hex_to_string(Resources[i].hexdata[1][Resources[i].hexdata[1].index("0d0a0d0a")+8:])
##    else:
##        return ""
##
##for i in range(0, len(Resources)):
##    print i,
##    h = getheader(i)
##    c = getcontents(i)
##    if "Transfer-Encoding:" in h:
##        print "encoded",
##    if "Transfer-Encoding: chunked" in h:
##        print "chunked",
##        c = dechunk(c)
##    if "Content-Encoding: br" in h:
##        try:
##            c = brotli.decompress(c)
##            print "decompressed br",
##        except:
##            print "decompress failed",
##            pass
##    Resources[i].data[1] = h + "\r\n\r\n" + c
####    print h6
##    print ""
##
##for r in Resources:
##    hexs = string_to_hex(r.URI)
##    for r2 in Resources:
##        if r.URI in r2.data[1]:
##            print Resources.index(r), Resources.index(r2)
##
##sys.exit(-1)
    

###we use a second loop to determine referrers, because they could be before init
##Resources_ptr = 0
##for line_i in range(0, len(lines)):
##    line = lines[line_i]
##    params = tbrparse(line)
##    if (params["f"] == "nsHttpChannel::SetupTransaction"):
##        r = Resources[Resources_ptr]
##        assert(Resources[Resources_ptr].ptr == params["mTransaction"])
##        Resources_ptr += 1
##        if "type" in params.keys():
##            if params["type"] == "WithoutTrigger":
##                #this cannot be used
##                continue
##        try:
##            r2 = Resources_search["GETURI=" + URI_format(params["triggeringURI"])]
##        except:
##            print "Error: did not find referrer for", line
##            continue
##        r.referrer = r2
####    if (params["f"] == "nsHttpTransaction::WritePipeSegment"):
####        r.mTransferSize = int(params["countWritten"])
##    #a redirect is like a referrer for our purposes
##    if (params["f"] == "nsHttpChannel::AsyncProcessRedirection"): #
##        try:
##            r = Resources_search["GETURI=" + URI_format(params["mRedirectURI"])]
##            r2 = Resources_search["GETURI=" + URI_format(params["mURI"])]
##        except:
##            print "Error: did not find redirect for", line
##            continue
##        r.referrer = r2
##    if (params["f"]== "nsHttpTransaction::HandleContent mResponseIsComplete"):
##        try:
##            r2 = Resources_search["ptr=" + params["ptr"]]
##            r2.length = int(params["mTransferSize"])
##        except:
##            print "mResponseIsComplete could not find transaction", params["ptr"]
####        print r
