#Opens tbrlog, trlg, and tdrlog files
#Gets all relevant stuff, writes a dill file
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

#4947 
class tbrdata:
    def __init__(self, time=0, di=0):
        self.data = "" #recorded as a string
        self.header = "" #used for records, pells
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
        self.num = -1
        
        self.type = None #segment, record, pell, or cell
        self.is_enc = None #decide if segments or records contain encrypted data
        self.isdata = 0 #decide if a pell contains real data (corresponding to segments)
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
    def is_data(self):
        if self.type == "record":
            if int("0x" + self.data[:2], 16) == 23 or self.data[:8] == "48545450": #SSL data or HTTP
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
        return len(self.data)
        

class tbrpell(tbrdata):
    def __init__(self, time=0, di=0):
        tbrdata.__init__(self, time, di)
        self.htype = -1
        
    def parse_cell(self):
        #called after data is loaded in with parse_data
        self.htype = int("0x" + self.data[0:2], 16)
        length = int("0x" + self.data[18:22], 16)
        self.circ = int("0x" + self.data[6:10], 16)
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
        self.URI = ""
        self.referrer = None
        self.referrerWritten = -1 #how much the referrer wrote when we loaded it
        self.methodname = ""
        self.channel = "" #currently unused
        self.Connection = None
        self.countWritten = 0
        self.countRead = 0
        self.num = -1 #used by printout of referrer
        self.fass = [] #front association to segments
        self.fassinds = []

        self.endtime = None
        self.connind = None
        self.xell_inds = []

        self.writtenSegmentSizes = [] #used for referrerWritten

        self.cell_inds = [] #filled by fill_cell_inds()

        self.createdtime = 0
        self.dispatchedtime = 0
        self.ispipelined = 0
        self.complete = 0
        self.blocking = 0
        
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
        string += " with length " + str(self.countWritten)
        return string
    def __repr__(self):
        return str(self)

    def fill_cell_inds(self):
        cell_inds = []
        for segment in self.fass:
            for record in segment.fass:
                for pell in record.fass:
                    k = pell.num
                    if not(k) in cell_inds:
                        cell_inds.append(k)
        self.cell_inds = cell_inds

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

class Stream:
    #A stream ID, as processed directly from pells
    def __init__(self):
        self.pells = []
        self.pellinds = []
        self.id = 0 #stream ID
        self.createdtime = 0
        self.tlstime = 0
        self.sizes = [0, 0]
    def __str__(self):
        string = "Stream {} with pellinds {}".format(
            self.id, self.pellinds)
        return string
    def __repr__(self):
        return str(self)
        

def cellstate_to_num(state):
    states = ["bstart", "bend", "astart", "aend"]
    if state in states:
        return states.index(state)
    else:
        print "Error: cellstate_to_num cannot find state", state
        return -1

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
        st += chr(int("0x" + hexstring[i*2:i*2+2], 16))
    return st

def URI_format(URI):
    #remove fragment identifier because they don't matter on the wire
    if ("#" in URI):
        URI = URI.split("#")[0]
    return URI

def lev(rlens, slens):
    ##rlens = [0, 1, 2]
    ##slens = [0, 1, 2, 3]

    #use levenshtein distance (no substitutions) to match
    lev = range(0, len(slens)+1)  
    #cur_lev[j] is distance between rlens[:i] and slens[:j] for current i; lev[j] is previous
    #changes[j] is how rlen can become slen
    #changes[j] is a list of [-1, i] (remove rlens[i] from rlens)
    #or [1, i] (add slens[i] to rlens, when rlens has i elements)
    paths = []
    for i in range(0, len(rlens)+1):
        paths.append([0] * (len(slens) + 1))
    paths[0][0] = 3
    #paths[i][j] = 0 means we got here by adding a slens
    #1 means we got here by skipping a rlens
    #2 means we didn't have to change rlens to get to slens
    #3 is the edge
    #lev[0][j] is the last row
    for i in range(1, len(rlens)+1):
        cur_lev = [0] * (len(slens) + 1)
        cur_lev[0] = i
        paths[i][0] = 1
        
        for j in range(1, len(slens)+1):
            if lev[j] + 1 > cur_lev[j-1] + 1:
                minlev = cur_lev[j-1] + 1
                paths[i][j] = 0
            else:
                minlev = lev[j] + 1
                paths[i][j] = 1
            if slens[j-1] == rlens[i-1] and lev[j-1] <= minlev:
                minlev = lev[j-1]
                paths[i][j] = 2
            cur_lev[j] = minlev
        lev = cur_lev
##    for p in paths:
##        print p
    changes = []
    
    cur_x = len(rlens)
    cur_y = len(slens)
    while paths[cur_x][cur_y] != 3:
        if paths[cur_x][cur_y] == 0:
            cur_y -= 1
            changes.append([1, cur_y])
        if paths[cur_x][cur_y] == 1:
            cur_x -= 1
            changes.append([-1, cur_x])
        if paths[cur_x][cur_y] == 2:
            cur_x -= 1
            cur_y -= 1
    changes = changes[::-1]
    return changes

def read_trlg(torname):
    #this was written after read_torlog, for the new data format
    #we noted that cells is actually never used
    #so we just read pells and leave cells empty
    pells = []

    f = open(torname, "r")
    lines = f.readlines()
    f.close()

    for line in lines:
        line = line[:-1]
        li = line.split(" ")
        t = float(li[0])
        d = int(li[1])
        pell = tbrpell(time=t, di=d)
        pell.circ = int(li[2])
        pell.type = "pell"
        pell.is_enc = 1
        pell.header = str(li[3])
        pell.data = str(li[4])
        pell.num = len(pells)

        #sanity check of length
        assert(len(pell.data) == int("0x" + pell.header[18:22], 16) * 2)
        pell.htype = int("0x" + pell.header[0:2], 16)
        pells.append(pell)


    return pells, []

import dill
import os
import sys
##rlens = [0, 0, 0, 15, 25, 35]
##slens = [15, 25, 35]
##changes = lev(rlens, slens)
##print changes
##sys.exit(-1)

fnames = []
[sitestart, inststart] = [0, 0]
[siteend, instend] = [200, 2]
fold = "data/treebatch-nopipeline/"
for fname_i in range(sitestart, siteend):
    if fname_i == sitestart:
        fname_start = inststart
    else:
        fname_start = 0
    for fname_j in range(fname_start, instend):
        for k in range(0, 6):
            fname = "{}-{}-{}".format(fname_i, fname_j, k)
            endings = [".tbrlog", ".tdrlog", ".trlg"]
            exist = 1
            for ending in endings:
                if not(os.path.exists(fold + fname + ending)):
##                    print "{}{} not found".format(fname, ending)
                    exist = 0
            if exist == 1:
                fnames.append(fname)


##fnames = ["2-10-3"]
##fnames = fnames[2424:]
##fnames = fnames[fnames.index("37-0-1"):]
##fnames = ["1-1-5"]
for fname in fnames:
    print fname
    tbrname = fold + fname + ".tbrlog"
    tdrname = fold + fname + ".tdrlog"
    trname = fold + fname + ".trlg"

    pells = []

    pells, [] = read_trlg(trname)
    #note that each cell has a header
    #1st byte is its type (02 = data)
    #4th/5th is its stream
    #10th/11th is its length

    #link all pells to streams
    Streams = []
    Streams_dict = {} #matches ID to stream object
    for pell_i in range(len(pells)):
        pell = pells[pell_i]
        if pell.circ != 0 and pell.circ != -1:
            if not(pell.circ in Streams_dict.keys()):
                s = Stream()
                s.id = pell.circ
                Streams.append(s)
                Streams_dict[pell.circ] = s
            s = Streams_dict[pell.circ]
            s.pells.append(pell)
            s.pellinds.append(pell_i)
    #calculate stream tlstime, createdtime
    for s in Streams:
        for pell in s.pells:
            if len(pell.data) >= 6:
                if pell.data[:6] == "160301" or pell.data[:6] == "160300":
                    if s.tlstime == 0:
                        s.tlstime = pell.time
                        break
        s.createdtime = s.pells[0].time

    #for simplicity in the linking code, it is easier to only have data pells
    dpells = [] #data pells
    for pell in pells:
        if pell.htype == 2:
            dpells.append(pell)

    #we build a dictionary for each stream's dpells (using negative stream numbers) here:
    #dpells_dict[stream] should be a list of indices for dpells of that stream
    dpells_dict = {}

    for dpell_i in range(len(dpells)):
        pell = dpells[dpell_i]
        streamstr = str(pell.circ) + "," + str(pell.di)
##            stream = int(pell.circ) * int(pell.di)
        if not(streamstr in dpells_dict.keys()):
            dpells_dict[streamstr] = []
        dpells_dict[streamstr].append(dpell_i)

    #from dpells, parse out records
    #some "records" are actually plaintext in pells
    records = [] #we will populate this using dpells
    for streamstr in dpells_dict.keys():
        #get all the data together
        streamdata = ""
        dpell_ranges = [] #dpell_ranges[i] is [total length up to and including cell i, index for pdell]
        dpell_times = [] #dpell_times[i] is [total length up to cell i, time of cell i]
        for ind in dpells_dict[streamstr]:
            streamdata += dpells[ind].data
            dpell_ranges.append([len(streamdata), ind])
            dpell_times.append([len(streamdata), dpells[ind].time])
        streamptr = 0
        rangeptr = 0

        #first, let us decide if this stream is encrypted
        #to do so, we try to parse it as SSL records; if we fail, it is considered unencrypted.
        enc_succeeded = 0
        while streamptr < len(streamdata) - 10:
            header = int("0x" + streamdata[streamptr:streamptr+2], 16)
            version = streamdata[streamptr+2:streamptr+6]
            length = int("0x" + streamdata[streamptr+6:streamptr+10], 16)*2
            if header < 20 or header > 23 or streamptr+10+length > len(streamdata):
                #this isn't encrypted
                break
            if version == "0303" or version == "0301":
                enc_succeeded += 1
            streamptr += 10 + length

##            print enc_succeeded

        if (enc_succeeded == 0):
            #let's try to parse streamdata as HTTP records
            #if we fail at any stage, throw the rest of streamdata into a record and call it a day
            #use the first pell's time, with slight differentiation to avoid time-based issues
            dictptr = 0
            dataptr = 0
            try:
                print "attempting to parse HTTP stream", streamstr, len(streamdata)
                while len(streamdata) > 0:
                    headerend = streamdata.index("0d0a0d0a")
                    httpheaders = streamdata[:headerend].split("0d0a")
                    cohe = string_to_hex("Content-Length: ")
                    foundhe = 0
                    for he in httpheaders:
                        if he[:len(cohe)] == cohe:
                            foundhe = 1
                            length = int(hex_to_string(he[len(cohe):len(he)]))
                            this_data = streamdata[:headerend+2*length+8]
                            streamdata = streamdata[headerend+2*length+8:]
                            dpell = dpells[dpells_dict[streamstr][dictptr]]
                            record = tbrdata(time=dpell.time, di=dpell.di) #shouldn't be final time
                            record.data = this_data
                            record.circ = int(streamstr.split(",")[0])
                            record.type = "record"
                            record.is_enc = 0
                            tomoveptr = len(this_data)
                            while (tomoveptr > 0):
                                dpell = dpells[dpells_dict[streamstr][dictptr]]
                                remlen = min(tomoveptr, len(dpell.data) - dataptr)
                                tomoveptr -= remlen
                                record.time = dpell.time
                                record.fass.append(dpell)
                                record.fassinds.append(dpells_dict[streamstr][dictptr])
                                record.fassranges.append([dataptr, dataptr+remlen])
                                dpell.is_enc = 0
                                dataptr += remlen
                                if dataptr == len(dpell.data):
                                    dataptr = 0
                                    dictptr += 1
                            records.append(record)
                            print "created record of length", len(record), "during stream split"
                    if foundhe == 0:
                        raise Exception("did not find content length header")
            except Exception as e:
                print e
                pass
            
            if len(streamdata) == 0:
                continue
            #throw the rest into a record
            dpell = dpells[dpells_dict[streamstr][dictptr]]
            record = tbrdata(time=dpell.time, di=dpell.di)
            record.data = streamdata
            record.circ = int(streamstr.split(",")[0])
            record.type = "record"
            record.is_enc = 0
            this_data = streamdata
            tomoveptr = len(this_data)
            while (tomoveptr > 0):
                dpell = dpells[dpells_dict[streamstr][dictptr]]
                remlen = min(tomoveptr, len(dpell.data) - dataptr)
                tomoveptr -= remlen
                record.time = dpell.time
                record.fass.append(dpell)
                record.fassinds.append(dpells_dict[streamstr][dictptr])
                record.fassranges.append([dataptr, dataptr+remlen])
                dpell.is_enc = 0
                dataptr += remlen
                if dataptr == len(dpell.data):
                    dataptr = 0
                    dictptr += 1
            records.append(record)
            continue

        #if we get here,  it is encrypted
        streamptr = 0    
        while (streamptr < len(streamdata) - 10):
            #read in header
            header = int("0x" + streamdata[streamptr:streamptr+2], 16)
            #read in length
            length = int("0x" + streamdata[streamptr+6:streamptr+10], 16)*2
            if header < 20 or header > 23 or streamptr+10+length > len(streamdata):
                #this can happen because the condition checking is greedy (we parse as much as we can)
                break
            #we create a record, inheriting all info from the -last- cell
            streamptr += 10 + length
            fassinds = [dpell_ranges[rangeptr][1]]
            if (rangeptr >= 1):
                fassranges = [[max(streamptr-10-length-dpell_ranges[rangeptr-1][0], 0),
                               min(streamptr-dpell_ranges[rangeptr-1][0], len(dpells[dpell_ranges[rangeptr][1]].data))]]
            else:
                fassranges = [[max(streamptr-10-length, 0), min(streamptr, dpell_ranges[rangeptr][0])]]
            time = dpell_times[rangeptr][1]
            while streamptr > dpell_ranges[rangeptr][0]:
                rangeptr += 1
                fassinds.append(dpell_ranges[rangeptr][1])
                fassranges.append([0, min(streamptr-dpell_ranges[rangeptr-1][0], len(dpells[dpell_ranges[rangeptr][1]].data))])
                time = dpell_times[rangeptr][1]
            record = tbrdata(time=time, di=int(streamstr.split(",")[1]))
            record.data = streamdata[streamptr-10-length:streamptr]
            record.circ = int(streamstr.split(",")[0])
            record.fassinds = fassinds
            record.type = "record"
            record.is_enc = 1
            for ind in record.fassinds:
                record.fass.append(dpells[ind])
            record.fassranges = fassranges
            records.append(record)
            if streamptr == dpell_ranges[rangeptr][0]:
                rangeptr += 1
        if (streamptr < len(streamdata)):
            print "parsing excess records", streamptr, len(records), len(streamdata), streamdata[streamptr:streamptr+10]
##                sys.exit(-1)
            #again, throw the rest into a record
            #parsing code copied from the above
            length = len(streamdata) - streamptr - 10 #this is a fake length created for this
            if (length <= 0):
                break
            streamptr = len(streamdata)
            fassinds = [dpell_ranges[rangeptr][1]]
            if (rangeptr >= 1):
                fassranges = [[max(streamptr-10-length-dpell_ranges[rangeptr-1][0], 0),
                               min(streamptr-dpell_ranges[rangeptr-1][0], len(dpells[dpell_ranges[rangeptr][1]].data))]]
            else:
                fassranges = [[max(streamptr-10-length, 0), min(streamptr, dpell_ranges[rangeptr][0])]]
            time = dpell_times[rangeptr][1]
            while streamptr > dpell_ranges[rangeptr][0]:
                rangeptr += 1
                fassinds.append(dpell_ranges[rangeptr][1])
                fassranges.append([0, min(streamptr-dpell_ranges[rangeptr-1][0], len(dpells[dpell_ranges[rangeptr][1]].data))])
                time = dpell_times[rangeptr][1]
            record = tbrdata(time=time, di=int(streamstr.split(",")[1]))
            record.data = streamdata[streamptr-10-length:]
            record.circ = int(streamstr.split(",")[0])
            record.fassinds = fassinds
            record.fassranges = fassranges
            record.type = "record"
            record.is_enc = 0
            for ind in record.fassinds:
                record.fass.append(dpells[ind])
            records.append(record)
    records = sorted(records, key = lambda r:r.time)

    #extract out the header of every record
    for r in records:
        if r.is_enc == 1:
            r.header = r.data[:12] #we stole an extra byte because it may be the handshake/alert
        else:
            r.header = ""
    #connect pells back to records
    for record_i in range(0, len(records)):
        record_ptr = 0
        for ind_i in range(len(records[record_i].fassinds)):
            ind = records[record_i].fassinds[ind_i]
            dpells[ind].bass.append(records[record_i])
            dpells[ind].bassinds.append(record_i)
            ptrsize = records[record_i].fassranges[ind_i][1] - records[record_i].fassranges[ind_i][0]
            dpells[ind].bassranges.append([record_ptr, record_ptr + ptrsize])
            record_ptr += ptrsize

    ##for i in range(0, 50):
    ##    print i,records[i].fassinds, records[i].fassranges

    ##for i in range(0, len(dpells)):
    ##    print dpells[i].bassranges, len(dpells[i].data)
    ##sys.exit(-1)
    for ind in range(0, len(records)):
        st = ""
        for dpell_ind_i in range(len(records[ind].fassinds)):
            dpell_ind = records[ind].fassinds[dpell_ind_i]
            dpell_range = records[ind].fassranges[dpell_ind_i]
            st += dpells[dpell_ind].data[dpell_range[0]: dpell_range[1]]
        if st != records[ind].data:
            raise Exception("sanity check failed at record/dpell link {}".format(ind))

    #now, update all record fassinds to point to pells, not dpells
    for r in records:
        for ind in range(len(r.fassinds)):
            r.fassinds[ind] = r.fass[ind].num
    f = open(tdrname, "r")
    lines = f.readlines()
    f.close()

    #first, read in segments
    segments = []
    reading = 0
    data = ""
    for line in lines:
        if "\t" in line:
            pline = tbrparse(line)
            if pline["f"] in ["nsHttpTransaction::WritePipeSegment",
                              "nsHttpTransaction::ReadRequestSegment"] and \
                              pline["type"] == "start":
                reading = 1
            if pline["f"] == "nsHttpTransaction::WritePipeSegment" and \
               pline["type"] == "end":            
                tb = tbrdata(time=float(pline["t"]), di=-1)
                tb.type = "segment"
                tb.data = data
                data = ""
                reading = 0
                segments.append(tb)
            if pline["f"] == "nsHttpTransaction::ReadRequestSegment" and \
               pline["type"] == "end":
                tb = tbrdata(time=float(pline["t"]), di=1)
                tb.type = "segment"
                tb.data = data
                data = ""
                reading = 0
                segments.append(tb)
        else:
            if reading == 1:
                line = line.strip("\n")
                line = "".join(line.split(" "))
                data += line
                
    #give each segment and resource a "circuit" (the connection pointer from tbrlog)
    f = open(tbrname, "r")
    lines = f.readlines()
    f.close()
    segptr = 0
    trans_connind_dict = {} #trans_conn_dict[trans] says what connection the trans is dispatched under
    conn_ptrs = []
    conn_ptrs_connind_dict = {}
    conn_sizes = []
    for line in lines:
        if not("\t" in line and line[:2] == "f="):
            continue
        if "\t" in line:
            pline = tbrparse(line)
            if pline["f"] in ["nsHttpConnection::Init"]:
                conn_ptrs_connind_dict[pline["this"]] = len(conn_ptrs) 
                conn_ptrs.append(pline["this"])
                conn_sizes.append([0, 0])
            if pline["f"] in ["nsHttpConnectionMgr::DispatchTransaction",
                              "nsHttpConnectionMgr::AddToBestPipeline"]:
                trans_connind_dict[pline["trans"]] = conn_ptrs_connind_dict[pline["conn"]]
            if pline["f"] in ["nsHttpTransaction::WritePipeSegment",
                              "nsHttpTransaction::ReadRequestSegment"]:
                if (segptr >= len(segments)):
                    continue
                this_time = float(pline["t"])
                if this_time != segments[segptr].time:
                    raise Exception("seg time mismatch", segptr, line)
                segments[segptr].circ = trans_connind_dict[pline["ptr"]]
                if pline["f"] in "nsHttpTransaction::ReadRequestSegment":
                    conn_sizes[segments[segptr].circ][0] += int(pline["countRead"])
                if pline["f"] in "nsHttpTransaction::WritePipeSegment":
                    conn_sizes[segments[segptr].circ][1] += int(pline["countWritten"])
                segptr += 1

    #in preparation for segments linking during resource reading, let us build an index of positive and negative segments
    possegmentsinds = []
    negsegmentsinds = []
    for i in range(len(segments)):
        if segments[i].di == 1:
            possegmentsinds.append(i)
        else:
            negsegmentsinds.append(i)
    possegmentsptr = 0
    negsegmentsptr = 0

    f = open(tbrname, "r")
    lines = f.readlines()
    f.close()

    Resources = []
    Connections = []
    Sockets = []
    Resources_search = {} #table for the right resources
    Connections_dict = {} #to get objects with pointers
    Sockets_dict = {}
    
    conn_ptrs_connind_dict = {}
    conn_ptrs = []
    for line in lines:
        if not("\t" in line and line[:2] == "f="):
            continue
        params = tbrparse(line)
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resource()
            r.URI = URI_format(params["origin"] + params["URI"])
            r.ptr = URI_format(params["ptr"])
            r.methodname = params["methodname"]
            r.channel = params["channel"]
    ##        if (r.methodname != "GET"):
    ##            print "E:", r.URI, "has methodname", r.methodname
            r.num = len(Resources)
            r.createdtime = float(params["t"])
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
            
            conn_ptrs_connind_dict[params["this"]] = len(conn_ptrs) 
            conn_ptrs.append(params["this"])

        if params["f"] in ["nsHttpConnectionMgr::DispatchTransaction",
                           "nsHttpConnectionMgr::AddToBestPipeline"]:
            c = None
            r = None
            try:
                r = Resources_search["ptr=" + params["trans"]]
            except:
                print "Error: Could not find transaction being dispatched", params[trans]
                continue
            try:
                c = Connections_dict[params["conn"]]
            except:
                if r != None:
                    print "Could not find connection for", r
                else:
                    print "Could not find connection and transaction", params["conn"], params["trans"]
                continue
            if c != None and r != None:
                c.Transaction = r
                r.Connection = c
                r.connind = conn_ptrs_connind_dict[params["conn"]]
                r.dispatchedtime = float(params["t"])
                if params["f"] == "nsHttpConnectionMgr::AddToBestPipeline":
                    r.ispipelined = 1

        if params["f"] == "nsHttpTransaction::ReadRequestSegment": #writes to socket
            if possegmentsptr >= len(possegmentsinds): #this happens if tbrlog has more stuff than tdrlog
                continue
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countRead += int(params["countRead"])
            else:
                print "Cannot find resource for", line
            seg = segments[possegmentsinds[possegmentsptr]]
            if seg.time != float(params["t"]):
                raise Exception("Pos segment time mismatch", possegmentsptr, seg.time, float(params["t"]))
            seg.bass.append(r)
            seg.bassinds.append(r.num)
            r.fass.append(seg)
            r.fassinds.append(possegmentsinds[possegmentsptr])
            possegmentsptr += 1

        if params["f"] == "nsHttpTransaction::WritePipeSegment": #writes to socket
            if negsegmentsptr >= len(negsegmentsinds): #this happens if tbrlog has more stuff than tdrlog
                continue
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.countWritten += int(params["countWritten"])
            else:
                print "Cannot find resource for", line
            #do a sanity check
            seg = segments[negsegmentsinds[negsegmentsptr]]
            if seg.time != float(params["t"]):
                raise Exception("Neg segment time mismatch", negsegmentsptr, seg.time, float(params["t"]))
            seg.bass.append(r)
            seg.bassinds.append(r.num)
            r.fass.append(seg)
            r.fassinds.append(negsegmentsinds[negsegmentsptr])
            r.endtime = float(params["t"])
            negsegmentsptr += 1
            
        if (params["f"]== "nsHttpTransaction::HandleContent mResponseIsComplete"):
            try:
                r = Resources_search["ptr=" + params["ptr"]]
                r.complete = 1
            except:
                print "mResponseIsComplete could not find transaction", params["ptr"]
            
        if (params["f"]== "nsHttpTransaction::DispatchedAsBlocking"):
            try:
                r = Resources_search["ptr=" + params["trans"]]
                r.blocking = 1
            except:
                print "DispatchedAsBlocking could not find transaction", params["trans"]
    print "len(Resources)", len(Resources)
    #we use a second loop to determine referrers, because they could be before init
    Resources_ptr = 0
    for line_i in range(0, len(lines)):
        line = lines[line_i]
        if not("\t" in line and line[:2] == "f="):
            continue
        params = tbrparse(line)
        if (params["f"] == "nsHttpChannel::SetupTransaction"):
            r = Resources[Resources_ptr]
            try:
                assert(Resources[Resources_ptr].ptr == params["mTransaction"])
            except:
                continue
            Resources_ptr += 1
            if "type" in params.keys():
                if params["type"] == "WithoutTrigger":
                    #this cannot be used
                    continue
            try:
                r2 = Resources_search["GETURI=" + URI_format(params["triggeringURI"])]
            except:
                print "Error: did not find referrer for", line
                continue
            r.referrer = r2
        #a redirect is like a referrer for our purposes
        if (params["f"] == "nsHttpChannel::AsyncProcessRedirection"): #
            try:
                r = Resources_search["GETURI=" + URI_format(params["mRedirectURI"])]
                r2 = Resources_search["GETURI=" + URI_format(params["mURI"])]
            except:
                print "Error: did not find redirect for", line
                continue
            if r != r2:
                #there is a case of a page that redirects to itself; we don't want that to happen
                #this has the effect of "removing" this resource from the tree
                r.referrer = r2

    Resources_search = {} #search resource by ptr or URI
    Resources_ptr = 0
    #we use a third loop to determine referrerWritten, by re-examining Init
    #countWritten is not modified here, we use writtenSegmentSizes instead
    #the last segment is dropped as any byte in it may have caused this particular resource to load
    for line_i in range(0, len(lines)):
        line = lines[line_i]
        if not("\t" in line and line[:2] == "f="):
            continue
        
        params = tbrparse(line)
        
        if (params["f"] == "nsHttpTransaction::Init"):
            r = Resources[Resources_ptr]
            if r.referrer != None:
                r.referrerWritten = sum(r.referrer.writtenSegmentSizes[:-1]) #remove the last segment
            Resources_search["ptr=" + r.ptr] = r
            Resources_ptr += 1
        
        if params["f"] == "nsHttpTransaction::WritePipeSegment":
            r_ptr = "ptr=" + params["ptr"]
            if (r_ptr in Resources_search):
                r = Resources_search[r_ptr]
                r.writtenSegmentSizes.append(int(params["countWritten"]))
            else:
                print "Cannot find resource for", line
            #do a sanity check

    #we use levenshtein distance of sizes to connect records back to segments

    #determine which pells contain real data
    #a pell is said to contain real data if either:
    #1. it is bass'd to a encrypted record starting with 17
    #2. it is bass'd to an unencrypted record

    for pell in pells:
        for ind in pell.bassinds:
            if records[ind].is_data() == 1:
                pell.isdata = 1

    print "Using Levenshtein to connect records to segments..."

    circ_Streams_dict = {} #circ_Streams_dict links r.circ to Streams
    for s in Streams:
        circ_Streams_dict[s.id] = s

    circ_ptrs = []
    circ_sizes = []
    i = 0
    for r in records:
        if r.circ == 0 or r.circ == -1:
            continue
        if not (r.circ in circ_ptrs):
            circ_ptrs.append(r.circ)
            circ_sizes.append([0, 0])
        if r.di == -1:
            dind = 1
        else:
            dind = 0
        if r.is_enc == 0:
            ind = circ_ptrs.index(r.circ)
            circ_sizes[ind][dind] += len(r.data)/2
            circ_Streams_dict[r.circ].sizes[dind] += len(r.data)/2
        else:
            if int("0x" + r.data[:2], 16) == 23:
                ind = circ_ptrs.index(r.circ)
                #circ_sizes[ind][dind] += len(r.data)/2 - 10
                circ_sizes[ind][dind] += int("0x" + r.data[6:10], 16) - 24
                circ_Streams_dict[r.circ].sizes[dind] += int("0x" + r.data[6:10], 16) - 24
    #link connections with circuits
    #connections are derived from the browser side (writesegment, readsegment)
    #circs are derived from the tor side (streams)
    conn_circ = [None] * len(conn_ptrs)
    circ_sizes_temp = list(circ_sizes)
    for i in range(len(conn_sizes)):
        if not(conn_sizes[i] == [0, 0]) and conn_sizes[i] in circ_sizes_temp:
            j = circ_sizes_temp.index(conn_sizes[i])
            conn_circ[i] = j
            circ_sizes_temp[j] = [0, 0]
    #some are yet unconnected, just link them in order if they have any incoming
    j = 0
    for i in range(len(conn_sizes)):
        if not(conn_sizes[i][1] == 0) and conn_circ[i] == None:
            while circ_sizes_temp[j] == [0, 0]:
                j += 1
                if j >= len(circ_sizes_temp):
                    break
            if j >= len(circ_sizes_temp):
                break
            conn_circ[i] = j
            print "Connecting", conn_sizes[i], "->", circ_sizes_temp[j]
            circ_sizes_temp[j] = [0, 0]

    print "conn_circ linkage:", conn_circ

    circ_records = {}
    for i in range(len(records)):
        if not(records[i].circ in circ_records.keys()):
            circ_records[records[i].circ] = []
        if records[i].is_enc == 1 and int("0x" + records[i].data[:2], 16) == 23:
            circ_records[records[i].circ].append(i)
        if records[i].is_enc == 0:
            circ_records[records[i].circ].append(i)
##        conn_segments = {}
##        for i in range(len(segments)):
##            if not(segments[i].circ in conn_segments.keys()):
##                conn_segments[segments[i].circ] = []
##            conn_segments[segments[i].circ].append(i)
    conn_Resources = {}
    for i in range(len(Resources)):
        if Resources[i].fassinds == []:
            continue
        for ind in Resources[i].fassinds:
            mycirc = segments[ind].circ
            if segments[ind].di == -1:
                break
        if not(mycirc in conn_Resources.keys()):
            conn_Resources[mycirc] = []
        conn_Resources[mycirc].append(i)

    for connind in range(len(conn_ptrs)):
        if conn_circ[connind] == None:
            continue
        if not (connind in conn_Resources.keys()):
            continue
        myresources_inds = conn_Resources[connind]
        myrecords_inds = circ_records[circ_ptrs[conn_circ[connind]]]
        
        rlens = []
        slens = []
        rptr = 0
        excess = 0
        for ind in myresources_inds:
            res = Resources[ind]
##                print res.countWritten
##                print myrecords_inds
            hasWritten = excess
            while hasWritten < res.countWritten:
                rec = records[myrecords_inds[rptr]]
                if rec.di == -1 and rec.is_data():
                    for pell_ind in rec.fassinds:
                        if not (pell_ind in res.xell_inds):
                            res.xell_inds.append(pell_ind)
                    if rec.is_enc == 0:
                        hasWritten += len(rec.data)/2
                    else:
                        if int("0x" + rec.data[:2], 16) == 23:
                            hasWritten += int("0x" + rec.data[6:10], 16) - 24
                rptr += 1
                if (rptr >= len(myrecords_inds)):
                    break
            if (rptr >= len(myrecords_inds)):
                break
            excess = hasWritten - res.countWritten
##                print "---"
            
##            for ind in myrecords_inds:
##                if records[ind].is_enc == 1:
##                    rlens.append(len(records[ind].data) - 58)
##                else:
##                    rlens.append(len(records[ind].data))
##            for ind in mysegments_inds:
##                slens.append(len(segments[ind].data))
##            if (sum(rlens) != sum(slens)):
##                sys.exit(-1)
        ##            myResources = []
##            for r in Resources:
##                if r.connind == connind:
##                    myResources.append(r)
##            myResources = sorted(myResources, key = lambda k:k.endtime)
##            if conn_circ[connind] == None or myResources == []:
##                continue
##            mycirc = circ_ptrs[conn_circ[connind]]
####            print connind
####            for r in myResources:
####                print r.endtime
##            myResourcesptr = 0
##            for pell_i in circ_Resources[mycirc]:
##                pell = pells[pell_i]
##                if pell.time > myResources[myResourcesptr].endtime:
##                    myResourcesptr += 1
##                    if myResourcesptr >= len(myResources):
##                        break
####                print pell_i
##                myResources[myResourcesptr].xell_inds.append(pell_i)

    for di in [-1, 1]:
        rlens = []
        rinds = []
        for r_i in range(len(records)):
            r = records[r_i]
            if r.di == di and r.is_enc == 0:
                rlens.append(len(r))
                rinds.append(r_i)
            else:
                if r.di == di and r.is_ssl_data() == 1:
                    rlens.append(len(r) - 58)
                    rinds.append(r_i)
        slens = []
        sinds = []
        for r_i in range(len(segments)):
            r = segments[r_i]
            if r.di == di:
                slens.append(len(r))
                sinds.append(r_i)

        print "number of records {}, segments {}".format(len(rlens), len(slens))

##            ##rlens = [0, 1, 2]
##            ##slens = [0, 1, 2, 3]
##
##            #use levenshtein distance (no substitutions) to match
##            lev = range(0, len(slens)+1)  #lev[j] is distance between rlens[:i] and slens[:j], lev[0][j] is the previous
##            changes = []
##            #changes[j] is how rlen can become slen
##            #changes[j] is a list of [-1, i] (remove rlens[i] from rlens)
##            #or [1, i] (add slens[i] to rlens, when rlens has i elements)
##            for i in range(0, len(slens)+1):
##                change = []
##                for k in range(1, i+1):
##                    change.append([1, k-1])
##                changes.append(change)
##            #lev[0][j] is the last row
##            ##print changes
##            for i in range(1, len(rlens)+1):
##                print i, len(rlens) + 1
##                cur_lev = [0] * (len(slens) + 1)
##                cur_lev[0] = i
##                change = [[]] * i
##                for k in range(0, i):
##                    change[k] = [-1, k]
##                cur_changes = [[]] * (len(slens) + 1)
##                cur_changes[0] = change
##                
##                for j in range(1, len(slens)+1):
##                    if lev[j] + 1 > cur_lev[j-1] + 1:
##                        change = list(cur_changes[j-1])
##                        change.append([1, j-1])
##                        minlev = cur_lev[j-1] + 1
##                    else:
##                        change = list(changes[j])
##                        change.append([-1, i-1])
##                        minlev = lev[j] + 1
##                    if slens[j-1] == rlens[i-1] and lev[j-1] <= minlev:
##                        change = changes[j-1]
##                        minlev = lev[j-1]
##                    cur_changes[j] = change
##                    cur_lev[j] = minlev
##                lev = cur_lev
##                changes = cur_changes

        #sanity check that changes[-1] is correct
        #at the same time, link records and segments
        rlens_ptr = 0
        ch_ptr = 0
        change = lev(rlens, slens)
        change.append([1, len(slens)+2]) #for easier coding; won't be triggered
        rslens = [] #combine rlens and slens in the way described by changes
        #it should be equal to slens at the end
        slens_ptr = 0
        for rlens_ptr in range(len(rlens)):
            #check if we need to skip an slens
            while (change[ch_ptr][0] == 1 and change[ch_ptr][1] == len(rslens)):
                rslens.append(slens[len(rslens)])
                ch_ptr += 1
                slens_ptr += 1
            #check if we need to skip an rlens
            if change[ch_ptr][0] == -1 and change[ch_ptr][1] == rlens_ptr:
                rlens_ptr += 1
                ch_ptr += 1
            else:
                rslens.append(rlens[rlens_ptr])
                records[rinds[rlens_ptr]].bass.append(segments[sinds[slens_ptr]])
                records[rinds[rlens_ptr]].bassinds.append(sinds[slens_ptr])
                segments[sinds[slens_ptr]].fass.append(records[rinds[rlens_ptr]])
                segments[sinds[slens_ptr]].fassinds.append(rinds[rlens_ptr])
                if records[rinds[rlens_ptr]].is_enc == 1:
                    assert(len(records[rinds[rlens_ptr]]) == len(segments[sinds[slens_ptr]]) + 58)
                else:
                    assert(len(records[rinds[rlens_ptr]]) == len(segments[sinds[slens_ptr]]))
                rlens_ptr += 1
                slens_ptr += 1
        #at this point, all rlens has been added to rslens, but
        #there might still be slens left to skip
        for change_i in range(ch_ptr, len(change) - 1):
            rslens.append(slens[change[change_i][1]])

    assert(rslens == slens)

    inds = []
    for i in range(len(segments)):
        if segments[i].fass == []:
            inds.append(i)

    print "Using sum size to connect records to segments..."
    #one more way to connect records and segments:
    #records are parsed from cells
    #segments are told by tor browser
    #sometimes, a record contains several segments of the same circ
    #we try to see if several segments added together are immediately followed by a record sending them out
    #first, we build a segment circ dictionary
    segments_circ_dict = {}
    for s_i in range(len(segments)):
        s = segments[s_i]
        circname = str(s.circ) + "," + str(s.di)
        if not (circname in segments_circ_dict.keys()):
            segments_circ_dict[circname] = []
        segments_circ_dict[circname].append(s_i)

    #let's list the unmerged records
    unm_records = []
    for i in range(len(records)):
        record = records[i]
        if record.is_data() == 1 and record.bassinds == []:
            unm_records.append([record.time, len(record) * record.di, i])

    #we try to merge them stream by stream.
    #in the first round, we add up all unmerged segments of each stream
    #then we merge them if there is a reasonably close record to the final stream with the same size
    for circname in segments_circ_dict.keys():
        this_di = int(circname.split(",")[1])
        #list all the unmerged segments of this circname
        unm_segments = []
        sum_size = 0
        for ind in segments_circ_dict[circname]:
            if segments[ind].fassinds == []:
                unm_segments.append([segments[ind].time, len(segments[ind]) * this_di, ind])
                sum_size += len(segments[ind]) * this_di
        #we accept the segments should be merged iff:
        #1. the final unmerged segment is within 0.1s of the record
        #2. the sum sizes of all unmerged segments is the same as that of the record
        if unm_segments == []:
            continue
        for r_i in range(len(unm_records)):
            r = unm_records[r_i]
            if r[1] == 0:
                continue
            if abs(r[0] - unm_segments[-1][0]) < 0.1:
                correct = 0
                if r[1] == sum_size and records[r[2]].is_ssl_data() == 0:
                    correct = 1
                if r[1] == sum_size + (abs(r[1])/r[1]) * 58 and records[r[2]].is_ssl_data() == 1:
                    correct = 1
                if correct == 0:
                    continue
                #merging time
                print "segments", unm_segments, "merged to link with record", r[2]
                r_ptr = 0
                for unm_segment in unm_segments:
                    ind = unm_segment[2]
                    segments[ind].fass.append(records[r[2]])
                    segments[ind].fassinds.append(r[2])
                    segments[ind].fassranges.append([r_ptr, r_ptr + len(segments[ind])])
                    r_ptr += len(segments[ind])
                    records[r[2]].bassranges.append([0, len(segments[ind])])
                    records[r[2]].bassinds.append(ind)
                    records[r[2]].bass.append(segments[ind])
                unm_records.pop(r_i)
                break
    #in the second round, we accept segments if -a continuous part of them- add up to a record
    for circname in segments_circ_dict.keys():
        this_di = int(circname.split(",")[1])
        #list all the unmerged segments of this circname
        unm_segments = []
        for ind in segments_circ_dict[circname]:
            if segments[ind].fassinds == []:
                unm_segments.append([segments[ind].time, len(segments[ind]) * this_di, ind])
        #for each segment, try to find a matching record, then start counting backwards
        last_merged_ind = 0
        if unm_segments == []:
            continue 
        for unm_segment_i in range(len(unm_segments)):
            s = unm_segments[unm_segment_i]
            has_merged = 0
            merged_records = []
            for r_i in range(len(unm_records)):
                r = unm_records[r_i]
                if r[1] == 0 or r_i in merged_records:
                    continue
                if abs(s[0] - r[0]) < 0.1:
                    rev_ptr = unm_segment_i
                    sum_size = 0
                    while rev_ptr >= last_merged_ind:
                        sum_size += unm_segments[rev_ptr][1]
                        if (r[1] == sum_size and records[r[2]].is_ssl_data() == 0) or \
                           (r[1] == sum_size + (abs(r[1])/r[1]) * 58 and records[r[2]].is_ssl_data() == 1):
                            #let's merge
                            last_merged_ind = unm_segment_i
                            #everything from rev_ptr to unm_segment_i inclusive is merged
                            merged_inds = []
                            r_ptr = 0
                            for merge_ptr in range(rev_ptr, unm_segment_i + 1):
                                ind = unm_segments[merge_ptr][2]
                                merged_inds.append(ind)
                                segments[ind].fass.append(records[r[2]])
                                segments[ind].fassinds.append(r[2])
                                segments[ind].fassranges.append([r_ptr, r_ptr + len(segments[ind])])
                                r_ptr += len(segments[ind])
                                records[r[2]].bassranges.append([0, len(segments[ind])])
                                records[r[2]].bassinds.append(ind)
                                records[r[2]].bass.append(segments[ind])
                            merged_records.append(r_i)
                            print "segments", merged_inds, "merged to link with record", r[2]
                            r_ptr = 0
                            has_merged = 1
                            break
                        rev_ptr -= 1
                if (has_merged == 1):
                    break
            for r_i in merged_records[::-1]:
                unm_records.pop(r_i)
##            print "this_di", this_di
##            roundnum = 0
##            has_merged = 1
##            while (has_merged == 1):
##                has_merged = 0
##                possizes = []
##                for i in range(len(segments)):
##                    segment = segments[i]
##                    if segment.di == this_di and segment.fassinds == []:
##                        possizes.append([segment.time, len(segment), i])
##                for i in range(len(records)):
##                    record = records[i]
##                    if record.di == this_di and record.is_data() == 1 and record.bassinds == []:
##                        possizes.append([record.time, -len(record), i])
##                possizes = sorted(possizes)
##                print possizes
##                totalsizes = []
##                seginds = []
##                for i in range(0, len(possizes)):
##                    if possizes[i][1] > 0:
##                        totalsizes.append(possizes[i][1])
##                        seginds.append(possizes[i][2])
##                    if possizes[i][1] < 0:
##                        has_removed_totalsizes = None
##                        has_removed_seginds = None
##                        if roundnum > 0:
##                            #let's see if we can remove 1 thing from totalsizes and match
##                            has_found_match = None
##                            for totalsizes_i in range(len(totalsizes)):
##                                s = totalsizes[totalsizes_i]
##                                if sum(totalsizes) - s + 58 == -possizes[i][1]:
##                                    has_removed_totalsizes = s
##                                    has_removed_seginds = seginds[totalsizes_i]
##                                    totalsizes.pop(totalsizes_i)
##                                    seginds.pop(totalsizes_i)
##                                    break
##                        if sum(totalsizes) + 58 == -possizes[i][1]:
##                            #this is a successful merge
##                            has_merged = 1
##                            r_ptr = 0
##                            for segind in seginds:
##                                segments[segind].fass.append(records[possizes[i][2]])
##                                segments[segind].fassinds.append(possizes[i][2])
##                                segments[segind].fassranges.append([r_ptr, r_ptr + len(segments[segind])])
##                                r_ptr += len(segments[segind])
##                                records[possizes[i][2]].bassranges.append([0, len(segments[segind])])
##                                records[possizes[i][2]].bass.append(segments[segind])
##                            records[possizes[i][2]].bassinds = seginds
##                            print "segments", seginds, "merged to become record", possizes[i][2]
##                        #whether or not merge is successful, some things should be reset
##                        totalsizes = []
##                        seginds = []
##                        #if we removed something to make it successful, keep it for the future
##                        if has_removed_totalsizes != None:
##                            totalsizes.append(has_removed_totalsizes)
##                            seginds.append(has_removed_seginds)
##                roundnum += 1
##            possizes = []
##            for i in range(len(segments)):
##                segment = segments[i]
##                if segment.di == this_di and segment.fassinds == []:
##                    possizes.append([segment.time, len(segment), i])
##            for i in range(len(records)):
##                record = records[i]
##                if record.di == this_di and record.is_data() == 1 and record.bassinds == []:
##                    possizes.append([record.time, -len(record), i])
##            possizes = sorted(possizes)

    #let's see how much we've managed to connect
    count = 0
    countmid = 0
    for pell_i in range(len(pells)):
        if pells[pell_i].bass != []:
            count += 1
        if pells[pell_i].htype == 2:
            countmid += 1
    print "{}/{}/{} pells bass connected".format(count, countmid, len(pells))
    print "(all records fass connected because they are derived from pells.)"
    count = 0
    countmid = 0
    for i in range(len(records)):
        if records[i].bass != []:
            count += 1
        if int("0x" + records[i].data[:2], 16) == 23 or records[i].is_enc == 0:
            countmid += 1
##        if (int("0x" + records[i].data[:2], 16) == 23 or records[i].is_enc == 0) and records[i].bass == []:
##            print i
    print "{}/{}/{} records bass connected".format(count, countmid, len(records))
    count = 0
    countmid = 0
    for i in range(len(segments)):
        if segments[i].fass != []:
            count += 1
##        else:
##            print i
    print "{}/{} segments fass connected".format(count, len(segments))
        

    #now, we add non-dpell cells into resource fassinds.
    #for each resource, we determine its stream (all cells must be from the first stream, otherwise we do skip.)
    #then, we add all cells on that stream -before-
    pell_circ_dict = {}
    for pell_i in range(len(pells)):
        pell = pells[pell_i]
        if not (pell.circ in pell_circ_dict.keys()):
            pell_circ_dict[pell.circ] = []
        pell_circ_dict[pell.circ].append(pell_i)
    #we don't need to sort resources because it's already sorted correctly above
    has_added = [0] * len(pells)
    for r in Resources:
        r.fill_cell_inds() #fills r.cell_inds and r.cells
        if r.fassinds == []:
            continue
        if len(r.cell_inds) == 0:
            continue
        stream = pells[r.cell_inds[0]].circ
        samestream = 1
        for cell_ind in r.cell_inds:
            if pells[ind].circ != stream:
                samestream = 0
        lastcellind = r.cell_inds[-1]
        if samestream == 0:
            continue
        for ind in pell_circ_dict[pell.circ]:
            if has_added[ind] == 0 and ind <= lastcellind:
                has_added[ind] = 1
                if not (ind in r.cell_inds):
                    r.cell_inds.append(ind)
                    r.cell_inds = sorted(r.cell_inds)

    #before dill dump, we clear out all the data to reduce size
    for r_i in range(len(pells)):
        r = pells[r_i]
        r.data = ""
        r.num = r_i
    for r_i in range(len(records)):
        r = records[r_i]
        r.header = r.data[:20]
        r.data = ""
        r.num = r_i
    for r_i in range(len(segments)):
        r = segments[r_i]
        r.header = r.data[:20]
        r.data = ""
        r.num = r_i

    #do a sanity check on -all- connections.
    #after the sanity check, remove the object connections for dill.
    for r_i in range(len(Resources)):
        r = Resources[r_i]
        for s_i in range(len(r.fassinds)):
            if r.fass[s_i].num != r.fassinds[s_i]:
                raise Exception("{} {} {}".format("Resources fass",r_i, s_i))
        r.fass = []
    for r_i in range(len(segments)):
        r = segments[r_i]
        for s_i in range(len(r.fassinds)):
            if r.fass[s_i].num != r.fassinds[s_i]:
                raise Exception("{} {} {}".format("segments fass",r_i, s_i))
        for s_i in range(len(r.bassinds)):
            if r.bass[s_i].num != r.bassinds[s_i]:
                raise Exception("{} {} {}".format("segments bass",r_i, s_i))
        r.fass = []
        r.bass = []
    for r_i in range(len(records)):
        r = records[r_i]
        for s_i in range(len(r.fassinds)):
            if r.fass[s_i].num != r.fassinds[s_i]:
                raise Exception("{} {} {}".format("records fass",r_i, s_i))
        for s_i in range(len(r.bassinds)):
            if r.bass[s_i].num != r.bassinds[s_i]:
                raise Exception("{} {} {}".format("records bass",r_i, s_i))
        r.fass = []
        r.bass = []
    for r_i in range(len(pells)):
        r = pells[r_i]
        for s_i in range(len(r.bassinds)):
            if r.bass[s_i].num != r.bassinds[s_i]:
                raise Exception("{} {} {}".format("pells bass",r_i, s_i))
        r.bass = []
        r.fass = []
        
    for r_i in range(len(pells)):
        r = pells[r_i]

    fout = open(fold + fname + ".dill", "w")
    dill.dump([pells, records, segments, Resources, Connections, Sockets, Streams], fout)
    fout.close()
    sys.stdout.flush()

            #we create two files here in TSV format
    #first, a list of annotated cells (".acells")
    #second, a list of annotated resources (".ares")
    #any non-existing thing is written as a -1

    #for each cell, we print:
    #index, time, direction, which resource it belongs to (by index), which stream it belongs to,
    #the header number, the actual size
    #a cell can belong to multiple resources, so those are output as a list

    #for each resource we print:
    #index, URI, referrer index, circuit (ptr), 
    #total read, total written, total size (as declared by the resource itself, so inaccurate),

    #note that fortunately writepipesegment and readpipesegment show segments, so pipelining won't hurt total size


##        ##sys.exit(-1)
##        fout = open(fname + ".acells", "w")
##        for cell_i in range(len(cells)):
##            cell = cells[cell_i]
##            pell = cell.bass[0] #only one
##            resinds = []
##            pr_recs = pell.bass
##            for r in pr_recs:
##                pr_segs = r.bass
##                for s in pr_segs:
##                    pr_resinds = s.bassinds
##                    for ind in pr_resinds:
##                        resinds.append(ind)
##            pr = [cell_i, pell.time, pell.di, resinds, pell.circ, pell.htype, len(pell.data)]
##            prints = []
##            for pr_thing in pr:
##                prints.append(str(pr_thing))
##            fout.write("\t".join(prints) + "\n")
##        fout.close()
##
##
##        fout = open(fname + ".ares", "w")
##        for res_i in range(len(Resources)):
##            res = Resources[res_i]
##            if res.referrer == None:
##                refnum = -1
##            else:
##                refnum = res.referrer.num
##            pr = [res_i, res.URI, refnum, res.channel, res.countRead, res.countWritten, res.length]
##            prints = []
##            for pr_thing in pr:
##                prints.append(str(pr_thing))
##            fout.write("\t".join(prints) + "\n")
##        fout.close()
