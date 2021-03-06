import random
import numpy

LOG_LEVEL = 0

ALLOW_SIMUL = 1 #Whether or not we allow simultaneous connection establishment.
#If we do, it checks the pipeline size to determine when to build new ones. 
#MIN_PIPELINE_DEPTH (see Sim-better.py) has been removed because TB-8.5 doesn't have that nonsense.
#If there is an active pipeline and fewer than this number of waiting trans,
#All trans must wait.
MAX_PIPELINE_LOWERBOUND = 1 #The lower bound of the maximum pipeline size.
MAX_PIPELINE_UPPERBOUND = 1 #The upper bound of the maximum pipeline size.
#Actual max pipeline depth is randomly determined.
MAX_CONNECTIONS = 6 #per server. The global limit is practically infinite.

PACKET_RATE = 164 #(kB/s)

HAS_HTTP2 = 1 #HTTP2 requires an ALPN negotiation
#we use 1 pipeline with infinite depth to simualte HTTP2
HAS_TFO = 0 #TCP Fast Open
HAS_OPTDATA = 0
HAS_ZEROTLS = 0
HAS_SHAVEREDIRECT = 0
HAS_FASTHTTP2 = 0

GLOBAL_COUNT = 0

class Conn():
    def __init__(self):
        #A connection can have these states:
        #0 = HalfOpen, just started
        #1 = Established but idle
        #2 = Active or Pipelining (check length of resources)
        self.state = 0
        #used to determine when idle should be closed:
        self.lastWritten_t = None #time when last thing was written
        self.ent = None #Which ent this belongs to
        self.tls_done = False #whether TLS negotiation is truly complete
        self.index = None #logging purposes
        self.trans = [] #list of Trans dispatched here
        self.pasttrans = [] #throw them here for record purposes
        self.hasWritten = [0, 0] #record purposes too
        self.cells = [] #for verification. populated by loader events (use addcell()). Don't append directly.
        self.cell_count = [0, 0] #for SENDMEs.

        self.freetime = 0 #only applies to non-http2
        self.readytime = None #When did this connection finish tls?

        self.http2_ready = False #set to True when ALPN is complete

    def addcell(self, cell):
        if (self.ent == None):
            raise Exception("Error: Sending cell on {} without associated ent".format(self.index))
##        ty = cell.cellty
##        self.celltys.append(ty)
##        self.ent.celltys.append(ty)
        self.cells.append(cell)
        self.ent.cells.append(cell)

    def __str__(self):
        s = "Conn {} carried".format(self.index, self.hasWritten[0], self.hasWritten[1])
        for tr in self.pasttrans:
            s += " " + repr(tr.res.index)
        if len(self.pasttrans) == 0:
            s += " nothing"
        s += ", is carrying"
        for tr in self.trans:
            s += " " + repr(tr.res.index)
        if len(self.trans) == 0:
            s += " nothing"
        s += " [cells: "
        cell_dict = {}
        for c in self.cells:
            cellty = c.cellty
            if not (cellty in cell_dict.keys()):
                cell_dict[cellty] = 0
            cell_dict[cellty] += 1
        sorted_keys = sorted(cell_dict.keys())
        for k in sorted_keys:
            s += "({})x{}, ".format(k, cell_dict[k])
        s = s[:-2]
        s += " ]"
        return s
    def __repr__(self):
        return str(self)

class Cell():
    def __init__(self, time, ty = None, di = None):
        self.cellty = None #cell type.
        self.recty = None #record type.
        self.recsubty = None #record subtype, only applicable to handshakes.
        self.di = di
        self.time = time
        if ty == "BEGIN":
            self.cellty = 1
            self.di = 1
        if ty == "CONNECTED":
            self.cellty = 4
            self.di = -1
        if ty == "DATA":
            self.cellty = 2
            self.recty = 0
        if ty == "ENCDATA":
            self.cellty = 2
            self.recty = 23
        if ty == "HANDSHAKE1":
            self.cellty = 2
            self.recty = 22
            self.recsubty = 1
            self.di = 1
        if ty == "HANDSHAKE2":
            self.cellty = 2
            self.recty = 22
            self.recsubty = 11
            self.di = -1
        if ty == "HANDSHAKE3":
            self.cellty = 2
            self.recty = 22
            self.recsubty = 16
            self.di = 1
        if ty == "HANDSHAKE4":
            self.cellty = 2
            self.recty = 22
            self.recsubty = 0
            self.di = -1
        if ty == "SENDME":
            self.cellty = 5            

    def get_cellty_str(self):
        if self.cellty == None:
            return ""
        cellstrs = ["UNKNOWN", "BEGIN", "DATA", "END", "CONNECTED", "SENDME"]
        if self.cellty < len(cellstrs):
            return cellstrs[self.cellty]
        else:
            return "UNKNOWN"

    def get_recty_str(self):
        if self.recty == None:
            return ""
        recstrs = ["UNKNOWN"] * 256
        recstrs[0] = "UNENCRYPTED"
        recstrs[20] = "CHANGE_CIPHER_SPEC"
        recstrs[21] = "ALERT"
        recstrs[22] = "HANDSHAKE"
        recstrs[23] = "DATA"
        return recstrs[self.recty]

    def get_recsubty_str(self):
        #Currently, we only implement one type of common handshake, which is:
        #Type 16: Subtype: 1, -2, -11, -12, -14, 16, 0, -0
        #in fact, -2, -12 and -14 are not simulated explicitly since they are tiny and don't often occupy cells
        #we add their expected sizes into -11 and merge the middle part into a bunch of -11 cells
        #so the actual handshake simulated would be 1, -11, 16, -0
        #note that the same applies to 1401 (CCS) and 1600 (handshake hello request)
        #they are also never simulated explicitly because they're always merged into the last subtype 16
        if self.recsubty == None:
            return ""
        recstrs = ["UNKNOWN"] * 256
        recstrs[0] = "HELLO_REQUEST"
        recstrs[1] = "CLIENT_HELLO"
        recstrs[2] = "SERVER_HELLO"
        recstrs[11] = "CERTIFICATE"
        recstrs[12] = "SERVER_KEY_EXCHANGE"
        recstrs[13] = "CERTIFICATE_REQUEST"
        recstrs[14] = "SERVER_HELLO_DONE"
        recstrs[15] = "CERTIFICATE_VERIFY"
        recstrs[16] = "CLIENT_KEY_EXCHANGE"
        recstrs[20] = "FINISHED"
        return recstrs[self.recsubty]

    def __str__(self):
        return "({}, {})".format(self.time, self.di * self.cellty)

    def __repr__(self):
        return str(self)
        
        
class Trans():
    def __init__(self, Res):
        #A Trans is a "realization" of a Resource, and thus corresponds to one
        self.res = Res
        self.res.tr = self
        #whichever Conn it is dispatched onto, if any...
        #Note that dispatching != ready. 
        self.conn = None
        #If it does not have a conn, it is waiting in an Ent's queue
        self.ent = None
        self.is_blocking = False #not set properly yet
        self.inc_cell_num = 0
        self.out_cell_num = 0
        
        self.is_init = 0 #To prevent initiating a child twice

        self.readytime = None
    def __str__(self):
        return "(T)" + str(self.res)
##        name = self.res.name
##        if len(self.res.name) > 80:
##            name = self.res.name[:77] + "..."
##        return name
    def __repr__(self):
        return str(self)
        

class Resource():
    def __init__(self):
        self.requestsize = None
        self.parentWritten = None
        self.hasWritten = 0 #used to make parentWritten too, final count is total size
        self.server = None
        self.parent = None
        self.tr = None #which transaction this corresponds to
        self.children = []
        self.name = None
        self.index = None

        self.createdtime = None
        self.dispatchedtime = None
        self.firstreadtime = None
        self.lastreadtime = None
        self.firstwritetime = None
        self.lastwritetime = None

    def get_sname(self):
        sname = self.name
        if len(sname) > 80:
            sname = sname[:77] + "..."
        return sname

    def __str__(self):
        s = "[{}] {} of size {}".format(self.index, self.get_sname(), self.hasWritten)
        if (self.parent != None):
            s += " (Parent: {})".format(self.parent.get_sname())
        return s

    def __repr__(self):
        return str(self)

class Ent():
    def __init__(self, server):
        #A Ent is a "realization" of a Server
        self.server = server #the CI; each CI has one ent
        server.ent = self
        if self.server.is_pipelined == True:
            self.pipesize = random.randint(MAX_PIPELINE_LOWERBOUND,
                                           MAX_PIPELINE_UPPERBOUND) #the pipe size is randomly determined per server at creation time
        else:
            self.pipesize = 1 #no pipelining!
        self.trans = [] #PendingQ
        self.conns = [] #Includes active, idle, half open
        self.cells = [] #list of cells sent.
        #this list is only populated when a conn's cells is populated
        #a conn's cells are populated directly by events
        
    def get_conns_by_state(self, state):
        toret = []
        for conn in self.conns:
            if conn.state == state:
                toret.append(conn)
        return toret

    def __repr__(self):
        s = "Ent for {}:\n".format(self.server.name)
        conns = self.get_conns_by_state(0)
        s += "Resources:\n"
        for c in self.conns:
            for t in c.pasttrans:
                s += str(t.res) + "\n"
        s += "Half-open conns:\n"
        for c in conns:
            s += "({}/{}) ".format(conns.index(c), len(conns)) + str(c) + "\n"
        conns = self.get_conns_by_state(1)
        s += "Idle conns:\n"
        for c in conns:
            s += "({}/{}) ".format(conns.index(c), len(conns)) + str(c) + "\n"
        conns = self.get_conns_by_state(2)
        s += "Active conns:\n"
        for c in conns:
            s += "({}/{}) ".format(conns.index(c), len(conns)) + str(c) + "\n"
        s += "Pending Q:\n"
        for q in self.trans:
            s += "({}/{}) ".format(self.trans.index(q), len(self.trans)) + str(q) + "\n"

        s += "Cells:\n"
        lastdit = ""
        lastcount = 0
        circ_pells_counts = {}
        for cell in self.cells:
            if cell.di == 1:
                dis = ""
            else:
                dis = "-"
            dit = "{}{} {} {}".format(dis, cell.cellty, cell.recty, cell.recsubty)
            if dit != lastdit:
                s += lastdit + " x " + str(lastcount) + "\n"
                lastcount = 0
            lastdit = dit
            lastcount += 1
            if not str(cell.cellty) in circ_pells_counts.keys():
                circ_pells_counts[str(cell.cellty)] = [0, 0]
            if cell.di == 1:
                circ_pells_counts[str(cell.cellty)][0] += 1
            else:
                circ_pells_counts[str(cell.cellty)][1] += 1

        s += "Total:\n"
        for key in sorted(circ_pells_counts.keys()):
            s += "{} x [{}, {}]\n".format(key, circ_pells_counts[key][0], circ_pells_counts[key][1])
        s = s[:-1]
##        cell_dict = {}
##        s += "Cells:\n"
##        if len(self.celltys) != 0:
##            lastty = self.celltys[0]
##            count = 0
##            for c in self.celltys:
##                if c == lastty:
##                    count += 1
##                else:
##                    s += "({})x{}\n".format(lastty, count)
##                    count = 1
##                lastty = c
##            s += "({})x{}\n".format(lastty, count)
##        for c in self.celltys:
##            if not (c in cell_dict.keys()):
##                cell_dict[c] = 0
##            cell_dict[c] += 1
##        sorted_keys = sorted(cell_dict.keys())
##        for k in sorted_keys:
##            s += "({})x{}, ".format(k, cell_dict[k])
##        s = s[:-2] + "\n"
        return s
        

class Server():
    def __init__(self):
        self.name = ""
        self.is_tls = None
        self.is_pipelining = None
        self.cert_length = None
        self.ent = None
        self.is_http2 = None

    def __str__(self):
        s = "[Serv] {} ({}/{}/{})".format(self.name, self.is_tls, self.is_pipelining, self.cert_length)
        return s

    def __repr__(self):
        return str(self)

def log(string, server, req_level=1):
    if LOG_SERVER != -1 and LOG_SERVER != server:
        return None
    if LOG_LEVEL >= req_level:
        print string
    else:
        return None

class Events():
    #contains a list of events with functions to queue and pop
    def __init__(self):
        self.ptr = 0
        self.events = []
            
    def insert_t(self, event):
        #insert the event at the right time
        events = self.events
        if len(events) == 0:
            events.append(event)
            return 1
        
        cur_step = len(events)/2
        last_ptr = 0
        cur_ptr = 0
        found_ptr = None #add it after found_ptr
        while True:
            if events[cur_ptr][0] > event[0]:
                cur_dir = -1
    ##        elif events[cur_ptr][0] == event[0]:
    ##            found_ptr = cur_ptr
    ##            break
            else:
                cur_dir = 1
            cur_step = max(cur_step/2, 1)
            next_ptr = cur_ptr + cur_step * cur_dir
            if next_ptr == last_ptr and cur_step == 1:
                if next_ptr > cur_ptr:
                    found_ptr = cur_ptr
                    break
                else:
                    found_ptr = cur_ptr - 1
                    break
            if next_ptr == len(events):
                found_ptr = len(events) - 1
                break
            #we won't add an event before time 0
            last_ptr = cur_ptr
            cur_ptr = next_ptr
        events.insert(found_ptr+1, event)

    def get_event(self):
        if self.ptr < len(self.events):
            event = self.events[self.ptr]
            self.ptr += 1
            return event
        else:
            return None

class Loader():
    #contains all objects necessary to simulate a page load
    def __init__(self, rlist, slist):
        self.rlist = rlist #a list of resources (actually a tree)
        self.slist = slist #a list of servers and their properties
        #we send this server property to Ent to build it
        self.trans = [] #each trans is one resource but loader only deals with trans
        self.ents = [] #ent to server is trans to resource
        for s in slist:
            self.ents.append(Ent(s))
        for r in rlist:
            tr = Trans(r)
            tr.ent = self.ents[slist.index(r.server)]
            #don't assign ent.trans here! that is a pending q
            self.trans.append(tr)
        self.conns = []
        self.events = Events()
        self.cur_t = 0
        self.blockers = []

        self.GLOBAL_COUNT = 0

        self.cell_count = [0, 0]
        #number of data cells sent in each direction. Used for per-circuit SENDMEs.
        #Perhaps it should be random because those counts are kept from previous web pages.
        #0 would be a (very slight) underestimation, though it is cleaner.
        
        self.cells = [] #list of cells. Should only be called by addcell with appropriate conn.

    def addcell(self, conn, cell):
        #this is where we do SENDMEs
        #Note that cells may be misordered
        self.cells.append(cell)
        conn.addcell(cell)
        if cell.cellty == 2:
            curtime = cell.time
            if cell.di == 1:
                di_ind = 0
            else:
                di_ind = 1
            conn.cell_count[di_ind] += 1
            self.cell_count[di_ind] += 1
            if di_ind == 0: #outgoing
                #circuit SENDMEs
                if self.cell_count[di_ind] >= 100:
                    self.cell_count[di_ind] -= 100
                    sendme = Cell(curtime + get_rtt(), ty="SENDME", di=-1)
                    self.cells.append(sendme)
                    #note that we don't add this to any connection
                #stream SENDMEs
                if conn.cell_count[di_ind] >= 50:
                    conn.cell_count[di_ind] -= 50
                    sendme = Cell(curtime + get_rtt(), ty="SENDME", di=-1)
                    self.cells.append(sendme)
                    conn.addcell(sendme)
            if di_ind == 1: #incoming
                #circuit SENDMEs
                if self.cell_count[di_ind] >= 100:
                    self.cell_count[di_ind] -= 100
                    sendme = Cell(curtime, ty="SENDME", di=1)
                    self.cells.append(sendme)
                    #note that we don't add this to any connection
                #stream SENDMEs
                if conn.cell_count[di_ind] >= 50:
                    conn.cell_count[di_ind] -= 50
                    sendme = Cell(curtime, ty="SENDME", di=1)
                    self.cells.append(sendme)
                    conn.addcell(sendme)

    def processEvent(self):
        #the core of resource loading
        #loader.events[i] is being processed here
        #event is a [time, string, index], and string can be (brackets are explanations):
        #Init Trans (we want to start loading this resource; index is trans)
        #(Init Conn is never called because TryDispatchTransaction handles the whole connection establishment)
        #ALPN Done (this server supports HTTP/2; index is ent). can happen many times. 
        #Conn Done (connection has been established, index is conn)
        #Trans Ready (send out the trans request; index is trans)
            #this is where all the data cells are built
            #Actual DispatchTrans is done in TryDispatchTrans
        #Trans Done (index is trans)
            #this finishes the transaction and calls WalkCT again

        event = self.events.get_event()
        if event == None:
            return -1
        [self.cur_t, ename, eind] = event

        if ename == "Init Trans":
            #here we create a new 
            tr = self.trans[eind]
            tr.res.createdtime = self.cur_t
            tr.readytime = self.cur_t
            if tr.ent == None:
                print tr, eind
            tr.ent.trans.append(tr)
            tr.is_init = 1 #this should only really matter for the parent resource
            
            log("{:05.2f}\t---[E]\tTrans {} init".format(self.cur_t, eind),
                self.ents.index(tr.ent))
            self.WalkCT(tr.ent)
            
        if ename == "Conn Done":
            log("{:05.2f}\t---[E]\tConn {} done".format(self.cur_t, eind),
                self.ents.index(self.conns[eind].ent))
            #add the incoming cell for connection done
            cell = Cell(self.cur_t, "CONNECTED")
            conn = self.conns[eind]
            ent = conn.ent
            timer = self.cur_t
            self.addcell(conn, cell)
            
            want_handshake4 = 0
            if ent.server.is_tls == True:
                cell = Cell(timer, "HANDSHAKE1")
                self.addcell(conn, cell)
                if ent.server.cert_length != None:
                    inc_cell_num = roundup(ent.server.cert_length + 200, 498) #200 is about 02+0c
                else:
                    inc_cell_num = 1
                for c in range(inc_cell_num):
                    cell = Cell(timer, "HANDSHAKE2")
                    self.addcell(conn, cell)
                cell = Cell(timer, "HANDSHAKE3")
                self.addcell(conn, cell)

                #incoming handshake response
                if HAS_ZEROTLS == 0:
                    timer = timer + get_rtt()
                cell = Cell(timer, "HANDSHAKE4")
                self.addcell(conn, cell)

                self.events.insert_t([timer, "TLS Done", eind])
            else:
                self.events.insert_t([timer, "TLS Done", eind]) #fake TLS Done

        if ename == "TLS Done":
            log("{:05.2f}\t---[E]\tTLS {} done".format(self.cur_t, eind),
                self.ents.index(self.conns[eind].ent))
            c = self.conns[eind]
            c.state = 1
            c.readytime = self.cur_t

            if HAS_HTTP2 == 1:
                if c.ent.conns.index(c) == 0:
                    #this is the first conn, so we should negotioate ALPN if this server is http
                    #no cell activity for this because we're not sure how big it is
                    if c.ent.server.is_http2:
                        if HAS_FASTHTTP2 == 0:
                            self.events.insert_t([self.cur_t + get_rtt(), "ALPN Done", self.ents.index(c.ent)])
                        if HAS_FASTHTTP2 == 1:
                            #we move ALPN Done here:
                            firstc = c.ent.conns[0]
                            firstc.http2_ready = True
            #For better pipelining, CT is walked when TLS is done, not when conns are done
            self.WalkCT(c.ent)
            
        if ename == "Trans Ready":
            log("{:05.2f}\t---[E]\tTrans {} ready".format(self.cur_t, eind),
                self.ents.index(self.trans[eind].ent))
            #this is the event that handles connection establishment, tls negotiation, and data transfer on the wire
            #before this, the trans must already have a connection
            #it must lead to trans done

            #this has a slight flaw, which is that we send cells for transactions separately
            #in reality, the wire can send cells for multiple transactions together
            #this may cause an extra cell or two
            tr = self.trans[eind]
            conn = tr.conn
            ent = tr.ent
            timer = self.cur_t
            if HAS_ZEROTLS == 0 and timer - get_rtt() < conn.readytime and conn.ent.server.is_tls == True:
                #let's make dispatched time possibly one round trip earlier
                #the above condition can only be true if this is the first resource sent by this conn
                tr.res.dispatchedtime = max(timer - get_rtt(), tr.readytime)
            else:
                tr.res.dispatchedtime = timer

            #if tls, get an extra round trip time, and certs...

            #we don't simulate certs yet because i'm not sure if OCSP really demands a second round-trip time all the time
            #so it's just one RTT for client/server hello

            #TLS handshake
            #We do the TLS handshake in Conn Done now. 

            #outgoing HTTP request
            out_len = tr.res.requestsize
            for c in range(roundup(out_len, 498)):
                if ent.server.is_tls == True:
                    cell = Cell(timer, "ENCDATA", 1)
                    self.addcell(conn, cell)
                else:
                    cell = Cell(timer, "DATA", 1)
                    self.addcell(conn, cell)
            tr.res.firstreadtime = timer
            tr.res.lastreadtime = timer

            timer += get_rtt()
            #incoming HTTP data
            #the "real" time this can begin is when the connection becomes free
            if conn.http2_ready == False:
                timer = max(timer, conn.freetime)
            log("\t\t[Ready] Timer set to {}".format(timer), self.ents.index(ent))
            tr.res.firstwritetime = timer
            stream_cell_count = 0
            
            #For encrypted data, this is first divided into a number of records.
            #Taking each record's length as the stated length in the header,
            #Each record is usually length 1425, out of which 1401 is actually resource data
            #And each cell's length as 498, the true length of the data.
            #There is also an overhead of 5 on each record when sent into cells (so effectively their lengths are 1430 from the cell perspective)
            #A multiple of records are grouped into cells. It appears to be related to timing.

            #First, divide resource into records
            reslen = tr.res.hasWritten
            total_used_reslen = 0
            recs = []
            res_useds = []
            while total_used_reslen < reslen:
                recnum = get_recnum(conn.ent)
                this_used_reslen = recnum * 1401
                this_reclen = recnum * 1430
                if total_used_reslen + this_used_reslen > reslen:
                    this_used_reslen = reslen - total_used_reslen
                    recnum = this_used_reslen/1401
                    remain = this_used_reslen % 1401
                    this_reclen = recnum * 1430 + remain
                    if remain > 0:
                        this_reclen += 29
                total_used_reslen += this_used_reslen
                recs.append(this_reclen)
                res_useds.append(this_used_reslen)
            data_written = 0
            for rec_i in range(0, len(recs)):
                rec = recs[rec_i]
                
                #send each rec as cells
                inc_cell_num = roundup(rec, 498)
                tr.inc_cell_num += inc_cell_num
                for c in range(0, inc_cell_num):
                    if ent.server.is_tls == True:
                        cell = Cell(timer, "ENCDATA", -1)
                        self.addcell(conn, cell)
                    else:
                        cell = Cell(timer, "DATA", -1)
                        self.addcell(conn, cell)
                    timer += get_itt()
                data_written += res_useds[rec_i]
                #checking which children should be sent
                for childres in tr.res.children:
                    if childres.parentWritten <= data_written and childres.tr.is_init == 0:
                        self.events.insert_t([timer+0.001, "Init Trans", self.rlist.index(childres)])
                        #0.001 ensures init trans happens after conn done, if this is the last packet
                        #this is true in reality
                        childres.tr.is_init = 1
                log("\t\t[Ready] {} data written (conn {} trans {}) {} {}".format(timer,
                                                                      self.conns.index(conn), self.trans.index(tr),
                                                                      data_written, rec),
                    self.ents.index(ent))
            conn.freetime = timer
            self.events.insert_t([timer, "Trans Done", self.rlist.index(tr.res)])
            tr.res.lastwritetime = timer

        if ename == "Trans Done":
            log("{:05.2f}\t---[E]\tTrans {} done".format(self.cur_t, eind),
                self.ents.index(self.trans[eind].ent))
            tr = self.trans[eind]
            if tr in self.blockers:
                self.blockers.remove(tr)
            tr.conn.pasttrans.append(tr)
            tr.conn.trans.remove(tr)
            if len(tr.conn.trans) == 0:
                tr.conn.state = 1
            tr.conn = None
            tr.ent = None
            
            self.WalkCT(None)

        if ename == "ALPN Done":
            if len(self.ents[eind].conns) == 0:
                raise Exception(str(self.ents) + " has no conns when ALPN is done")
            c = self.ents[eind].conns[0]
            c.http2_ready = True
            log("---[E]\tALPN {} done, set Conn {} to infinite".format(eind, self.conns.index(c)),
                eind)
            
        #RemoveDispatchedAsBlocking also calls CT
        #However, since we don't simulate bugs, a transaction being removed happens only if it's finished
        #that would call data done anyway, so... 
                                      
    
    def TryDispatchTrans(self, tr):
        #try to dispatch a given Trans, tr, on its attached ent
        #dispatching doesn't do anything to the wire, and is not an event
        #it only attached the Trans to a Conn. This causes the "Trans Ready" event
        #For pipelining, this can cause multiple trans to be dispatched
        #We may make new connections right here; this is not an event or it'll be "too late"
        #This can cause the "Conn Done" event
        #returns -1 if dispatch was not successful, 1 if it was
        #Affects the event list if a new conn needs to be made.
        if tr.conn != None:
            #this means it got pipelined
            return 1
        if tr.ent == None:
            raise Exception(str(tr) + " has no ent")
        if not(tr in tr.ent.trans):
            raise Exception(str(tr) + " not in ent pending queue")

        log("\t[TDT]\tTrans {}, {}/{}/{} connections, queue {}".format(self.trans.index(tr),
                                                                    len(tr.ent.get_conns_by_state(0)),
                                                                    len(tr.ent.get_conns_by_state(1)),
                                                                    len(tr.ent.get_conns_by_state(2)),
                                                                    len(tr.ent.trans)),
            self.slist.index(tr.ent.server))

        #let's check if there are any blocking transactions
        if self.blockers != []:
            if tr.is_blocking != 1:
                return -1 

        #We don't remove transactions from the pending q (tr.ent.trans) here
        #We will do that in WalkCT
        #Two possibilities of dispatching transactions
        #Sim-better uses a reversed order, but browser uses this one

        #(0) If any, HTTP/2 should go first, and it should ignore any pipesize limit.

        for c in tr.ent.conns:
            if c.http2_ready:
                log("[TDT] Conn {} (http2) dispatches trans {}".format(self.conns.index(c),
                                                                       self.trans.index(tr)),
                    self.ents.index(tr.ent))
                c.trans.append(tr)
                tr.conn = c
                if tr.is_blocking == 1:
                    self.blockers.append(tr)
                self.events.insert_t([self.cur_t, "Trans Ready", self.trans.index(tr)])

                return 1
                
        
        #(1) If there are any non-full pipelines, get the shortest such pipeline, then send this transaction
        #Except for disqualified pipelines. A pipeline is disqualified if it's expected to take too long to finish.
        #The expectation is: pipeline size * cur trans size > parameter (around 4 seconds of data)
        #If all pipelines are disquailfied, we hard wait for a new connection.
        conns = tr.ent.get_conns_by_state(2)
        if len(conns) != 0:
            s_conn = conns[numpy.argmin([len(c.trans) for c in conns])] #the shortest conn
            if len(s_conn.trans) < tr.ent.pipesize:
                log("[TDT] Conn {} (pipelined with {}/{}) dispatches trans {}".format(self.conns.index(s_conn),
                                                                             len(s_conn.trans),
                                                                                      tr.ent.pipesize,
                                                                             self.trans.index(tr)),
                    self.ents.index(tr.ent))
                s_conn.trans.append(tr)
                tr.conn = s_conn
                if tr.is_blocking == 1:
                    self.blockers.append(tr)
                self.events.insert_t([self.cur_t, "Trans Ready", self.trans.index(tr)])

                return 1
        
        #(2) If there are any idles, choose one
        conns = tr.ent.get_conns_by_state(1)
        if conns != []:
            conn = conns[0]
            log("\t[TDT]\tIdle conn {} dispatches trans {}".format(self.conns.index(conns[0]),
                                                                   self.trans.index(tr)),
                self.ents.index(tr.ent))
            
            #Dispatch this transaction
            conn.trans.append(tr)
            tr.conn = conn
            if tr.is_blocking == 1:
                self.blockers.append(tr)
            self.events.insert_t([self.cur_t, "Trans Ready", self.trans.index(tr)])

            #Dispatch other transactions too
            #For better sim, we never do this. Transactions instead ask to get sent onto pipelines when walked.
##            for i in range(len(tr.ent.trans)):
##                otr = tr.ent.trans[i]
##                if otr != tr and otr.conn == None:
##                    #let's dispatch it too
##                    conn.trans.append(otr)
##                    otr.conn = conn
##                    if tr.is_blocking == 1:
##                        self.blockers.append(otr)
##                    self.events.insert_t([self.cur_t, "Trans Ready", self.trans.index(otr)])
##                    log("Conn {} pipelines trans {}".format(self.conns.index(conns[0]), self.trans.index(otr)))
##                if len(conn.trans) >= tr.ent.pipesize:
##                    break

            if len(conn.trans) >= 1:
                conn.state = 2

            return 1

        #finally, we can make a connection
        #actually, it would make sense to ensure this is called right after
        #any successful dispatch. however, from reading the original code,
        #it appears that this does not happen.
        #the new connection could be too "late".

        #we don't open more than six connections
        if len(tr.ent.conns) >= MAX_CONNECTIONS:
            return -1

        #we don't half-open more connections than the queue size
        if len(tr.ent.get_conns_by_state(0)) >= len(tr.ent.trans):
            return -1

        #TB-8.5 allows simultaneous connections, so no more checks are needed

        #if we get here, we can make a new connection
        log("\t[TDT]\tCreating Conn {} for Trans {}".format(len(self.conns),
                                                         self.trans.index(tr)),
            self.ents.index(tr.ent))

        conn = Conn()
        conn.ent = tr.ent
        conn.ent.conns.append(conn)
        self.conns.append(conn)
        cind = len(self.conns) - 1
        conn.index = cind

        timer = self.cur_t

        conncount = len(tr.ent.get_conns_by_state(1)) + len(tr.ent.get_conns_by_state(2)) 

        if HAS_TFO == 1 and conncount > 0:
            timer += 0.001 #effectively no round-trip for connection establishment if we already have one
            #non zero timer push to make sure the event is later
        else:
            if HAS_OPTDATA == 1:
                timer += 0.1 #round-trip between exit node to server
            else:
                timer += get_rtt()
            
        cell = Cell(self.cur_t, "BEGIN")
        self.addcell(conn, cell)
        self.events.insert_t([timer, "Conn Done", len(self.conns)-1])
        return -1
    
    def WalkCT(self, ent):
        #Walks CT (Conn Table) to attempt to dispatch any Trans
        #starts with a given ent, but keeps dispatching until one succeeds (?)
        #if ent = None, then try dispatching everything

##        if ent == None:
##            print "CT walk called. Listing all ents:"
##        if ent != None:
##            print "CT walk called for {}. Listing all ents:".format(ent.server.name)
##        for ent in self.ents:
##            print " Ent {}:".format(ent.server.name)
        
        if ent == None:
            for ent in self.ents:
                for tr_i in range(0, len(ent.trans)):
                    ret = self.TryDispatchTrans(ent.trans[tr_i])
                    if (ret == -1):
                        break #this ent is hopeless. break (speed optimization)
                        #doesn't work on normal browser because of classes
        else:
            got_dispatch = 0
            for tr in ent.trans:
                if (self.TryDispatchTrans(tr) == -1):
                    break
                else:
                    got_dispatch = 1
            if got_dispatch == 0:
                for ment in self.ents:
                    for tr in ment.trans:
                        if (self.TryDispatchTrans(tr) == -1):
                            break
                        else:
                            got_dispatch = 1
                    if got_dispatch == 1:
                        break
        #now, let's refresh the queue if anything changed
        for ent in self.ents:
            tempq = []
            for tr in ent.trans:
                if tr.conn == None:
                    tempq.append(tr)
            ent.trans = tempq

    def printout(self):
        for ent in self.ents:
            print repr(ent)

def get_recnum(serv):
    #gets the number of records that were sent at the same time
    return random.randint(1, 10)

def get_rtt():
    #gets a random rtt
    return 0.8 #random.uniform(0.4, 0.7)
    
def get_itt():
    #gets a random rtt
    return 498.0/(PACKET_RATE*1000) #random.uniform(0.01, 0.02)
    
def roundup(num, denom):
    if num == 0:
        return 0
    if num % denom == 0:
        return num/denom
    else:
        return num/denom + 1

def DispatchTransaction(Trans, Conn):
    #dispatch a Trans onto a Conn
    #returns a list of Events which corresponds to data sent and received  
    Trans.Conn = Conn
    Conn.Trans.append(Trans)
    Conn.state = 2
    
    listTrans = [Trans]
    
    #call for pipelining here
    
    totalData = 0
    for Trans in listTrans:
        totalData += Trans.Resource.countWritten
    
    Events = []
    #create events based on data loading here 
    return Events

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

def load_rslist(fname):
    f = open(fname, "r")
    lines = f.readlines()
    f.close()
    readingres = 1
    rlines = []
    slines = []
    for line in lines:
        if len(line) == 0:
            continue
        if line == "\n" or line[0] == "#":
            continue
        if line == "---\n":
            readingres = 0
            continue
        if readingres == 1:
            rlines.append(line)
        else:
            slines.append(line)
    rlist = []
    slist = []
    for line in rlines:
        rlist.append(Resource())
    for line in slines:
        slist.append(Server())
    for ind in range(len(rlines)):
        li = rlines[ind].strip().split("\t")
        r = rlist[ind]
        r.index = ind
        if li[4] == "None": #no server found
            continue #this resource shouldn't be loaded
        [r.name, r.requestsize, r.hasWritten, r.server] = \
                 [li[0], int(li[1]), int(li[2]), slist[int(li[4])]]
        if li[5] == "None" or li[5] == "-1":
            r.parent = None
            r.parentWritten = None
        else:
            r.parent = rlist[int(li[5])]
            if li[3] == "None":
                r.parentwritten = rlist[ind].hasWritten
            else:
                r.parentWritten = int(li[3])
    #filter out rlist without server
    new_rlist = []
    for r in rlist:
        if r.server != None:
            new_rlist.append(r)
    rlist = new_rlist
            
    for ind in range(len(slines)):
        li = slines[ind].strip().split("\t")
        s = slist[ind]
        s.name = li[0]
        if li[1] == "1":
            s.is_tls = True
        else:
            s.is_tls = False
        if li[2] == "1":
            s.is_http2 = True
        else:
            s.is_http2 = False
            
        if s.name in pipeservers:
            s.is_pipelined = True
        else:
            s.is_pipelined = False

    #set up children
    for r in rlist:
        if r.parent != None:
            r.parent.children.append(r)
    return [rlist, slist]

def conn_popwritten(conns, cells):
    for conn in conns:
        conn.hasWritten = [0, 0]
    for cell in cells:
        ind = cell[2]
        if cell[1] < 0:
            di = 1
        else:
            di = 0
        conns[ind].hasWritten[di] += 1
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


fnames = []
for j in range(10):
    for i in range(50):
        fnames.append("{}-{}-comp0".format(j, i))
for j in range(200):
    for i in range(5):
        fnames.append("{}-{}-comp0".format(j, i))
for i in range(1000):
    fnames.append("{}-comp0".format(i))

import dill
results = []
fold = "simdata/"
LOG_SERVER = -1
##options = [["-http2.simres", 1, 1, 1],
##           ["-pipe.simres", 0, 6, 6]]

f = open("pipelined-servers.txt")
pipeservers = []
for line in f.readlines():
    pipeservers.append(line.strip())
f.close()

HAS_HTTP2 = 1 #HTTP2 requires an ALPN negotiation

f = open("prefetch-res.dill")
prefetch_dict = dill.load(f)
f.close()

TOTAL_PREFETCH_COUNT = 0
TOTAL_FAILFETCH_COUNT = 0

#this lets you load settings for various setups; can simplify away
f = open("Sim-settings.txt", "r")
lines = f.readlines()
f.close()
for line in lines:
    if len(line) == 0:
        continue
    if line[0] == "%":
        continue
    li = line.split("\t")
    outext = li[0]
    [HAS_HTTP2, HAS_TFO, HAS_OPTDATA, HAS_ZEROTLS, HAS_SHAVEREDIRECT, HAS_FASTHTTP2, HAS_PREFETCHING] = \
              [int(l) for l in li[1:8]]
    print [HAS_TFO, HAS_OPTDATA, HAS_ZEROTLS, HAS_SHAVEREDIRECT, HAS_FASTHTTP2, HAS_PREFETCHING]

    if HAS_SHAVEREDIRECT == 1:
        f = open("redirects-skip.txt", "r")
        lines = f.readlines()
        f.close()
        shave_dict = {}
        for line in lines:
            li = line.strip().split("\t")
            shave_dict[li[0]] = int(li[1])

    #packet rate

    if HAS_HTTP2 == 1:
        PACKET_RATE = 164
        MAX_PIPELINE_LOWERBOUND = 1
        MAX_PIPELINE_UPPERBOUND = 1
    else: #pipelining
        PACKET_RATE = 347
        MAX_PIPELINE_LOWERBOUND = 6
        MAX_PIPELINE_UPPERBOUND = 6
    
    for fname in fnames:
        print fname
        site = int(fname.split("-")[0])
        try:
            [rlist, slist] = load_rslist(fold + fname + ".simdata")
        except Exception as e:
            print "Loading rslist error:", e
            continue
        if HAS_SHAVEREDIRECT == 1:
            if fname in shave_dict.keys():
                shave_ind = shave_dict[fname]
                rlist = rlist[shave_ind:]
                for r in rlist:
                    r.index = rlist.index(r)
                rlist[0].parent = None

        if HAS_PREFETCHING == 1:
            if site in prefetch_dict.keys():
                prefetch_count = 0
                prefetch_hits = [0] * len(prefetch_dict[site])
                for r in rlist:
                    if r.name in prefetch_dict[site]:
                        r.parent = None
                        prefetch_count += 1
                        ind = prefetch_dict[site].index(r.name)
                        prefetch_hits[ind] = 1
                failfetch_count = prefetch_hits.count(0)
                TOTAL_PREFETCH_COUNT += prefetch_count
                TOTAL_FAILFETCH_COUNT += len(rlist)

        loader = Loader(rlist, slist)
        for rind in range(len(rlist)):
            r = rlist[rind]
            if r.parent == None:
                loader.events.events.append([0, "Init Trans", rind])
        while (loader.processEvent() != -1):
            continue

        #this lets you print out the simulated data

##        fout = open(fold + fname + "-" + outext + ".simres", "w")
##        for r in rlist:
##            toprint = [rlist.index(r), slist.index(r.server), r.createdtime, r.dispatchedtime, r.firstreadtime, r.firstwritetime, r.lastwritetime,
##                       r.hasWritten]
##            if r.parent != None and r.parent in rlist: #r.parent may not be in rlist if we're doing redirection skipping
##                toprint.append(rlist.index(r.parent))
##            else:
##                toprint.append(-1)
##            fout.write("\t".join([str(s) for s in toprint]) + "\n")
##        fout.close()

        if LOG_LEVEL >= 1:
            for r in loader.rlist:
                if r.parent != None:
                    print loader.rlist.index(r), loader.rlist.index(r.parent), loader.slist.index(r.server), r.hasWritten, r.createdtime,
                    print r.dispatchedtime, r.firstreadtime, r.lastwritetime
                else:
                    print loader.rlist.index(r), "None", loader.slist.index(r.server), r.hasWritten, r.createdtime,
                    print r.dispatchedtime, r.firstreadtime, r.lastwritetime


