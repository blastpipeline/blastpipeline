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
        #filled by procedure in dillwriter.py which checks lengths per connection
        self.xell_inds = []
        self.children = []


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
        

class Res(): #This is a Resource, but it is the class used by Sim.py and simdata
    def __init__(self):
        self.requestsize = None
        self.parentWritten = None
        self.hasWritten = 0 #used to make parentWritten too, final count is total size
        self.server = None
        self.parent = None
        self.children = []
        self.name = None
        self.index = None

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
        self.sizes = []
    def __str__(self):
        string = "Stream {} with pellinds {}".format(
            self.id, self.pellinds)
        return string
    def __repr__(self):
        return str(self)
        

class Server():
    def __init__(self):
        self.name = ""
        self.is_tls = None
        self.is_pipelining = None
        self.cert_length = None
        self.ent = None

    def __str__(self):
        s = "[Serv] {} ({}/{}/{})".format(self.name, self.is_tls, self.is_pipelining, self.cert_length)
        return s

    def __repr__(self):
        return str(self)

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
        

def typeparse(s): #lol
    if s == "None":
        return None
    try:
        x = int(s)
        return x
    except:
        try:
            x = float(s)
            return x
        except:
            return s

def parse(fname):
    f = open(fname, "r")
    lines = f.readlines()
    f.close()
    result = []
    sresults = []
    for line in lines:
        line = line.strip()
        if line == "---":
            result.append(sresults)
            sresults = []
        else:
            li = line.split("\t")
            sresults.append([typeparse(l) for l in li])
    if sresults != []:
        result.append(sresults)
    return result
