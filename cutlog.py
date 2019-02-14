#cuts size of torlog
#only used for first 100 sites


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
        self.len = length
        self.header = self.data[:22]
        self.data = self.data[22:22+length*2]
        
    def __repr__(self):
        st =  "tbrdata at time {}, di {}, type {}, data:\n".format(self.time, self.di, self.type)
        st += self.data
        return st


def cellstate_to_num(state):
    states = ["bstart", "bend", "astart", "aend"]
    if state in states:
        return states.index(state)
    else:
        print "Error: cellstate_to_num cannot find state", state
        return -1
    
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

fnames = []
fold = "data/treebatch-nopipeline/"
for site in range(0, 200):
    for inst in range(0, 2):
        for subinst in range(1, 6):
            fnames.append(fold + "{}-{}-{}".format(site, inst, subinst))

fnames = fnames[fnames.index(fold + "95-0-1"):]
##fnames = [fold + "0-0-0"]
for fname in fnames:
    print fname
    pells = []
    cells = []
    tor_infile = fname + ".torlog"
    f = open(tor_infile, "r")
    lines = f.readlines()
    f.close()

    state = "aend" #-> bend, astart, aend, bstart
    state_num = cellstate_to_num(state)
    t = -1
    reading = 0
    this_pcell = None
    this_lines = ""
    circpells = []
    for line in lines:
        if "\t" in line:
            #parse line
            pline = tbrparse(line)
            if pline["f"] == "circuit_package_relay_cell" or \
               pline["f"] == "relay_crypt":
                #determine state
                t = pline["t"]
                this_state = pline["type"]
                this_state_num = cellstate_to_num(this_state)
                if this_state_num != ((state_num + 1) % 4):
                    print "Error: {} follows {} at {}".format(this_state, state, lines.index(line))

                #determine direction
                if pline["f"] == "circuit_package_relay_cell":
                    this_di = 1 #encrypting cell for outgoing
                else:
                    this_di = -1

                #start a pcell
                if this_state == "bstart" or this_state == "astart":
                    reading = 1 #start reading data
                    if (this_state == "bstart" and pline["f"] == "circuit_package_relay_cell") or\
                       (this_state == "astart" and pline["f"] == "relay_crypt"):
                        this_pcell = tbrpell(time=t, di=this_di)
                    else:
                        this_pcell = tbrdata(time=t, di=this_di)

                #end a pell
                if (this_state == "bend" and pline["f"] == "circuit_package_relay_cell") or\
                   (this_state == "aend" and pline["f"] == "relay_crypt"):
                    this_pcell.parse_data(this_lines)
                    this_pcell.parse_cell()
                    this_pcell.type = "pell"
                    this_pcell.is_enc = 1 #pells are considered record-encrypted by default
                    pells.append(this_pcell)
                    this_lines = ""
                    this_pcell = None
                    reading = 0

                #end a cell
                if (this_state == "aend" and pline["f"] == "circuit_package_relay_cell") or\
                   (this_state == "bend" and pline["f"] == "relay_crypt"):
                    this_pcell.parse_data(this_lines)
                    this_pcell.type = "cell"
                    this_pcell.is_enc = 1
                    cells.append(this_pcell)
                    this_lines = ""
                    this_pcell = None
                    reading = 0

                state = this_state
                state_num = this_state_num
        else:
            if reading == 1:
                this_lines += line
        if "OUTGOING CIRC" in line or "INCOMING CIRC" in line:
            li = line.split(" ")
            t = float(li[0])
            if "OUTGOING CIRC" in line:
                this_di = 1
            if "INCOMING CIRC" in line:
                this_di = -1
            this_pcell = tbrpell(time=t, di=this_di)
            this_pcell.circ = int(li[5][:-1])
            this_pcell.len = int(li[9])
            this_pcell.htype = int(li[7][li[7].index("(") + 1:li[7].index(")")])
            circpells.append(this_pcell)
            
    #matching for pells and circs
    pells_ind = 0
    circpells_ind = 0
    while pells_ind < len(pells) and circpells_ind < len(circpells):
        cpell = circpells[circpells_ind]
        pell = pells[pells_ind]
        if cpell.len == pell.len and cpell.htype == pell.htype and cpell.di == pell.di and \
           abs(cpell.time - pell.time) < 0.02:
            pell.circ = cpell.circ
            pells_ind += 1
            circpells_ind += 1
        elif cpell.time < pell.time:
            print "Warning: cpell pell mismatch", circpells_ind, pells_ind
            circpells_ind += 1
        elif pell.time <= cpell.time:
            print "Warning: cpell pell mismatch", circpells_ind, pells_ind
            pells_ind += 1

    for pell in pells:
        if pell.circ == None:
            pell.circ = -1
##            if not(len(pells) == len(circs)):
##                
##            else:
##                for i in range(len(pells)):
##                    pells[i].circ = circs[i]

    tor_outfile = fname + ".trlg"
    f = open(tor_outfile, "w")
    for p in pells:
        f.write("{} {} {} {} {}\n".format(repr(p.time), p.di, p.circ, p.header, p.data))
    f.close()
