import struct
import binascii
from scapy.all import *
from scapy.fields import *
import BER

#########################
# Resources:
#   http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.684.9918&rep=rep1&type=pdf
#   http://www.ucaiug.org/Meetings/Austin2011/Shared%20Documents/IEC_61850-Tutorial.pdf
#   https://www.fit.vut.cz/research/publication-file/11832/TR-61850.pdf
#   https://cdn.selinc.com/assets/Literature/Publications/Technical%20Papers/6921_IEC61850Network_MS_20190712_Web.pdf?v=20190821-201111
#########################

class ASNType(object):
    tag = ''
    def __init__(self, data='', length=0):
        pass

    def unpack(self, data):
        raise NotImplemented()

    def pack(self, data):
        raise NotImplemented()

    def __str__(self):
        return str(self.data)

    def __repr__(self):
        return str(self.data)

class Integer(ASNType):
    def __init__(self, data='', length=0):
        self.data = BER.unpack_varint(data, length)

    def pack(self):
        if isinstance(self.data, int):
            if self.data <= 255:
                return struct.pack('!B', self.data)
            elif self.data <= 65535:
                return struct.pack('!h', self.data)
            else:
                return struct.pack('!i', self.data)
        if isinstance(self.data, long):
            return struct.pack('!l', self.data)

class VisibleString(ASNType):
    def __init__(self, data='', length=0):
        self.data = data

    def __repr__(self):
        #return "'" + self.data.encode() + "'"
        return "'" + self.data.decode() + "'"

    def pack(self):
        return self.data

class Boolean(ASNType):
    ID = 3
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!b', data)[0]

    def __repr__(self):
        if self.data:
            return "True"
        else:
            return "False"

    def pack(self):
        return struct.pack('!b', self.data)

class UTCTime(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

    def pack(self):
        return struct.pack('!d', self.data)

class UnsignedInteger(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack()

class Float(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!f', data)[0]

    def pack(self):
        return struct.data('!f', data) 

class Real(Float):
    pass

class OctetString(ASNType):
    def __init__(self, data='', length=0):
        self.data = struct.unpack('!d', data)[0]

class BitString(ASNType):
    ID = 4
    def __init__(self, data='', length=0):
        c = {'0': '0000', '1': '0001', '2': '0010', 
             '3':'0011', '4':'0100', '5':'0101', 
             '6':'0110', '7':'0111', '8':'1000', 
             '9':'1001', 'a':'1010', 'b':'1011', 
             'c':'1100', 'd':'1101', 'e':'1110', 
             'f':'1111'}
        self.padding = struct.unpack('!h', b'\x00'+data[:1])[0]
        #h = binascii.b2a_hex(data[1:])
        h = str(binascii.b2a_hex(data[1:]))[2:-1]
        self.data = ''
        for i in h:
            self.data += c[i]

    def pack(self):
        packed_padding = struct.pack('!B', self.padding)
        packed_data = struct.pack('!h', int(self.data, 2))
        return packed_padding + packed_data

class ObjectID(ASNType):
    pass

class BCD(ASNType):
    pass

class BooleanArray(ASNType):
    pass

class UTF8String(ASNType):
    pass
    
class Data(object):
    tag = ''
    tagmap = {(128,0,3):('boolean', Boolean), 
              (128,0,4):('bitstring', BitString),
              (128,0,5):('integer', Integer), 
              (129,0,6):('unsigned', UnsignedInteger),
              (128,0,7):('float', Float), 
              (128,0,8):('real', Real),
              (128,0,9):('octetstring', OctetString),
              (129,0,10):('visiblestring', VisibleString),
              (128,0,12):('binarytime', UTCTime), 
              (128,0,13):('bcd', BCD),
              (129,0,14):('booleanarray', BooleanArray),
              (128,0,15):('objID', ObjectID),
              (128,0,16):('mMSString', UTF8String), 
              (128,0,17):('utcstring', UTCTime)}

    def __init__(self, data=None, length=0):
        self.tagmap[(128,32,1)] = ('array', Data)
        self.tagmap[(128,32,2)] = ('structure', Data)
        self.data = BER.decoder(data, self.tagmap, decode_as_list=True)

    def __getitem__(self, index):
        return self.data[index]

    def __repr__(self):
        return repr(self.data)

    def pack(self):
        """ This is a hack, and should probably be integrated in to
            the BER encoder at some point.
        """
        packed_data = ''
        for i in self.data:
            tag = i.tag[0] + i.tag[1] + i.tag[2]
            tag = struct.pack('!B', tag)
            package = i.pack()
            if len(package) < 128:
                length = struct.pack('!B', len(package))
            else: # HACK.. this will only support lengths up to 254.
                length = struct.pack('!BB', 129, len(package))
            packed_data += tag + length + package

        return packed_data



# GOOSE
class GOOSE(Packet):
    name = "GOOSE"
    fields_desc = [ ShortField("APPID", 3),
                    ShortField("Length", None),
                    ShortField("Reserved1", 0),
                    ShortField("Reserved2", 0),
                  ]

#bind_layers(Ether,GOOSE)
bind_layers(Ether,Dot1Q)
bind_layers(Dot1Q,GOOSE)

class GOOSEPDU(Packet):

    name = "GOOSEPDU"
    fields_desc = [
        # TODO: Change to conditional to ensure GOOSE
        XByteField("ID",0x61),
        XByteField("DefLen",0x81),
        ConditionalField(XByteField("PDU1ByteLen",0x00),lambda pkt:pkt.DefLen^0x80 == 1),  # NOTE: Length comes from this byte's Least Significant Nibble. Not sure what MSN is for.
        ConditionalField(XShortField("PDU2BytesLen",0x0000),lambda pkt:pkt.DefLen^0x80 == 2)
    ]

class GOOSEPDUHeader(Packet):

    name = "GOOSEPDUHeader"
    fields_desc = [
        # NOTE: We could handle these like ASN.1, but these are fixed, so handle manually
        # TODO: Change to conditional to ensure GOOSE
        # TODO: Change to correct field type
        XByteField("gocbRefType",0x80),
        XByteField("gocbRefLen",0),
        PacketLenField("gocbRef",0,None,length_from=lambda pkt:pkt.gocbRefLen), 
        XByteField("timeAllowedToLiveType",0x81),
        XByteField("timeAllowedToLiveLen",0),
        PacketLenField("timeAllowedToLive",0,None,length_from=lambda pkt:pkt.timeAllowedToLiveLen),
        XByteField("datSetType",0x82),
        XByteField("datSetLen",0),
        PacketLenField("datSet",0,None,length_from=lambda pkt:pkt.datSetLen),
        XByteField("goIDType",0x83),
        XByteField("goIDLen",0),
        PacketLenField("goID",0,None,length_from=lambda pkt:pkt.goIDLen),
        XByteField("tType",0x84),
        XByteField("tLen",0),
        PacketLenField("t",0,None,length_from=lambda pkt:pkt.tLen),
        XByteField("stNumType",0x85),
        XByteField("stNumLen",0),
        PacketLenField("stNum",0,None,length_from=lambda pkt:pkt.stNumLen),
        XByteField("sqNumType",0x86),
        XByteField("sqNumLen",0),
        PacketLenField("sqNum",0,None,length_from=lambda pkt:pkt.sqNumLen),
        XByteField("testType",0x87),
        XByteField("testLen",0),
        PacketLenField("test",0,None,length_from=lambda pkt:pkt.testLen),
        XByteField("confRevType",0x88),
        XByteField("confRevLen",0),
        PacketLenField("confRev",0,None,length_from=lambda pkt:pkt.confRevLen),
        XByteField("ndsComType",0x89),
        XByteField("ndsComLen",0),
        PacketLenField("ndsCom",0,None,length_from=lambda pkt:pkt.ndsComLen),
        XByteField("numDataSetEntriesType",0x8a),
        XByteField("numDataSetEntriesLen",0),
        PacketLenField("numDataSetEntries",0,None,length_from=lambda pkt:pkt.numDataSetEntriesLen),
        XByteField("allDataType",0xab),
        XByteField("allDataLen",0),
        PacketLenField("allData",0,None,length_from=lambda pkt:pkt.allDataLen)
    ]


bind_layers(GOOSE, GOOSEPDU)
bind_layers(GOOSEPDU, GOOSEPDUHeader)
#bind_layers(GOOSEPDUHeader, GOOSEPDUData, allData=0xab)

'''
class GOOSEPDUData(Packet):

    name = "GOOSEPDUData"

    def post_build(self, s):
        """
        Try to dissect the following data as a TLS message.
        Note that overloading .guess_payload_class() would not be enough,
        as the TLS session to be used would get lost.
        """
        if s:
            try:
                p = Data(s)
            except KeyboardInterrupt:
                raise
            except Exception:
                p = conf.raw_layer(s, _internal=1, _underlayer=self)
            self.add_payload(p)

    tagmap = {(128,0,0):('gocbRef', VisibleString), 
              (128,0,1):('timeAllowedToLive', Integer), 
              (128,0,2):('datSet', VisibleString), 
              (128,0,3):('goID', VisibleString),
              (128,0,4):('t', UTCTime), 
              (128,0,5):('stNum', Integer),
              (128,0,6):('sqNum', Integer), 
              (128,0,7):('test',Boolean),
              (128,0,8):('confRev', Integer), 
              (128,0,9):('ndsCom', Boolean),
              (128,0,10):('numDataSetEntries', Integer),
              (128,32,11):('allData', Data)}
'''

# NOTE: Keep this for the flag definitions. Might need in future versions.
class GOOSEPDU_ORIG(object):
    ID = 97
    tagmap = {(128,0,0):('gocbRef', VisibleString), 
              (128,0,1):('timeAllowedToLive', Integer), 
              (128,0,2):('datSet', VisibleString), 
              (128,0,3):('goID', VisibleString),
              (128,0,4):('t', UTCTime), 
              (128,0,5):('stNum', Integer),
              (128,0,6):('sqNum', Integer), 
              (128,0,7):('test',Boolean),
              (128,0,8):('confRev', Integer), 
              (128,0,9):('ndsCom', Boolean),
              (128,0,10):('numDataSetEntries', Integer),
              (128,32,11):('allData', Data)}

    def __init__(self, data=None, length=0):
        self.__dict__ = BER.decoder(data, self.tagmap)

    def pack(self):
        #print('GOOSEPDU pack')
        try:
            return BER.encoder(self.__dict__, self.tagmap)
        except:
            print("GOOSEPDU pack: Unexpected error:", sys.exc_info())

    '''
    In [105]: start = 0; end = 0

    In [106]: for e in range(0x80,0x8a):
        ...:     start = start + end + 1
        ...:     end = ag[start] + 1
        ...:     d = ag[start + 1:start + end]
        ...:     print('start: %s - end: %s - d: %s'%(start,end,d))
    '''


