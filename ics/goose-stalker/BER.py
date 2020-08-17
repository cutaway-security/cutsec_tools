import struct 
import sys

DEBUG = False

class DecoderError(Exception):
    pass

def unpack_varint(data, length):
    """ Decodes a variable length integer """
    if length == 1: 
        data = struct.unpack('!h', b'\x00' + data)[0]
    elif length == 2:
        data = struct.unpack('!h', data)[0]
    elif length == 4:
        data = struct.unpack('!i', data)[0]
    else:
        data = -1
    return data

def encoder(data, tagmap):
    keys = sorted(tagmap.keys())
    keys.sort()
    packed_data = b''

    for key in keys:
        try:
            attr = data[tagmap[key][0]]
        except KeyError:
            continue

        tag = key[0] + key[1] + key[2]
        tag = struct.pack('!B', tag)
        try:
            package = attr.pack()
        except:
            print('\n####\nattr.pack: Unexpected error: %s'%(sys.exc_info()[0]))
            print('attr metadata - Type: %s'%(type(attr)))
            print('attr data: %s\n#####\n'%(attr))
            continue
        if len(package) < 128:
            length = struct.pack('!B', len(package))
        else:  # HACK.. this will only support lengths up to 254.
            length = struct.pack('!BB', 129, len(package))
        packed_data += tag + length + package
    return packed_data

def decoder(data, tagmap, ignore_errors=True, decode_as_list=False):
    """ Decodes binary data encoded in a BER format and return a dictionary.

    Keyword Arguments:
    data -- the binary data to decode stored in a string
    tagmap -- a dictionary keyed by a tag tuple (class, format, id) as integer
              values with tuple values (name, type).
    ignore_errors -- will cause the decoder to skip past errors and continue

    """
    if decode_as_list:
        results = list()
    else:
        results = dict()

    while len(data) > 0:
        chunk = 1
        # Grab first byte, which is tags
        tag = ord(data[:chunk])
        data = data[chunk:]
        tag_class = tag & 0xC0
        tag_format = tag & 0x20
        tag_id = tag & 0x1F
        if DEBUG: print('\n\nval.tag: %s,%s,%s' % (tag_class, tag_format, tag_id))

        # Grab second byte, which is length
        length = ord(data[:chunk])
        data = data[chunk:]

        if length & 0x80 == 0x80: # length field is longer than a byte
            if DEBUG: print('len^0x80 variant')
            n = length & 0x7F 
            length = unpack_varint(data[:n], n)
            data = data[n:] 

        if DEBUG: print('Len: %s - Tag Data: %s'%(length,data))
        try:
            # Get name from tags
            name = tagmap[(tag_class, tag_format, tag_id)][0]
            if DEBUG: print('Name: %s'%(name))
            # Get type from tags
            inst = tagmap[(tag_class, tag_format, tag_id)][1]
            if DEBUG: print('Inst: %s'%(inst))
            # Get the value as defined by the type
            if DEBUG: print('Data to parse: %s'%(data[:length]))
            val = inst(data[:length], length) # exception handling?
            val.tag = (tag_class, tag_format, tag_id)
            if DEBUG: print('Val: %s'%(val))
        except TypeError:
            print("BER.py: decoder: TypeError: %r"%(sys.exc_info()))
            continue
        except KeyError:
            #print('In Except KeyError')
            print("BER.py: decoder: KeyError: %r"%(sys.exc_info()))
            if ignore_errors:
                if DEBUG: 
                    print('Unfound tag %s,%s,%s' % (tag_class, tag_format, tag_id))
                    print('tag data: %s\n#####\n'%(repr(data)))
                continue
            else:
                raise DecoderError("Tag not found in tagmap")
        except:
            print("BER.py: decoder: Unexpected error: %s"%(sys.exc_info()[0]))
            continue
        finally:
            data = data[length:] 
   
        if decode_as_list:
            results.append(val)
        else:
            results[name] = val

    if DEBUG: print('Returning results: %s'%(results))
    return results
