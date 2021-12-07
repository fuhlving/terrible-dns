import socket
import struct
import json
import sys
from random import randrange

DNS_TYPE = {
    1: "A",
    28: "AAAA",
    42: "APL",
    257: "CAA",
    60: "CDNSKEY",
    59: "CDS",
    37: "CERT",
    5: "CNAME",
    62: "CSYNC",
    49: "DHCID",
    32769: "DLV",
    39: "DNAME",
    48: "DNSKEY",
    43: "DS",
    108: "EUI48",
    109: "EUI64",
    55: "HIP",
    65: "HTTPS",
    45: "IPSECKEY",
    25: "KEY",
    36: "LOC",
    15: "MX",
    35: "NAPTR",
    2: "NS",
    47: "NSEC",
    50: "NSEC3",
    51: "NSEC3PARAM",
    61: "OPENPGPKEY",
    12: "PTR",
    46: "RRSIG",
    17: "RP",
    24: "SIG",
    53: "SMIMEA",
    6: "SOA",
    33: "SRV",
    44: "SSHFP",
    64: "SVCB",
    32768: "TA",
    249: "TKEY",
    52: "TLSA",
    250: "TSIG",
    16: "TXT",
    256: "URI",
    63: "ZONEMD",
    255: "*",
    252: "AXFR",
    251: "IXFR",
    41: "OPT"
}
DNS_CLASS = {
    0: "RESERVED",
    1: "IN",
    3: "CH",
    4: "HS",
    254: "NONE",
    255: "*"
}
DNS_RCODE = {
    0: "NoError",
    1: "FormErr",
    2: "ServFail",
    3: "NXDomain",
    4: "NotImp",
    5: "Refused",
    6: "YXDomain",
    7: "YXRRSet",
    8: "NXRRSet",
    9: "NotAuth",
    10: "NotZone",
    11: "DSOTYPENI",
    16: "BADVERS",
    17: "BADSIG",
    18: "BADTIME",
    19: "BADMODE",
    20: "BADNAME",
    21: "BADALG",
    22: "BADTRUNC",
    23: "BADCOOKIE",
}

class DnsClient:
    def __init__(self, port=53, timeout=10, nameserver="8.8.8.8"):
        self.port = port
        self.timeout = timeout
        self.nameserver = nameserver

    def sourceport(self):
        return randrange(40000, 65535)

    def id(self):
        return randrange(0, 65534)

    def binumerate(self, input, format="str"):
        input = bin(input)[2:]
        values = []
        for _ , x in enumerate(input):
            values.append(x)
        
        if format == "str":
            values = "".join([str(x) for x in values])

        return values


    def genereate_header(self, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0):
        
        header = struct.pack("!H", self.id())
        flags = "0000000100000000"
        header += struct.pack("!H", int(flags, 2))
        header += struct.pack("!HHHH", QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

        return header

    def genereate_request(self, domain, request_type=1):
        request = self.genereate_header()
        
        for x in domain.split("."):
            request += struct.pack("B", len(x))
            for _ , byte in enumerate(x):
                request += struct.pack("c", byte.encode())
        
        request += struct.pack("!B", 0)

        if isinstance(request_type, int):
            request += struct.pack("!HH", request_type, 1)
        elif isinstance(request_type, str):
            for key, value in DNS_TYPE.items():
                if request_type.lower() == value.lower():
                    request += struct.pack("!HH", key, 1)
                    break
            else:
                raise Exception(f"{request_type} ({type(request_type)}) is invalid. Valid types: {DNS_TYPE}")
        else:
            raise Exception(f"{request_type} is not valid type: should be str or int. type is {type(request_type)}")

        return request

    def send_request(self, hostname, request_type=1):

        packet = self.genereate_request(hostname, request_type=request_type)

        data = self.connect_udp(packet)

        if data[2] & 0b10:
            print ("Truncated packet, trying TCP")
            packet = self.genereate_request(hostname, request_type=request_type)

            data = self.connect_tcp(packet)
            # Remove the length provided by TCP
            data = data[2:]

        data = self.parse(data)

        return data

    def connect_udp(self, packet):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tries = 0
            while tries < 15: 
                try: 
                    s.bind(('', self.sourceport()))
                    break
                except OSError as e:
                    print(f"Error binding soocket, {e}")
                    tries = tries + 1
            s.sendto(bytes(packet), (self.nameserver, self.port))

            data, _ = s.recvfrom(1024)

        return data

    def connect_tcp(self, packet):  
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            tries = 0
            while tries < 15:
                try:
                    s.connect((self.nameserver, self.port))
                    break
                except OSError as e:
                    print(f"Error binding socket, {e}")
                    tries = tries + 1
            # TCP Expects length in the first octet RFC 7766 Section 8. The length is just the data, not including the octet itself
            length = struct.pack("!H", len(packet))
            packet = length + packet
            s.sendall(packet)
            data = b""
            while True:
                part = s.recv(1024)
                data += part
                if len(part) < 1024:
                    break
            
            if not data:
                print("Empty response?")
                quit()
    
        return data

    def parse(self, data):
        
        # Haeder section
        #print(data)
        header = data[0:2*6]
        
        ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack("!HHHHHH", header)

        # Binary numbers here could have leading zeroes removed and or converted to decimal, but its easier two read this way
        QR = True if FLAGS & 0b1000000000000000 else False
        AA = True if FLAGS & 0b0000010000000000 else False
        TC = True if FLAGS & 0b0000001000000000 else False
        RD = True if FLAGS & 0b0000000100000000 else False
        RA = True if FLAGS & 0b0000000010000000 else False
        OPCODE = FLAGS >> 10 & 15 # 0b1111
        Z = FLAGS >> 4 & 7 # 0b111
        RCODE = FLAGS & 15 # 0b1111

        header = {
            "id": ID,
            "flags": FLAGS,
            "flags_values": {
                "QR": QR,
                "AA": AA,
                "TC": TC,
                "RD": RD,
                "RA": RA,
                "OPCODE": OPCODE,
                "Z": Z,
                "RCODE": RCODE,
                "RCODE_TEXT": DNS_RCODE[RCODE]
            },
            "qdcount": QDCOUNT,
            "ancount": ANCOUNT,
            "nscount": NSCOUNT,
            "arcound": ARCOUNT
        }

        response = data[12:]

        # Question Section
        QUESTIONS = []
        length, domain = self.walk(response, packet=data)

        response = response[length:]
        QTYPE, QCLASS = struct.unpack("!HH", response[:2*2])
        response = response[2*2:]
        QDOMAIN = ".".join(domain)
        question = {
            "domain": QDOMAIN,
            "qtype": QTYPE,
            "qtype_text": DNS_TYPE[QTYPE],
            "qclass": QCLASS,
            "qclass_text": DNS_CLASS[QCLASS]
        }
        QUESTIONS.append(question)


        # Ansers section
        RESPONSES = []
        for _ in range(ANCOUNT):
            length, domain = self.walk(response, packet=data)

            response = response[length:]
            TYPE, CLASS, TTL = struct.unpack("!HHI", response[:2*4])
            response = response[2*4:]

            length = struct.unpack("!H", response[0:2])[0]
            address = self.rdataparse(response[2:], length, response_type=TYPE, packet=data)
            response = response[length+2:]
        
            answer = {
                "domain": ".".join(domain),
                "address": address,
                "ttl": TTL,
                "type": TYPE,
                "type_text": DNS_TYPE[TYPE],
                "class": CLASS,
                "class_text": DNS_CLASS[CLASS]


            }
            RESPONSES.append(answer)
        
        PACKET = {
            "HEADER": header,
            "QUESTIONS": QUESTIONS,
            "ANSWERS": RESPONSES
        }

        return PACKET
            

    def rdataparse(self, data, length, response_type=None, packet=None):
        address = []
        # A
        if response_type == 1:
            for i in range(length):
                address.append(data[i])
            result = ".".join([str(x) for x in address])
        # AAAA
        elif response_type == 28:
            address = struct.unpack("!HHHHHHHH", data)
            result = ":".join([hex(x)[2:] for x in address])
        # TXT
        elif response_type == 16:
            length = data[0]
            result = ""
            for i in range(length):
                result += chr(data[i+1])
        # NS
        elif response_type == 2:
            _, nameserver = self.walk(data, packet=packet)
            result = ".".join([str(x) for x in nameserver])

        # MX
        elif response_type == 15:
            _, nameserver = self.walk(data, packet=packet)
            result = ".".join([str(x) for x in nameserver])
        else:
            self.dump_packet(data)
            raise Exception(f"Unsupported response: {response_type} ({DNS_TYPE[response_type]})")
            #print(data)
            #_, address = self.walk(data=data, position=2, packet=packet)
        
        return result




    def walk(self, data, packet, position=0):
        string = []
        total_length = 0
        while True:
            length = data[position]
            # cheks if first two bits are 1. 192 decimal is 0b11000000 binary. since we can ignore the next byte we dont have to unpack it to check the first two bits
            offset = True if length & 192 == 192 else False
            if offset:
                offset_value = struct.unpack("!H", data[position:position + 2])[0]
                print(f"OFFSET: {offset_value & 16383}")
                # offset is stored in the last 16 bits of the two octets. 16383 decimal is 0b0011111111111111 
                data = packet[offset_value & 16383:]
                _ , offset_value = self.walk(data=data, packet=packet)
                for s in offset_value: string.append(s)
                total_length = total_length + 1
                break
            else:
                position = position + 1
                if length == 0:
                    break
                val = ""
                for _ in range(length):
                    val += chr(data[position])
                    position = position + 1
                
                string.append(val)
                total_length = total_length + length + 1

        #total lengde med selve lengde, verdi + termiator byte
        return (total_length + 1, string)

    def dump_packet(self, packet):
        for x, y in enumerate(packet):
            CHR = ""
            if 126 > y > 33:
                CHR = chr(y)
            else:
                CHR = " "
            print(f"{x}: DEC: {y:#03},\tHEX: {y:#04x},\tCHR: {CHR}, \tBIN: {y:#010b}")

    def a(self, hostname, request_type=None):
        a = self.send_request(hostname, request_type=request_type)
        
        print(json.dumps(a, indent=1))

if __name__ == "__main__":
    a = DnsClient()
    a.a(sys.argv[1], request_type=sys.argv[2])

