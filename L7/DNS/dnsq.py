from email.policy import default
import io
import enum
import socket
import struct
import typing as t
import argparse
from dataclasses import dataclass


def decode_labeled_str(buf: io.BytesIO) -> str:
    result = ""

    while True:
        label = buf.read(1)

        # Unexpected end of buffer
        if label == b'':
            print(f"WARNING: decode_labeled_str: unexpected end of buffer: {data}")
            break

        # Normal end of buffer
        if label == b'\x00':
            break

        # Pointer received, we'll jump to it
        if label[0] & 0b1100_0000:
            offset = label[0] & 0b0011_1111 << 8 | buf.read(1)[0]
            old_pos = buf.tell()
            buf.seek(offset)
            result += decode_labeled_str(buf)
            buf.seek(old_pos)
            return result

        length = label[0]
        result += buf.read(length).decode('ascii') + '.'

    return result


def encode_labeled_str(s: str) -> bytes:
    parts = s.split(".")
    return b"".join(
        bytes([len(part)]) + part.encode()
        for part in parts
    ) + b"\x00"


class DNSResourceType(enum.Enum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16


class DNSResourceClass(enum.Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4


@dataclass
class DNSPacketHeader:
    # IDENT (16 bit) - identification
    IDENT: int = 42

    # QR (1 bit): 0 for query, 1 for reply
    QR: int = 0

    # OPCODE (4 bits):
    #   0 - Standart query
    #   1 - IQUERY (Inverse query)
    #   2 - STATUS (Server status request)
    OPCODE: int = 0

    # AA (1 bit) - Authoritative Answer
    AA: int = 0

    # TC (1 bit) - Truncation
    #   indicates that this message was truncated due to excessive length
    TC: int = 0

    # RD (1 bit) - Recursion Desired
    #   indicates if the client means a recursive query
    RD: int = 0

    # RA (1 bit) - Recursion Available
    #    in a response, indicates if the replying DNS server supports recursion
    RA: int = 0

    # Z (3 bits) - Reserved
    Z: int = 0

    # RCODE (4 bits) - Response code
    #    0 - NOERROR
    #    1 - FORMERR (Format error)
    #    2 - SERVFAIL
    #    3 - NXDOMAIN (Nonexistent domain)
    RCODE: int = 0

    # QDCOUNT (16 bits) - number of questions
    QDCOUNT: int = 0

    # ANCOUNT (16 bits) - number of answers
    ANCOUNT: int = 0

    # NSCOUNT (16 bits) - number of authority resource records
    NSCOUNT: int = 0

    # ARCOUNT (16 bits) - number of additional authority resource records
    ARCOUNT: int = 0


    @classmethod
    def parse(cls, buf: io.BytesIO):
        ident, flags, q, ans, rr, add = struct.unpack('>HHHHHH', buf.read(12))

        return DNSPacketHeader(
            IDENT=ident,
            QR=flags & 0b1000_0000_0000_0000 >> 15,
            OPCODE=flags & 0b0111_1000_0000_0000 >> 11,
            AA=flags & 0b0000_0100_0000_0000 >> 10,
            TC=flags & 0b0000_0010_0000_0000 >> 9,
            RD=flags & 0b0000_0001_0000_0000 >> 8,
            RA=flags & 0b1000_0000 >> 7,
            Z=flags & 0b0111_0000 >> 4,
            RCODE=flags & 0b1111,
            QDCOUNT=q,
            ANCOUNT=ans,
            NSCOUNT=rr,
            ARCOUNT=add,
        )

    def pack(self) -> bytes:
        ident = self.IDENT
        flags = (
            self.QR << 15 |
            self.OPCODE << 11 |
            self.AA << 10 |
            self.TC << 9 |
            self.RD << 8 |
            self.RA << 7 |
            self.Z << 4 |
            self.RCODE
        )

        q, ans, rr, add = self.QDCOUNT, self.ANCOUNT, self.NSCOUNT, self.ARCOUNT

        # Pack to BIG ENDIAN two UNSIGNED 16-bit fields
        return struct.pack('>HHHHHH', ident, flags, q, ans, rr, add)

    def __str__(self):
        opcode = {0: "QUERY", 1: "IQUERY", 2: "STATUS"}
        rcode = {
            0: "OK",
            1: "FORMAT ERROR",
            2: "SERVER FAILURE",
            3: "NAME ERROR",
            4: "NOT IMPLEMENTED",
            5: "REFUSED",
        }

        return (
            f"{'RESPONSE' if self.QR else 'QUERY'}" +
            f", STATUS: {rcode.get(self.RCODE, 'UNKNOWN')}" +
            f", IDENT: {hex(self.IDENT)}" +
            f", OPCODE: {opcode.get(self.OPCODE, 'UNKNOWN')}" +
            f", {'Authoritative ' if self.AA else 'Non-Authoritative '}" +
            f"{'| Truncated ' if self.TC else ''}" +
            f"{'| Recursion Desired ' if self.TC else ''}" +
            f"{'| Recursion Available ' if self.RA else ''}"
        )


@dataclass
class DNSQuestionRecord:
    QNAME: str
    QTYPE: DNSResourceType  # 16 bit
    QCLASS: DNSResourceClass  # 16 bit

    @classmethod
    def parse(cls, buf: io.BytesIO):
        qname = decode_labeled_str(buf)
        qtype, qclass = struct.unpack('>HH', buf.read(4))

        return cls(
            QNAME=qname,
            QTYPE=DNSResourceType(qtype),
            QCLASS=DNSResourceClass(qclass),
        )

    def pack(self) -> bytes:
        qname = encode_labeled_str(self.QNAME)
        qtype = struct.pack('>H', self.QTYPE.value)
        qclass = struct.pack('>H', self.QCLASS.value)
        return qname + qtype + qclass

    def __repr__(self):
        return f"{self.QNAME} {self.QTYPE.name} {self.QCLASS.name}"


@dataclass
class DNSResourceRecord:
    NAME: str
    TYPE: DNSResourceType
    CLASS: DNSResourceClass
    TTL: int
    RDLENGTH: int
    RDATA: str

    @classmethod
    def parse(cls, buf: io.BytesIO) -> DNSQuestionRecord:
        name = decode_labeled_str(buf)
        t, c, ttl, rdlen = struct.unpack('>HHIH', buf.read(10))
        rdata = cls.parse_rdata(DNSResourceType(t), rdlen, buf)

        return cls(
            NAME=name,
            TYPE=DNSResourceType(t),
            CLASS=DNSResourceClass(c),
            TTL=ttl,
            RDLENGTH=rdlen,
            RDATA=rdata,
        )

    def pack(self) -> bytes:
        raise NotImplementedError()
    
    @classmethod
    def parse_rdata(cls, type_: DNSResourceType, rdlen: int, buf: io.BytesIO):
        def as_ipv4():
            return ".".join(map(str, struct.unpack(">BBBB", buf.read(4))))
        
        def as_labeled_str():
            return decode_labeled_str(buf)
        
        def as_mx():
            preference = struct.unpack(">H", buf.read(2))[0]
            name = as_labeled_str()

            return f"{name} (PREF: {preference})"
        
        def as_txt():
            return buf.read().decode()
        
        def as_soa():
            mname = as_labeled_str()
            rname = as_labeled_str()
            serial, refresh, retry, expire = struct.unpack(">4I", buf.read(4 * 4))

            return f"{mname} / {rname} (serial: {serial}, refresh: {refresh}, retry: {retry}, expire: {expire})"

        match type_:
            case DNSResourceType.A:
                if rdlen == 4:
                   return as_ipv4()
            case DNSResourceType.NS | DNSResourceType.PTR:
                return as_labeled_str()
            case DNSResourceType.SOA:
                return as_soa()
            case DNSResourceType.MX:
                return as_mx()
            case DNSResourceType.TXT:
                return as_txt()

        return buf.read(rdlen)

    def __repr__(self):
        return f"TTL: {self.TTL} | {self.NAME} {self.TYPE.name} {self.CLASS.name} {self.RDATA}"


@dataclass
class DNSPacket:
    header: DNSPacketHeader
    question: t.List[DNSQuestionRecord]
    answer: t.List[DNSResourceRecord]
    authority: t.List[DNSResourceRecord]
    additional: t.List[DNSResourceRecord]

    @classmethod
    def query(cls, type_: DNSResourceType, name: str, reverse=False, recurse=True):
        if type_ == DNSResourceType.PTR and "in-addr.arpa" not in name:
            name = ".".join(reversed(name.split("."))) + ".in-addr.arpa"

        return cls(
            header=DNSPacketHeader(
                IDENT=0xF149,
                OPCODE=(1 if reverse else 0),
                RD=(1 if recurse else 0),
                QDCOUNT=1,
            ),
            question=[DNSQuestionRecord(
                QNAME=name,
                QTYPE=type_,
                QCLASS=DNSResourceClass.IN,
            )],
            answer=[],
            authority=[],
            additional=[],
        )

    @classmethod
    def parse(cls, buf: io.BytesIO):
        header = DNSPacketHeader.parse(buf)
        question = []
        answer = []
        authority = []
        additional = []

        for _ in range(header.QDCOUNT):
            question.append(DNSQuestionRecord.parse(buf))
        for _ in range(header.ANCOUNT):
            answer.append(DNSResourceRecord.parse(buf))
        for _ in range(header.NSCOUNT):
            authority.append(DNSResourceRecord.parse(buf))
        for _ in range(header.ARCOUNT):
            additional.append(DNSResourceRecord.parse(buf))

        return cls(
            header,
            question,
            answer,
            authority,
            additional,
        )

    def pack(self) -> bytes:
        result = self.header.pack()

        for q in self.question:
            result += q.pack()
        for a in self.answer:
            result += a.pack()
        for a in self.authority:
            result += a.pack()
        for a in self.additional:
            result += a.pack()

        return result

    def __repr__(self):
        result = f"{self.header}\n"

        if self.question:
            result += "======= QUERIES =======\n"
        for q in self.question:
            result += repr(q) + '\n'
        if self.answer:
            result += "======= ANSWERS =======\n"
        for a in self.answer:
            result += repr(a) + '\n'
        if self.authority:
            result += "======= AUTHORITY =======\n"
        for a in self.authority:
            result += repr(a) + '\n'
        if self.additional:
            result += "======= ADDITIONAL =======\n"
        for a in self.additional:
            result += repr(a) + '\n'

        return result


DNS_PORT = 53


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("name", help="Name to resolve")
    p.add_argument("resource_type", help="Query resource type (A, TXT, ...)")
    p.add_argument("--ns", help="DNS Server Address", default="1.1.1.1")
    p.add_argument("-r", help="Use recursive DNS", action="store_true")
    p.add_argument("-i", "--inverse", help="Inverse query", action="store_true")
    args = p.parse_args()

    if args.resource_type not in DNSResourceType.__members__:
        print(f"Unknown resource type '{args.resource_type}'")

    resource_type = DNSResourceType.__members__[args.resource_type]

    packet = DNSPacket.query(resource_type, args.name)
    print(packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    sock.connect((args.ns, DNS_PORT))
    sock.send(packet.pack())

    data = sock.recv(4096)
    # print(data)

    received = DNSPacket.parse(io.BytesIO(data))
    print(received)
    
