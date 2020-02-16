import time
import pprint
import argparse

from berserker_resolver import Resolver
from multiprocessing.pool import ThreadPool as Pool
from concurrent.futures import ThreadPoolExecutor

from typing import List
from dataclasses import dataclass
from datetime import datetime

import binascii
import io
import pprint
import re
import socket
import struct
import sys
import time
from base64 import b64encode
from typing import *

SOCKET = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCKET.settimeout(5.0)

parser = argparse.ArgumentParser(description='Scan IP\'s for DNS Resolvers')
parser.add_argument('ADDRESS_FILE', type=argparse.FileType('r'), help='File containg IP addresses to scan')
parser.add_argument('--domain', default='google.com', help='Domain usedin DNS A record query (default = google.com)')
parser.add_argument('--outfile', default='nameservers.csv', help='CSV output file')


class Record:
    """
    Shared data for all records. Also defines functions which should be used for all
    records.
    """

    def __init__(self, name: str, answer_type: 'short',
                 answer_class: 'short', ttl: int, rdata_len: 'short'):
        """

        :param name:    List of labels (bytes)
        :param answer_type:
        :param answer_class:
        :param ttl:
        :param rdata_len:
        """
        self.name = name
        self.answer_type = answer_type
        self.answer_class = answer_class
        self.ttl = ttl
        self.rdata_len = rdata_len

    def attributes_as_dict(self):
        """
        Get the current record attributes as a dictionary
        :return:    Dictionary of record attributes
        """
        answer_type = self.answer_type
        answer_class = self.answer_class

        return {
            'name': self.name,
            'answer_type': answer_type,
            'answer_class': answer_class,
            'ttl': self.ttl,
            'rdata_len': self.rdata_len
        }

    @staticmethod
    def from_bytes(message: bytes, offset: int):
        """
        Read the shared record data from bytes
        :param message:     Bytes that represent the message
        :param offset:  Offset at which to read the message
        :return:    Dictionary of gathered attributes and new offset (after what we just read)
        """
        answer_section = struct.Struct("!2HiH")
        name, offset = decode_labels(message, offset)
        answer_type, answer_class, ttl, rdata_len = answer_section.unpack_from(message, offset)
        # name, offset = decode_labels(message, offset)
        name = b'.'.join(name).decode()

        return {
            'name': name,
            'answer_type': answer_type,
            'answer_class': answer_class,
            'ttl': ttl,
            'rdata_len': rdata_len
        }, offset + 10




    def serialize(self, buffer: io.BytesIO, original_ttl: int, capitalize_name=False):
        """
        Serialzes the data from this record into the given buffer.
        :param buffer:  Buffer to insert WIRE data into
        :param original_ttl:    Original time to live of the message
        :param capitalize_name:     Whether or not the NAME field should be capitalized
        :return:    None
        """
        if self.name == '': # root zone
            buffer.write(struct.pack('!B', 0x00))
        else:
            n = self.name.lower()
            if capitalize_name:
                k = n.split('.')
                n = '.'.join(['.'.join(k[:-1]).upper(), k[-1]])

            dname = [struct.pack(f"!{len(label)}s", label) for label in compress_name(n)]
            buffer.write(b''.join(dname))

        buffer.write(struct.pack("!2HIH", self.answer_type,
                                 self.answer_class, original_ttl, self.rdata_len))


class A(Record):
    """
    A record, record type.
    """
    def __init__(self, octet1: 'byte', octet2: 'byte', octet3: 'byte', octet4: 'byte', **kwargs):
        """

        :param octet1: The first octet of the ip address
        :param octet2: The second octet of the ip address
        :param octet3: The third octet of the ip address
        :param octet4: The fourth octet of the ip address
        :param kwargs: The record header
        """
        super(A, self).__init__(**kwargs)
        self.octet1 = octet1
        self.octet2 = octet2
        self.octet3 = octet3
        self.octet4 = octet4


    def pretty_print(self):
        """
        Print the A record in a way that is visually pleasing
        :return:    None
        """
        print("\nA")
        pprint.pprint({
            **super().attributes_as_dict(),
            'ip': f'{self.octet1}.{self.octet2}.{self.octet3}.{self.octet4}',
        })

    def print(self, rrsig: 'RRSIG', valid):
        """
        Print the A record in a way that is specified by the project writeup
        :param rrsig:   RRSIG record corresponding to this A record
        :param valid:   Whether or not the rrsig is valid
        :return:    None
        """
        print(f"IP\t{self.octet1}.{self.octet2}.{self.octet3}.{self.octet4}\t", end='')
        print(f'{rrsig.get_sig_b64()}\t', end='')

        if valid:
            print("VALID")
        else:
            print("INVALID")

    @staticmethod
    def from_bytes(message: bytes, offset: int):
        """
        Construct an A record from bytes
        :param message:     Byte array for the message
        :param offset:  Offset at which to start reading
        :return:    Constructed A record, the new offset
        """
        header, offset = Record.from_bytes(message, offset)

        octets = struct.unpack_from("BBBB", message, offset)
        a = A(*octets, **header)
        return a, offset + a.rdata_len



    def serialize(self, include_header=False):
        """
        Serialize this record in network byte order
        :param include_header:  Whether or not the header should be included in serialization
        :return:    Bytes, serialized record
        """
        buffer = io.BytesIO()
        if include_header:
            super().serialize(buffer)
        buffer.write(struct.pack("!BBBB", self.octet1, self.octet2, self.octet3, self.octet4))

        return buffer.getvalue()


def compress_name(name: str, return_hex_str=False) -> Union[List[bytes], str]:
    """
    Compress the given name into DNS compression format
    :param name:    Name to be compressed
    :param return_hex_str:  Whether or not a hex string should be returned
    :return:    List of bytes or hex string
    """
    name += '.'
    cache = {}
    pos = 0
    results = []

    labels = name.split('.')
    while len(labels):
        key = '.'.join(labels)
        if key.lower() in cache:
            results.append((cache[key.lower()] + 2 ** 15 + 2 ** 14).to_bytes(2, 'big'))
            pos += 2
            break
        else:
            label = labels.pop(0).encode('ascii')
            length = len(label).to_bytes(1, 'big')
            results.append(length + label)
            cache[key.lower()] = pos
            pos += len(label) + 1
    else:
        #results.append(b'0')
        pos += 1

    if not return_hex_str:
        return results

    out = ""
    for s in results:
        out += s.hex()
    return out


def construct_request(host: str):
    """
    Construct the DNS query request for the given host and query type
    :param host:    Host that we want
    :return:    Hex of the constructed request
    """
    buffer = ''

    # header
    buffer += '0000'
    buffer += '0130'
    buffer += '0001'
    buffer += '0000'
    buffer += '0000'
    buffer += '0001'

    # name
    if host == '.':
        buffer += '00'
    else:
        buffer += compress_name(host, return_hex_str=True)

    # A query
    buffer += '0001'

    # class (always 1)
    buffer += '0001'

    # OPT
    buffer += '00'
    # opt type 41
    buffer += '0029'
    # udp size
    buffer += '1000'
    # rcode
    buffer += '00'
    # enso version
    buffer += '00'
    # z (do bit set to 1)
    buffer += '8000'
    # data-len (always 0 for some reason)
    buffer += '0000'

    return binascii.unhexlify(buffer)


def send_dns_packet(host: str, address: Tuple[str, int]):
    """
    Send the DNS packet to the given address
    :param host:    Host that we want data for
    :param address:     Address and port nubmer
    :return:    RRSet
    """
    message = construct_request(host)
    SOCKET.sendto(message, address)

    #  data, addr = SOCKET.recvfrom(4096)
    #  print(addr)

    #  return decode_dns_message(data, print_records=False)


def decode_dns_message(message: bytes, print_records: bool=False):
    """
    Decode the given DNS message response
    :param message:     Message to read
    :param print_records:   Whether or not to print the records as they are read
    :return:    RRSet
    """
    DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")

    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    if ancount == 0 and nscount > 1: # we got NXDOMAIN so domain does not exist
        print("NOTFOUND")
        exit(1)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    offset = skip_questions_section(message, offset, qdcount)

    if print_records:
        result = {"id": id,
                  "is_response": qr,
                  "opcode": opcode,
                  "is_authoritative": aa,
                  "is_truncated": tc,
                  "recursion_desired": rd,
                  "recursion_available": ra,
                  "reserved": z,
                  "response_code": rcode,
                  "question_count": qdcount,
                  "answer_count": ancount,
                  "authority_count": nscount,
                  "additional_count": arcount}

        pprint.pprint(result)
        print()

    a_records: List[A] = []

    # Read the answer section
    answer_section = struct.Struct("!2HiH")
    for _ in range(ancount + nscount):
        name, temp_offset = decode_labels(message, offset)
        answer_type, answer_class, ttl, rdata_len = answer_section.unpack_from(message, temp_offset)
        # name, offset = decode_labels(message, offset)

        if answer_type == 1:  # A type
            record, offset = A.from_bytes(message, offset)

            if print_records:
                record.pretty_print()
            a_records.append(record)
        #  elif answer_type == 6:   # SOA
        #      record, offset = SOA.from_bytes(message, offset)
        #
        #      soa_records.append(record)
        else:
            pass
            #  raise Exception("Unrecognized answer type " + str(answer_type))

    return [a.pretty_print() for a in a_records]


def skip_questions_section(message: bytes, offset: int, qdcount: int) -> int:
    """
    Reads past the questions section of the message
    :param message:     Message to be read
    :param offset:  Offset at which to read the message
    :param qdcount:     Count of the questions
    :return:    New offset
    """
    DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        _, _ = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

    return offset


def compress_name(name: str, return_hex_str=False) -> Union[List[bytes], str]:
    """
    Compress the given name into DNS compression format
    :param name:    Name to be compressed
    :param return_hex_str:  Whether or not a hex string should be returned
    :return:    List of bytes or hex string
    """
    name += '.'
    cache = {}
    pos = 0
    results = []

    labels = name.split('.')
    while len(labels):
        key = '.'.join(labels)
        if key.lower() in cache:
            results.append((cache[key.lower()] + 2 ** 15 + 2 ** 14).to_bytes(2, 'big'))
            pos += 2
            break
        else:
            label = labels.pop(0).encode('ascii')
            length = len(label).to_bytes(1, 'big')
            results.append(length + label)
            cache[key.lower()] = pos
            pos += len(label) + 1
    else:
        #results.append(b'0')
        pos += 1

    if not return_hex_str:
        return results

    out = ""
    for s in results:
        out += s.hex()
    return out


def decode_labels(message: bytes, offset: int) -> Tuple[List[bytes], int]:
    """
    Decodes the labels from the given message at the given offset. If the two bytes
    at/after the offset is a pointer, it will be followed and the full
    label will be computed.

    :param message: Byte array of received message
    :param offset:  Offset of message
    :return: Labels as list of bytes, offset after reading "name"
    """
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF)[0], offset

        if (length & 0xC0) != 0x00:
            raise Exception("Unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from(f"{length}s", message, offset))
        offset += length


def get_nameservers(f: str) -> List[str]:
    """
    Read all nameservers from the given file into a list of IP's

    :param f: Name of the file to read
    :returns:   List of IP addresses as strings
    """
    with open(f) as nss:
        return [ns.strip() for ns in nss.readlines()]


def send(nameservers: List[str], domain: str='google.com', retries: int=4):
    # repeat the process RETRIES number of times as UDP is lossy
    for i in range(retries):
        for i in range(len(nameservers)):
            if i == 10000:
                time.sleep(3)
                # take a break every 10k queries so we don't overload the network

            send_dns_packet(domain, (nameservers[i], 53))


def listen():
    resolvers = set()
    try:
        while True:
            data, addr = SOCKET.recvfrom(4096)

            ip = addr[0]
            if ip not in resolvers:
                print(ip)
            resolvers.add(ip)
            #  decode_dns_message(data)
    except socket.timeout:
        # if we time'd out, we're done receiving messages
        pass


def scan_nameservers_parallel(nameservers: List[str], threads: int=1000, domain: str='google.com'):
    with ThreadPoolExecutor(2) as executor:
        jobs = [
            executor.submit(send, nameservers, domain),
            executor.submit(listen)
        ]
        
        for job in jobs:
            res = job.result()


def main():
    args = parser.parse_args()
    
    nameservers = get_nameservers(args.ADDRESS_FILE.name)

    scan_nameservers_parallel(nameservers)

    #  for ns in nameservers:
    #      send_dns_packet('google.com', 'A', (ns, 53))

    #  while True:
    #      data, addr = SOCKET.recvfrom(4096)
    #      print(addr)
    #      decode_dns_message(data)

    #  return decode_dns_message(data, print_records=False)
    #  a = scan_nameservers_parallel(nameservers, domain=args.domain)
    #  pprint.pprint(a)


if __name__ == '__main__':
    main()
