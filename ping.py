#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2017 Rokas Kupstys
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
import os
import time
import select
import socket
import struct
from collections import namedtuple

ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8

IcmpEchoReplyHeader = namedtuple('IcmpEchoReply', ('type', 'code', 'checksum', 'id', 'seq_number'))
IpHeader = namedtuple('IpHeader', ('version', 'type', 'length', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_ip',
                                   'dest_ip'))
IcmpEchoReply = namedtuple('IcmpEchoReply', ['icmp_header', 'ip_header', 'reply_time', 'payload'])


def icmp_checksum(packet):
    checksum = 0
    for i in range(0, len(packet) - 1, 2):
        checksum += struct.unpack('<H', packet[i:i + 2])[0]

    # Last byte for odd-length packets.
    if len(packet) % 2:
        checksum += packet[-1]

    checksum &= 0xFFFFFFFF
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum += checksum >> 16
    checksum = ~checksum & 0xFFFF
    checksum = socket.htons(checksum)
    return checksum


def ping(address, payload=None, timeout=2.0, seq_number=0):
    if payload is None:
        payload = b'PING' * 16

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp')) as s:
            # Send ICMP_ECHO_REQUEST
            checksum = 0
            header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, os.getpid(), seq_number)
            packet = header + payload
            checksum = icmp_checksum(packet)
            packet = packet[:2] + struct.pack('!H', checksum) + packet[4:]
            send_time = time.perf_counter()
            s.sendto(packet, (address, 0))

            # Receive ICMP_ECHO_REPLY
            current_timeout = timeout
            while True:
                select_time = time.perf_counter()
                readable, _, __ = select.select([s], [], [], current_timeout)
                if len(readable) == 0:
                    current_timeout -= time.perf_counter() - select_time
                    if current_timeout <= 0:
                        return None
                    time.sleep(0)
                else:
                    reply_time = time.perf_counter()
                    packet, address = s.recvfrom(len(payload) + 28)
                    icmp_header = IcmpEchoReplyHeader(*struct.unpack('!BBHHH', packet[20:28]))

                    if icmp_header.type == ICMP_ECHO_REPLY and icmp_header.id == os.getpid() and \
                       icmp_header.seq_number == seq_number:
                        ip_header = IpHeader(*struct.unpack('!BBHHHBBHII', packet[:20]))
                        return IcmpEchoReply(icmp_header, ip_header, reply_time - send_time, packet[28:])
    except socket.error as e:
        raise Exception('Ping failed.') from e


if __name__ == '__main__':
    seq_number = 0
    for _ in range(3):
        response = ping('google.com', seq_number=seq_number)
        if response is None:
            print('Timeout')
        else:
            seq_number += 1
            print('Got response from {} in {:.3f}'
                  .format(socket.inet_ntoa(struct.pack('!I', response.ip_header.src_ip)), response.reply_time))
 
