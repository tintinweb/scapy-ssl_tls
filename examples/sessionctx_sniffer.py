#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>
"""

server:
    #> openssl s_server -accept 443 -WWW -debug -cipher AES128-SHA
client:
    #> openssl s_client -connect 192.168.220.131:443 -tls1

"""

from __future__ import print_function
import sys
import os
try:
    from scapy.all import *
except ImportError:
    from scapy import *

try:
    # try systemwide scapy import first, otherwise we might end up with different
    #  imports for SSL()/TLS() leading to sesionctx_sniffer.py not showing any
    #  traffic.
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    import scapy.layers.ssl_tls_crypto as ssl_tls_crypto
except ImportError:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    import scapy_ssl_tls.ssl_tls_crypto as ssl_tls_crypto

import socket


class L4TcpReassembler(object):

    """ WARNING - this is not a valid TCP Stream Reassembler.
                  It is not L5+ aware and only operates at L4
                  Only works for the assumption that a consecutive stream will be split in segments of the max segment size (mss). It will concat segments == mss until a segment < mss is found. it will then spit out a reassembled (fake) TCP packet with the full payload.
    """
    class TCPFlags:
        FIN = 0x01
        SYN = 0x02
        RST = 0x04
        PSH = 0x08
        ACK = 0x10
        URG = 0x20
        ECE = 0x40
        CWR = 0x80

    class TCPStream(object):

        def __init__(self, pkt):
            self.pktlist = []
            self.stream_id = L4TcpReassembler.TCPStream.stream_id(pkt)

            if not pkt[TCP].flags & L4TcpReassembler.TCPFlags.SYN:
                raise Exception("NOT THE BEGINNING OF A STREAM: %s" % repr(self.stream_id))

            self.syn = pkt[TCP]
            self.syn.payload = None   # strip payload
            self.initial_seq = pkt[TCP].seq

            self.last_seq = self.initial_seq
            self.relative_seq = 0

            self.mss = (option[1] for option in pkt[TCP].options if option[0] == "MSS").next()

        @staticmethod
        def stream_id(pkt):
            return pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport

        def process(self, pkt):
            self.last_seq = pkt[TCP].seq
            payload_size = len(pkt[TCP].payload)

            if payload_size < self.mss:
                # flush pktlist as [pkt stack, current_pkt]
                if len(self.pktlist) > 1:
                    # create fake packet
                    p_reassembled = pkt
                    del p_reassembled[IP].len
                    del p_reassembled[IP].chksum
                    del p_reassembled[TCP].chksum
                    #p_reassembled.name = "TCPReassembled"
                    p_reassembled[TCP].payload = ''.join(str(p[TCP].payload)
                                                         for p in self.pktlist) + str(p_reassembled[TCP].payload)
                    p_reassembled[TCP] = TCP(str(p_reassembled[TCP]))       # force re-dissect

                    self.pktlist = []
                    return p_reassembled
                # otherwise just return current pkt
                return pkt
            # segment size > track it
            self.pktlist.append(pkt)
            return None

        def __repr__(self, *args, **kwargs):
            return "<<TCPSTream: %s | mss=%s seq_init=%s seq_last=%s seq_diff=%s pktlist=%s>>" % (repr(
                self.stream_id),
                self.mss,
                self.initial_seq,
                self.last_seq,
                self.last_seq - self.initial_seq,
                self.pktlist)

    def __init__(self):
        # track streams
        self.streams = {}

    def get_stream(self, pkt):
        stream_id = L4TcpReassembler.TCPStream.stream_id(pkt)
        stream_obj = self.streams.get(stream_id)                # get stream tracker
        if not stream_obj:
            try:
                stream_obj = L4TcpReassembler.TCPStream(pkt)
                self.streams[stream_id] = stream_obj
            except:
                pass  # not a valid stream, or in the middle of a stream
        return stream_obj

    def reassemble(self, pktlist):
        """Defragment and Reassemble Streams
        """
        # defragment L3
        for pkt in defragment(pktlist):
            if not pkt.haslayer(TCP):
                # Not TCP, return
                yield pkt
                continue
            # get Stream object
            stream = self.get_stream(pkt)
            if not stream:
                continue
            p = stream.process(pkt)
            if not p:
                # assume stream not complete
                continue
            # assume stream complete
            yield p


class Sniffer(object):

    """ Sniffer()
        .rdpcap(pcap)
        or
        .sniff()
    """

    def __init__(self):
        self.ssl_session_map = {}
        self.exit_after_num_valid_packets = None
        self.valid_pkts = 0

    def _create_context(self, target, keyfile=None):
        self.target = target
        self.keyfile = keyfile

        session = ssl_tls_crypto.TLSSessionCtx()
        if keyfile:
            print ("* load servers privatekey for ciphertext decryption (RSA key only): %s" % keyfile)
            session.server_ctx.load_rsa_keys_from_file(keyfile)

            session.printed = False
            self.ssl_session_map[target] = session
        else:
            print ("!! missing private key")

    def process_ssl(self, p):
        if not p.haslayer(SSL):
            return
        session = self.ssl_session_map.get(
            (p[IP].dst, p[TCP].dport)) or self.ssl_session_map.get(
            (p[IP].src, p[TCP].sport))
        if not session:
            print (
                "|   %-16s:%-5d => %-16s:%-5d | %s" % (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport, repr(p[SSL])))
            return
        p_ssl = p[SSL]
        source = (p[IP].src, p[TCP].sport)

        if p_ssl.haslayer(SSLv2Record):
            print ("SSLv2 not supported - skipping..", repr(p))
            return


        if p_ssl.haslayer(TLSServerHello):
            session.printed = False
            session.master_secret = None
            session.match_server = source
            # reset the session and print it next time
        if p_ssl.haslayer(TLSClientHello):
            session.match_client = source

        session.insert(p_ssl)

        if session.master_secret and session.printed == False:
            print (session)
            session.printed = True

        print (
            "|   %-16s:%-5d => %-16s:%-5d | %s" % (p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport, repr(p_ssl)))
        if p.haslayer(TLSCiphertext) or (p.haslayer(TLSAlert) and p.haslayer(Raw)):
            if source == session.match_client:
                session.set_mode(server=True)
            elif source == session.match_server:
                session.set_mode(client=True)
            else:
                Exception("src packet mismatch: %s" % repr(source))
            try:
                p = SSL(str(p_ssl), ctx=session)
                print ("|-> %-48s | %s" % ("decrypted record", repr(p)))
            except ValueError as ve:
                print ("Exception:", repr(ve))

        self.valid_pkts += 1
        if self.exit_after_num_valid_packets and self.valid_pkts > self.exit_after_num_valid_packets:
            sys.exit(0)        

    def sniff(self, target, keyfile=None, iface=None):
        self._tcp_reassembler = L4TcpReassembler()

        def reassemble(p):
            for rp in (pkt for pkt in self._tcp_reassembler.reassemble([p]) if pkt.haslayer(SSL)):
                self.process_ssl(rp)
        if iface:
            conf.iface = iface
        self._create_context(target=target, keyfile=keyfile)
        while True:
            sniff(filter="host %s and tcp port %d" % (target[0], target[1]), prn=reassemble, store=0, timeout=3)

    def rdpcap(self, target, keyfile, pcap):
        self._create_context(target=target, keyfile=keyfile)
        for p in (pkt for pkt in L4TcpReassembler().reassemble(rdpcap(pcap)) if pkt.haslayer(SSL)):
            self.process_ssl(p)


def main(target, pcap=None, iface=None, keyfile=None, num_pkts=None):
    sniffer = Sniffer()
    sniffer.exit_after_num_valid_packets = num_pkts
    if pcap:
        print ("* pcap ready!")
        # pcap mainloop
        sniffer.rdpcap(target=target, keyfile=keyfile, pcap=pcap)
    else:
        print ("* sniffer ready!")
        # sniffer mainloop
        sniffer.sniff(target=target, keyfile=keyfile, iface=iface)

if __name__ == "__main__":
    if len(sys.argv) <= 3:
        print ("USAGE: <host> <port> <inteface or pcap> <keyfile> <abort_after_num_packets>")
        print ("\navailable interfaces:")
        for i in get_if_list():
            print ("   * %s" % i)
        print ("* default")
        exit(1)

    pcap = None
    iface = None
    keyfile = None
    num_pkts = None
    if len(sys.argv) > 3:
        if os.path.isfile(sys.argv[3]):
            pcap = sys.argv[3]
        elif sys.argv[3] in get_if_list():
            iface = sys.argv[3]
        else:
            raise Exception("Unknown interface or invalid path to pcap.")
    if len(sys.argv) > 4:
        if not os.path.isfile(sys.argv[4]):
            raise Exception("PrivateKey File not Found! %s" % sys.argv[4])
        keyfile = sys.argv[4]

    if len(sys.argv) > 5:
        num_pkts = int(sys.argv[5])

    main((sys.argv[1], int(sys.argv[2])), iface=iface, pcap=pcap, keyfile=keyfile, num_pkts=num_pkts)
