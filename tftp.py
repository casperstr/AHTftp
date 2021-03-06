#! /usr/bin/python

import sys
import socket
import struct
import select
import time

BLOCK_SIZE = 512

OPCODE_RRQ = 1
OPCODE_WRQ = 2
OPCODE_DATA = 3
OPCODE_ACK = 4
OPCODE_ERR = 5

MODE_NETASCII = "netascii"
MODE_OCTET = "octet"
MODE_MAIL = "mail"

TFTP_PORT = 69

# Timeout in seconds
TFTP_TIMEOUT = 2

ERROR_CODES = ["Undef",
               "File not found",
               "Access violation",
               "Disk full or allocation exceeded",
               "Illegal TFTP operation",
               "Unknown transfer ID",
               "File already exists",
               "No such user"]

# Internal defines
TFTP_GET = 1
TFTP_PUT = 2


def make_packet_rrq(filename, mode):
    # Note the exclamation mark in the format string to pack(). What is it for?

    # Answer: ! specifies that the byte order is network = {big-endian}.
    # H = unsigned short.
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'


def make_packet_wrq(filename, mode):
    # Write onto foreign file system
    # TODO
    return struct.pack("!H", OPCODE_WRQ) + filename + '\0' + mode + '\0'


def make_packet_data(blocknr, data):
    return struct.pack("!HH", OPCODE_DATA, blocknr) + data


def make_packet_ack(blocknr):
    return struct.pack("!H", OPCODE_ACK) + struct.pack("!H", blocknr)


def make_packet_err(errcode, errmsg):
    return struct.pack("!HH", OPCODE_ERR, errcode) + errmsg + '\0'  # TODO


def parse_packet(msg):
    """This function parses a recieved packet and returns a tuple where the
        first value is the opcode as an integer and the following values are
        the other parameters of the packets in python data types"""
    opcode = struct.unpack("!H", msg[:2])[0]
    if opcode == OPCODE_RRQ or opcode == OPCODE_WRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_DATA:
        nr = struct.unpack("!H", msg[2:4])[0]
        return opcode, nr, msg[4:]
    elif opcode == OPCODE_ERR:
        l = msg[4:].split('\0')
        errorCode = struct.unpack("!H", msg[2:4])[0]
        return opcode, errorCode, l[0]
    elif opcode == OPCODE_ACK:
        return opcode, struct.unpack("!H", msg[2:4])[0]
    return None


def upload(fd, hostname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)
    lastPacket = make_packet_wrq(fd.name, MODE_OCTET)
    sock.sendto(lastPacket, (hostname, TFTP_PORT))
    print "connected"
    block_nr = 0
    tid = TFTP_PORT
    while True:
        try:
            (chunk, (raddress, rport)) = sock.recvfrom(128 * BLOCK_SIZE)
        except socket.timeout:
            print "TIMEOUT resending"
            sock.sendto(lastPacket, (hostname, tid))
            continue

        if block_nr == 0:
            tid = rport

        parsed = parse_packet(chunk)
        if parsed[0] == OPCODE_ACK and parsed[1] == block_nr:
            data = fd.read(BLOCK_SIZE)
            if len(data) == 0:
                print "last packet"
                break
            block_nr = block_nr + 1
            lastPacket = make_packet_data(block_nr, data)
            sock.sendto(lastPacket, (hostname, tid))

        elif parsed[0] == OPCODE_ERR:
            print "Error: " + ERROR_CODES[parsed[1]]
            break
        else:
            break


def download(fd, hostname):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TFTP_TIMEOUT)

    print "connected"
    block_nr = 1
    tid = TFTP_PORT
    t = time.time()
    lastPacket = make_packet_rrq(fd.name, MODE_OCTET)
    sock.sendto(lastPacket, (hostname, TFTP_PORT))

    while True:
        try:
            (chunk, (raddress, rport)) = sock.recvfrom(128 * BLOCK_SIZE)
        except socket.timeout:
            print "TIMEOUT resending"  
            sock.sendto(lastPacket, (hostname, tid))
            continue
        if block_nr == 1:
            tid = rport

        if rport != tid:
            print "Did not expect data from that tid. Ignoring."
        else:
            parsed = parse_packet(chunk)
            if parsed[0] == OPCODE_DATA and block_nr == parsed[1]:
                lastPacket = make_packet_ack(block_nr)
                sock.sendto(lastPacket, (hostname, tid))
                print (block_nr * BLOCK_SIZE * 0.001 / (time.time() - t))
                block_nr = block_nr + 1
                fd.write(parsed[2])
                if (len(parsed[2]) < BLOCK_SIZE):
                    print "last block"
                    break
            elif parsed[0] == OPCODE_ERR:
                print "Error: " + ERROR_CODES[parsed[1]]
                break


def tftp_transfer(fd, hostname, direction):
    # Implement this function
    if direction == TFTP_GET:
        download(fd, hostname)
    elif direction == TFTP_PUT:
        upload(fd, hostname)
    # Open socket interface

    # Check if we are putting a file or getting a file and send
    #  the corresponding request.

        # Wait for packet, write the data to the filedescriptor or
        # read the next block from the file. Send new packet to server.
        # Don't forget to deal with timeouts and received error packets


def usage():
    """Print the usage on stderr and quit with error code"""
    sys.stderr.write("Usage: %s [-g|-p] FILE HOST\n" % sys.argv[0])
    sys.exit(1)


def main():
    # No need to change this function
    direction = TFTP_GET
    if len(sys.argv) == 3:
        filename = sys.argv[1]
        hostname = sys.argv[2]
    elif len(sys.argv) == 4:
        if sys.argv[1] == "-g":
            direction = TFTP_GET
        elif sys.argv[1] == "-p":
            direction = TFTP_PUT
        else:
            usage()
            return
        filename = sys.argv[2]
        hostname = sys.argv[3]
    else:
        usage()
        return

    if direction == TFTP_GET:
        print "Transfer file %s from host %s" % (filename, hostname)
    else:
        print "Transfer file %s to host %s" % (filename, hostname)

    try:
        if direction == TFTP_GET:
            fd = open(filename, "wb")
        else:
            fd = open(filename, "rb")
    except IOError as e:
        sys.stderr.write("File error (%s): %s\n" % (filename, e.strerror))
        sys.exit(2)

    tftp_transfer(fd, hostname, direction)
    fd.close()


if __name__ == "__main__":
    main()
