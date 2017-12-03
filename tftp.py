#! /usr/bin/python

import sys,socket,struct,select, time

BLOCK_SIZE= 512

OPCODE_RRQ=   1
OPCODE_WRQ=   2
OPCODE_DATA=  3
OPCODE_ACK=   4
OPCODE_ERR=   5

MODE_NETASCII= "netascii"
MODE_OCTET=    "octet"
MODE_MAIL=     "mail"

TFTP_PORT= 69

# Timeout in seconds
TFTP_TIMEOUT= 2

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
    return struct.pack("!H", OPCODE_RRQ) + filename + '\0' + mode + '\0'

def make_packet_wrq(filename, mode):
    return "" # TODO

def make_packet_data(blocknr, data):
    return "" # TODO

def make_packet_ack(blocknr):
    return "" # TODO

def make_packet_err(errcode, errmsg):
    return "" # TODO

def parse_packet(msg):
    """This function parses a recieved packet and returns a tuple where the
        first value is the opcode as an integer and the following values are
        the other parameters of the packets in python data types"""
    opcode = struct.unpack("!H", msg[:2])[0]
    if opcode == OPCODE_RRQ:
        l = msg[2:].split('\0')
        if len(l) != 3:
            return None
        return opcode, l[1], l[2]
    elif opcode == OPCODE_DATA:
        l = msg[4:].split('\0')
        nr = struct.unpack("!H", msg[2:4])[0]
        return opcode,nr, l[0]
    elif opcode == OPCODE_WRQ:
        # TDOO
        return opcode, # something here
    # TODO
    return None

def tftp_transfer(fd, hostname, direction):
    # Implement this function
    
    # Open socket interface
    
    # Check if we are putting a file or getting a file and send
    #  the corresponding request.
  
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Put or get the file, block by block, in a loop.
   # sock.connect((hostname, TFTP_PORT))
    sock.sendto(make_packet_rrq("big.txt", MODE_OCTET),(hostname, TFTP_PORT))
    print "connected"
    
    blockNr = 1
    while True:
        (chunk, (raddress, rport)) = sock.recvfrom(65536)

        
        parsed = parse_packet(chunk)
        print parsed
        print blockNr
        if parsed[0] == OPCODE_DATA and blockNr == parsed[1]:
            print "writing data to file"
            blockNr = blockNr + 1
            fd.write(parsed[2])
            if (len(parsed[2]) < BLOCK_SIZE):
                print "last block"
                break
        
        

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