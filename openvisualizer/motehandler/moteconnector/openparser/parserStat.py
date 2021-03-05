# Copyright (c) 2017, CNRS.
# All rights reserved.
#
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

import logging
import sys
import sqlite3

from openvisualizer.motehandler.moteconnector.openparser import parser
from openvisualizer.motehandler.moteconnector.openparser.parserexception import ParserException
from openvisualizer.utils import format_buf


log = logging.getLogger('ParserStat')
log.setLevel(logging.INFO)
log.addHandler(logging.NullHandler())


class ParserStat(parser.Parser):
    HEADER_LENGTH = 2

    buffer = ""


    def __init__(self):

        # log
        log.debug('create instance')

        # initialize parent class
        super(ParserStat, self).__init__(self.HEADER_LENGTH)

        # create the db
        directory = os.path.dirname(log.handlers[0].baseFilename)
        global dbfilename
        dbfilename = directory+'/openv_events.db'
        log.info("created the sqlite db {0}".format(dbfilename))
        if (os.path.exists(dbfilename)):
           os.remove(dbfilename)
        conn = sqlite3.connect(dbfilename)

        # Create tables
        c = conn.cursor()
        c.execute('''CREATE TABLE pkt
             (asn integer, src text, dest text, mode text, type text, validrx int, slotOffset int, channelOffset int, priority int, nb_retx int, lqi int, rssi int, crc int)''')
        conn.commit()
        conn.close()
         
    # returns a string with the decimal value of a uint16_t
    @staticmethod
    def bytes_to_string(bytestring):
        string = ''
        i = 0

        for byte in bytestring:
            string = format(eval('{0} + {1} * 256 ** {2}'.format(string, byte, i)))
            i = i + 1

        return string

    @staticmethod
    def bytes_to_addr(bytestring):
        string = ''

        for byte in bytestring:
            string = string + '{:02x}'.format(byte)

        return string
        
    #mode to string
    @staticmethod
    def modeString(mode):
        if (mode == 1):
            return("RX")
        if (mode == 2):
            return("TX")
        return("UNKNOWN")
    
    #type to string
    @staticmethod
    def typeString(type):
        if (type == 1):
            return("BEACON")
        if (type == 1):
            return("DATA")
        if (type == 2):
            return("ACK")
        if (type == 3):
            return("CMD")
        if (type == 5):
            return("UNDEFINED")
        return("UNKNOWN")

    
    def parse_input(self, data):

        # log
        log.debug('received stat {0}'.format(data))
        
        mote_id = ParserStat.bytes_to_addr(data[0:2])  # short addr (16bits)
        asn = ParserStat.bytes_to_string(data[2:7])    # asn
        typeStat = data[7]                                 # type
           
        #handle each statistic independently
        if (typeStat == 1):
            if (len(data) != 34):
                log.error("Incorrect length for a stat_pkt in ParserStat.py ({0})".format(len(data)))
                return 'error', data
        
            src             = ParserStat.bytes_to_addr(data[8:16])
            dest            = ParserStat.bytes_to_addr(data[16:24])
            mode            = ParserStat.modeString(data[24])
            validRx         = data[25]
            type            = ParserStat.typeString(data[26])
            slotOffset      = data[27]
            channelOffset   = data[28]
            priority        = data[29]
            nb_retx         = data[30]
            lqi             = data[31]
            rssi            = data[32]
            crc             = data[33]

            conn = sqlite3.connect(dbfilename)
            c = conn.cursor()
            c.execute("""INSERT INTO pkt (asn,src,dest,mode,type,validrx, slotOffset,channelOffset,priority,nb_retx,lqi,rssi,crc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (asn, src, dest, mode, type, validRx, slotOffset, channelOffset, priority, nb_retx, lqi, rssi, crc))
            conn.commit()
            conn.close()
            
        else:
            log.debug('unknown statistic type={0}'.format(typeStat))

        
        #sys.stdout.write("{0} {1} ".format(mote_id, asn));
        #sys.stdout.write("{}".format("".join([chr(c) for c in data[7:]])))
        #sys.stdout.flush()
          
       
        
        # everything was fine
        return 'error', data

