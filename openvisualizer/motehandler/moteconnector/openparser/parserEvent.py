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


log = logging.getLogger('ParserEvent')
log.setLevel(logging.INFO)
log.addHandler(logging.NullHandler())


class ParserEvent(parser.Parser):
    HEADER_LENGTH = 2

    buffer = ""


    def __init__(self):

        # log
        log.debug('create instance')

        # initialize parent class
        super(ParserEvent, self).__init__(self.HEADER_LENGTH)

        print("creation")

        # create the db
        try:
            directory = os.path.dirname(log.handlers[0].baseFilename)
            global dbfilename
            dbfilename = directory+'/openv_events.db'
            log.verbose("created the sqlite db {0}".format(dbfilename))
            print("created the sqlite db {0}".format(dbfilename))
            
            if (os.path.exists(dbfilename)):
                os.remove(dbfilename)
            conn = sqlite3.connect(dbfilename)

            # Create tables
            c = conn.cursor()
            #packet reception / transmission
            c.execute('''CREATE TABLE pkt
            (asn int, moteid text, event text, src text, dest text, type text, validrx int, slotOffset int, channelOffset int, priority int, nb_retx int, lqi int, rssi int, crc int)''')
            
             #schedule modification
            c.execute('''CREATE TABLE schedule
            (asn int, moteid text, event text, neighbor text, neighbor2 text, type text, shared int, anycast int,  priority int, slotOffset int, channelOffset int)''')
            
            #RPL changes
            c.execute('''CREATE TABLE rpl
            (asn int, moteid text, event text, addr1 text, addr2 text)''')
            
            conn.commit()
            conn.close()
        except AttributeError:
            print("no LogHandler for parserEvent: we cannot store the events in a sqlite DB")
        except:
            print("Unexpected error:", sys.exc_info()[0])

        
         
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
    def eventPktString(event):
        if (event == 1):
            return("RX")
        if (event == 2):
            return("TX")
        return("UNKNOWN")
    
    #type of packet to string
    @staticmethod
    def typePacketString(type):
        if (type == 0):
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
        
     #type of event schedule modification to string
    @staticmethod
    def eventScheduleString(event):
        if (event == 1):
            return("ADD")
        if (event == 2):
            return("DEL")
            return("UNDEFINED")
        return("UNKNOWN")

    #type of cell to string
    @staticmethod
    def typeCellString(type):
        if (type == 0):
            return("OFF")
        if (type == 1):
            return("TX")
        if (type == 2):
            return("RX")
        if (type == 3):
            return("TXRX")
        return("UNKNOWN")
        
    #type of RPL event to string
    @staticmethod
    def eventRPLString(type):
        if (type == 1):
            return("PARENT_CHANGE")
        if (type == 2):
            return("SECONDPARENT_CHANGE")
        return("UNKNOWN")
                    
  
    def parse_input(self, data):

        # log
        log.debug('received stat {0}'.format(data))
        
        mote_id = ParserEvent.bytes_to_addr(data[0:2])  # short addr (16bits)
        asn = ParserEvent.bytes_to_string(data[2:7])    # asn
        typeStat = data[7]                                 # type
           
        #handle each statistic independently
        #PKT TRANSMISSION / RECEPTION
        if (typeStat == 1):
            if (len(data) != 42):
                log.error("Incorrect length for a stat_pkt in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        
            moteid          = ParserEvent.bytes_to_addr(data[8:16])
            event           = ParserEvent.eventPktString(data[16])
            
            src             = ParserEvent.bytes_to_addr(data[17:25])
            dest            = ParserEvent.bytes_to_addr(data[25:33])
            validRx         = data[33]
            type            = ParserEvent.typePacketString(data[34])
            slotOffset      = data[35]
            channelOffset   = data[36]
            priority        = data[37]
            nb_retx         = data[38]
            lqi             = data[39]
            rssi            = data[40]
            crc             = data[41]
            
            if 'dbfilename' in globals():
                conn = sqlite3.connect(dbfilename)
                c = conn.cursor()
                c.execute("""INSERT INTO pkt (asn,moteid,event,src,dest,type,validrx, slotOffset,channelOffset,priority,nb_retx,lqi,rssi,crc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (asn, moteid, event, src, dest, type, validRx, slotOffset, channelOffset, priority, nb_retx, lqi, rssi, crc))
                conn.commit()
                conn.close()
            else:
                log.info("1 {0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13}".format(asn, moteid, event, src, dest, type, validRx, slotOffset, channelOffset, priority, nb_retx, lqi, rssi, crc))
                                
        elif (typeStat == 2):
            if (len(data) != 39):
                log.error("Incorrect length for a stat_schedule in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        
            moteid          = ParserEvent.bytes_to_addr(data[8:16])
            event           = ParserEvent.eventScheduleString(data[16])
            neighbor        = ParserEvent.bytes_to_addr(data[17:25])
            neighbor2       = ParserEvent.bytes_to_addr(data[25:33])
            type            = ParserEvent.typeCellString(data[33])
            shared          = data[34]
            anycast         = data[35]
            priority        = data[36]
            slotOffset      = data[37]
            channelOffset   = data[38]
            

            if 'dbfilename' in globals():
                conn = sqlite3.connect(dbfilename)
                c = conn.cursor()
                c.execute("""INSERT INTO schedule (asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset,channelOffset) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset, channelOffset))
                conn.commit()
                conn.close()
            else:
                log.info("2 {0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10}".format(asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset, channelOffset))
            
        elif (typeStat == 3):
            if (len(data) != 33):
                log.error("Incorrect length for a stat_rpl in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        
            moteid          = ParserEvent.bytes_to_addr(data[8:16])
            event           = ParserEvent.eventRPLString(data[16])
            addr1           = ParserEvent.bytes_to_addr(data[17:25])
            addr2           = ParserEvent.bytes_to_addr(data[25:33])

            if 'dbfilename' in globals():
                conn = sqlite3.connect(dbfilename)
                c = conn.cursor()
                c.execute("""INSERT INTO rpl (asn, moteid, event, addr1, addr2) VALUES (?,?,?,?,?)""", (asn, moteid, event, addr1, addr2))
                conn.commit()
                conn.close()
            else:
                log.info("3 {0} {1} {2} {3} {4}".format(asn, moteid, event, addr1, addr2))
                
        
        else:
            log.error('unknown statistic type={0}'.format(typeStat))
           
        
        #sys.stdout.write("{0} {1} ".format(mote_id, asn));
        #sys.stdout.write("{}".format("".join([chr(c) for c in data[7:]])))
        #sys.stdout.flush()
          
       
        
        # everything was fine
        return 'error', data

