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
            (asn int, moteid text, event text, src text, dest text, type text, validrx int, slotOffset int, channelOffset int, priority int, numTxAttempts int, lqi int, rssi int, crc int)''')
            
             #schedule modification
            c.execute('''CREATE TABLE schedule
            (asn int, moteid text, event text, neighbor text, neighbor2 text, type text, shared int, anycast int,  priority int, slotOffset int, channelOffset int)''')
            
            #RPL changes
            c.execute('''CREATE TABLE rpl
            (asn int, moteid text, event text, addr1 text, addr2 text)''')
            
           
            #SIXTOP
            c.execute('''CREATE TABLE sixtop
            (asn int, moteid text, seqNum int, event text, neighbor text, neighbor2 text,
            type int, command int, code int, numCells int)''')
            
            #SIXTOP STATE CHANGED
            c.execute('''CREATE TABLE sixtopStates
            (asn int, moteid text, state text)''')
                        
            #FRAME INTERRUPT
            c.execute('''CREATE TABLE frameInterrupt
            (asn int, moteid text, intrpt text, state text)''')
       
               #end
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
        return(str(event))

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
        return(str(type))
        
    #type of RPL event to string
    @staticmethod
    def eventRPLString(type):
        if (type == 1):
            return("PARENT_CHANGE")
        if (type == 2):
            return("SECONDPARENT_CHANGE")
        return(str(type))
                    
     #type of SIXTOP event to string
    @staticmethod
    def eventSixtopString(type):
        if (type == 1):
            return("SENDDONE")
        if (type == 2):
            return("REQ_CREATE")
        if (type == 3):
            return("RECEIVED")
        if (type == 4):
            return("SEQNUM_INCR")
        if (type == 5):
            return("SEQNUM_RESET")
        if (type == 6):
            return("CLEAR_BADPARENT")
        return(str(type))


    @staticmethod
    def typeSixtopString(type):
        if (type == 0):
            return("REQ")
        if (type == 1):
            return("REP")
        if (type == 2):
            return("CONF")
        if (type == 255):
            return("NONE")
        return(str(type))

    @staticmethod
    def codeSixtopString(code):
        if (code == 0):
            return("IANA_6TOP_RC_SUCCESS")
        if (code == 1):
            return("IANA_6TOP_RC_EOL")
        if (code == 2):
            return("IANA_6TOP_RC_ERROR")
        if (code == 3):
            return("IANA_6TOP_RC_RESET")
        if (code == 4):
            return("IANA_6TOP_RC_VER_ERR")
        if (code == 5):
            return("IANA_6TOP_RC_SFID_ERR")
        if (code == 6):
            return("IANA_6TOP_RC_SEQNUM_ERR")
        if (code == 7):
            return("IANA_6TOP_RC_CELLLIST_ERR")
        if (code == 8):
            return("IANA_6TOP_RC_BUSY")
        if (code == 9):
            return("IANA_6TOP_RC_LOCKED")
        if (code == 255):
            return("NONE")
        return(str(code))

    @staticmethod
    def commandSixtopString(code):
        if (code == 0):
            return("IANA_6TOP_CMD_NONE")
        if (code == 1):
            return("IANA_6TOP_CMD_ADD")
        if (code == 2):
            return("IANA_6TOP_CMD_DELETE")
        if (code == 3):
            return("IANA_6TOP_CMD_RELOCATE")
        if (code == 4):
            return("IANA_6TOP_CMD_COUNT")
        if (code == 5):
            return("IANA_6TOP_CMD_LIST")
        if (code == 6):
            return("IANA_6TOP_CMD_SIGNAL")
        if (code == 7):
            return("IANA_6TOP_CMD_CLEAR")
        if (code == 255):
            return("NONE")
        return(str(code))
        
    @staticmethod
    def sixtopStateString(code):
        if (code == 0):
            return("IDLE")
        if (code == 1):
            return("WAIT_ADDREQUEST_SENDDONE")
        if (code == 2):
            return("WAIT_DELETEREQUEST_SENDDONE")
        if (code == 3):
            return("WAIT_RELOCATEREQUEST_SENDDONE")
        if (code == 4):
            return("WAIT_COUNTREQUEST_SENDDONE")
        if (code == 5):
            return("WAIT_LISTREQUEST_SENDDONE")
        if (code == 6):
            return("WAIT_CLEARREQUEST_SENDDONE")
        if (code == 7):
            return("WAIT_ADDRESPONSE")
        if (code == 8):
            return("WAIT_DELETERESPONSE")
        if (code == 9):
            return("WAIT_RELOCATERESPONSE")
        if (code == 10):
            return("WAIT_COUNTRESPONSE")
        if (code == 11):
            return("WAIT_LISTRESPONSE")
        if (code == 12):
            return("WAIT_CLEARRESPONSE")
        if (code == 13):
            return("WAIT_ADDREQUEST")
        if (code == 255):
            return("NONE")
        return(str(code))
        
    @staticmethod
    def frameInterruptString(code):
        if (code == 0):
            return("STARTOFFRAME")
        if (code == 1):
            return("ENDOFFRAME")
        return(str(code))       

    @staticmethod
    def ieee154eStateString(code):
        if (code == 0):
            return("S_SLEEP")
        if (code == 1):
            return("S_SYNCLISTEN")
        if (code == 2):
            return("S_SYNCRX")
        if (code == 3):
            return("S_SYNCPROC")
        if (code == 4):
            return("S_TXDATAOFFSET")
        if (code == 5):
            return("S_TXDATAPREPARE")
        if (code == 6):
            return("S_TXDATAREADY")
        if (code == 7):
            return("S_TXDATADELAY")
        if (code == 8):
            return("S_TXDATA")
        if (code == 9):
            return("S_RXACKOFFSET")
        if (code == 10):
            return("S_RXACKPREPARE")
        if (code == 11):
            return("S_RXACKREADY")
        if (code == 12):
            return("S_RXACKLISTEN")
        if (code == 13):
            return("S_RXACK")
        if (code == 14):
            return("S_TXPROC")
        if (code == 15):
            return("S_RXDATAOFFSET")
        if (code == 16):
            return("S_RXDATAPREPARE")
        if (code == 17):
            return("S_RXDATAREADY")
        if (code == 18):
            return("S_RXDATALISTEN")
        if (code == 19):
            return("S_RXDATA")
        if (code == 20):
            return("S_TXACKOFFSET")
        if (code == 21):
            return("S_TXACKPREPARE")
        if (code == 22):
            return("S_TXACKREADY")
        if (code == 23):
            return("S_TXACKDELAY")
        if (code == 24):
            return("S_TXACK")
        if (code == 25):
            return("S_RXPROC")
        if (code == 26):
            return("S_CCATRIGGER")
        if (code == 27):
            return("S_CCATRIGGERED")
        if (code == 255):
            return("NONE")
        return(str(code))
     
     

    def parse_input(self, data):

        # log
        log.debug('received stat {0}'.format(data))
        
        #incorrect length
        if (len(data) < 14):
            log.error("Invalid length for this event: {0}<14", len(data))
            return
        
        asn = ParserEvent.bytes_to_string(data[0:5])    # asn
        typeStat = data[5]
        moteid   = ParserEvent.bytes_to_addr(data[6:14])                           # type
           
        #handle each statistic independently
        #PKT TRANSMISSION / RECEPTION
        if (typeStat == 1):
            if (len(data) != 40):
                log.error("Incorrect length for a stat_pkt in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        

            event           = ParserEvent.eventPktString(data[14])
            src             = ParserEvent.bytes_to_addr(data[15:23])
            dest            = ParserEvent.bytes_to_addr(data[23:31])
            validRx         = data[31]
            type            = ParserEvent.typePacketString(data[32])
            slotOffset      = data[33]
            channelOffset   = data[34]
            priority        = data[35]
            numTxAttempts   = data[36]
            lqi             = data[37]
            rssi            = data[38]
            crc             = data[39]
            
            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO pkt (asn,moteid,event,src,dest,type,validrx, slotOffset,channelOffset,priority,numTxAttempts,lqi,rssi,crc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (asn, moteid, event, src, dest, type, validRx, slotOffset, channelOffset, priority, numTxAttempts, lqi, rssi, crc))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("1 {0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10} {11} {12} {13}".format(asn, moteid, event, src, dest, type, validRx, slotOffset, channelOffset, priority, numTxAttempts, lqi, rssi, crc))
         
        #SCHEDULE
        elif (typeStat == 2):
            if (len(data) != 37):
                log.error("Incorrect length for a stat_schedule in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        
            event           = ParserEvent.eventScheduleString(data[14])
            neighbor        = ParserEvent.bytes_to_addr(data[15:23])
            neighbor2       = ParserEvent.bytes_to_addr(data[23:31])
            type            = ParserEvent.typeCellString(data[31])
            shared          = data[32]
            anycast         = data[33]
            priority        = data[34]
            slotOffset      = data[35]
            channelOffset   = data[36]
            

            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO schedule (asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset,channelOffset) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset, channelOffset))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("2 {0} {1} {2} {3} {4} {5} {6} {7} {8} {9} {10}".format(asn, moteid, event, neighbor, neighbor2, type, shared, anycast, priority, slotOffset, channelOffset))
            
        #RPL
        elif (typeStat == 3):
            if (len(data) != 31):
                log.error("Incorrect length for a stat_rpl in ParserEvent.py ({0})".format(len(data)))
                return 'error', data
        
            event           = ParserEvent.eventRPLString(data[14])
            addr1           = ParserEvent.bytes_to_addr(data[15:23])
            addr2           = ParserEvent.bytes_to_addr(data[23:31])

            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO rpl (asn, moteid, event, addr1, addr2) VALUES (?,?,?,?,?)""", (asn, moteid, event, addr1, addr2))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("3 {0} {1} {2} {3} {4}".format(asn, moteid, event, addr1, addr2))
                
                
        #SIXTOP
        elif (typeStat == 4):
            if (len(data) != 36):
                log.error("Incorrect length for a stat_sixtop in ParserEvent.py ({0})".format(len(data)))
                return 'error', data

            event           = ParserEvent.eventSixtopString(data[14])
            neighbor        = ParserEvent.bytes_to_addr(data[15:23])
            neighbor2       = ParserEvent.bytes_to_addr(data[23:31])
            type            = ParserEvent.typeSixtopString(data[31])
            code            = ParserEvent.codeSixtopString(data[32])
            command         = ParserEvent.commandSixtopString(data[33])
            seqNum          = data[34]
            numCells        = data[35]
            
            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO sixtop (asn, moteid, event, neighbor, neighbor2, type, code, command, seqNum, numCells) VALUES (?,?,?,?,?,?,?,?,?,?)""", (asn, moteid, event, neighbor, neighbor2, type, code, command, seqNum, numCells))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("4 {0} {1} {2} {3} {4} {5} {6} {7} {8} {9}".format(asn, moteid, event, neighbor, neighbor2, type, code, command, seqNum, numCells))
                
        #SIXTOP STATE CHANGED
        elif (typeStat == 5):
            if (len(data) != 15):
                log.error("Incorrect length for a stat_sixtopchangeState in ParserEvent.py ({0})".format(len(data)))
                return 'error', data

            state           = ParserEvent.sixtopStateString(data[14])
            
            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO sixtopStates (asn, moteid, state) VALUES (?,?,?)""", (asn, moteid, state))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("5 {0} {1} {2}".format(asn, moteid, state))
                
        #SIXTOP STATE CHANGED
        elif (typeStat == 6):
            if (len(data) != 16):
                log.error("Incorrect length for a frameInterrupt in ParserEvent.py ({0})".format(len(data)))
                return 'error', data

            intrpt = ParserEvent.frameInterruptString(data[14])
            state  = ParserEvent.ieee154eStateString(data[15])

            if 'dbfilename' in globals():
                try:
                    conn = sqlite3.connect(dbfilename)
                    c = conn.cursor()
                    c.execute("""INSERT INTO frameInterrupt (asn, moteid, intrpt, state) VALUES (?,?,?,?)""", (asn, moteid, intrpt, state))
                    conn.commit()
                    conn.close()
                except:
                    print("Unexpected error:", sys.exc_info()[0])

            else:
                log.info("5 {0} {1} {2} {3}".format(asn, moteid, intrpt, state))
                

            
        else:
            log.error('unknown statistic type={0}'.format(typeStat))
           
        
        #sys.stdout.write("{0} {1} ".format(mote_id, asn));
        #sys.stdout.write("{}".format("".join([chr(c) for c in data[7:]])))
        #sys.stdout.flush()
          
       
        
        # everything was fine
        return 'error', data

