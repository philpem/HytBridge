from enum import Enum
import logging
import struct

logger = logging.getLogger('ADK')
logger.setLevel(logging.WARNING)


class CallType(Enum):           # ADKCoreEngine_CLR/CallType.cs
    PRIVATE             = 0             # Private call
    GROUP               = 1             # Group call
    ALL                 = 2             # All call
    EMERGENCY_GROUP     = 3
    REMOTE_MONITOR      = 4
    PRIORITY_PRIVATE    = 5
    PRIORITY_GROUP      = 6
    PRIORITY_ALL        = 7


class TxCallStatus(Enum):       # Only used by B845 (Broadcast status report), which ADK doesn't seem to use
    STARTGROUP  = 0      # Start of group call voice traffic
    ENDGROUP    = 1      # End of group call voice traffic (doesn't end the call)

    ENDCALL    = 4      # End of a call (cleardown)                       -- RU or RPTR initiated

    #TMP_5       = 5

    UNKNOWN6   = 6      # Start private call + voice (RPTR initiated)
    UNKNOWN7   = 7      # End private call (2/2) (RPTR initiated?)
    UNKNOWN8   = 8      # End private call (1/2) (RPTR initiated?)

    #TMP_START   = 9     # Text message start?


class PTTTarget(Enum):
    FRONT_PTT   = 0x03  # Front PTT switch
    BACK_PTT    = 0x1E  # Back PTT switch

class MessageHeader(Enum):
    RCP         = 0x02
    LP          = 0x08
    TMP         = 0x09
    RRS         = 0x11
    TP          = 0x12
    DTP         = 0x13
    DDS         = 0x14      # Data Delivery States


class DataError(Exception):
    # TODO expand this
    def __str__(self):
        return "(HYT) Error decoding packet"

class BadSignatureError(DataError):
    def __str__(self):
        return "(HYT) Bad signature"


def HRNPChecksum(data):
    csum = 0
    logger.debug('HRNPChecksum: %s' % (' '.join([hex(x) for x in data])))
    for i in range(0,len(data)-1,2):
        csum += struct.unpack('>H', data[i:i+2])[0]
    if (len(data) % 2) != 0:
        csum += data[-1]
    if (csum > 0xFFFF):
        csum = (csum & 0xFFFF) + (csum >> 16)
    return ~csum & 0xFFFF


class HytPacket(object):
    def factory(data):
        BUILDERS = {
                    0:      HytPacket_TxCtrl,
                    1:      HytPacket_Ack,
                    2:      HytPacket_KeepAlive,
                    5:      HytPacket_SynAck,
                    0x20:   HytPacket_QSO,
                    0x24:   HytPacket_Syn
                }

        # check the signature is correct
        if data[0:3] != b'\x32\x42\x00':
            raise BadSignatureError()   # This isn't a Hytera packet

        # packet type
        pktType = int(data[3])

        if pktType in BUILDERS:
            return BUILDERS[pktType](data)
        else:
            return HytPacket(data)

    def __init__(self, data):
        self.signature = data[0:3]
        self.pktType = int(data[3])
        self.seqid = struct.unpack('>H', data[4:6])[0]
        
    def __str__(self):
        try:
            n = "HYT %s" % self.__getattribute__('NAME')
        except:
            n = "** HYT unknown 0x%02X" % self.pktType
            
        x = "%s/%d seq=%d" % (n, self.pktType, self.seqid)
        return x


# TODO need to turn this into a factory -- build based on opcode
class HytPacket_TxCtrl(HytPacket):
    NAME="TxCtrl"
    def __init__(self, data):
        super().__init__(data)

        # Strip the Hytera base packet
        data = data[6:]

        # TxCtrl --
        #   MsgHdr      1 byte      Protocol identifier. OR 0x80 for "reliable" message
        #   Opcode      2 bytes     Protocol defined
        #   Num bytes   2 bytes     Number of payload bytes
        #   Payload     <n> bytes
        #   Checksum    1 byte      ~(Opcode + Num Bytes + Payload) + 0x33
        #   MsgEnd      1 byte      Always 0x03

        self.msgHdr     = MessageHeader(data[0] & 0x7F)
        self.reliable   = (data[0] & 0x80) != 0
        if self.msgHdr == MessageHeader.RCP:
            # For some reason RCP is little endian while everything else is big endian
            self.opcode     = struct.unpack("<H", data[1:3])[0]
            self.numBytes   = struct.unpack("<H", data[3:5])[0]
        else:
            self.opcode     = struct.unpack(">H", data[1:3])[0]
            self.numBytes   = struct.unpack(">H", data[3:5])[0]
        self.payload    = data[5:5+self.numBytes]

        logger.debug("HytPacket_TxCtrl Dump: ", ' '.join(["%02X"%x for x in data]), "(%d bytes)" % len(data))
        
        if self.reliable:
            s = "(reliable)"
        else:
            s = ""
        
        logger.debug("MH ", self.msgHdr, s)
        logger.debug("Op ", hex(self.opcode))
        logger.debug("by ", hex(self.numBytes))
        logger.debug("PL ", ' '.join(["%02X"%x for x in self.payload]))
        
        # check the checksum
        csum = (~(sum(data[1:5]) + sum(self.payload)) + 0x33) & 0xFF
        self.checksum   = data[-2]

        if csum != self.checksum:
            logger.error("checksum not correct -- want", csum, "got", self.checksum)
            raise DataError()

        # check the message end byte
        if data[-1] != 0x03:
            logger.error("trailer byte not correct")
            raise DataError()

        if self.msgHdr == MessageHeader.RCP:
            if self.opcode == 0x0041:
                # Op=0x41, PTT state
                self.pttTarget  = PTTTarget(self.payload[0])
                self.pttState   = self.payload[1]

            elif self.opcode == 0x0841:
                # Op=0x841 -- call request -- call type and destination id
                self.callType   = CallType(self.payload[0])
                self.destID     = struct.unpack('<I', self.payload[1:])[0]

            elif self.opcode == 0x00E7:
                # Op=0xE7 -- channel status request?
                self.statusTarget = self.payload[0]
                self.statusValueType = self.payload[1]

        elif self.msgHdr == MessageHeader.TMP:
            if self.opcode == 0xA1:
                # TMP 0x21: Text message

                # Payload [0..2] not identified

                # TODO Payload [3] -- some kind of ID
                self.tmp3 = self.payload[3]
                # TODO Payload [4] -- not ID'd, always 0x0A
                self.tmp4 = self.payload[4]
                # Payload [5..7] -- destination ID
                self.destID = struct.unpack('>I', b'\x00' + self.payload[5:8])[0]
                # TODO Payload [8] -- not ID'd, always 0x0A
                self.tmp8 = self.payload[8]
                # Payload [9..11] -- source ID
                self.srcID = struct.unpack('>I', b'\x00' + self.payload[9:12])[0]

                # Payload [12...] -- text message
                self.message = self.payload[12:].decode('utf-16le')
                

        #raise DataError()

    def __str__(self):
        if self.reliable:
            rel = " (reliable)"
        else:
            rel = ""

        if self.msgHdr == MessageHeader.TMP:
            if self.opcode == 0xA1:     # Private message transmission (B1 is group)
                return "HYT TMP seq=%d tmp3=0x%02X tmp4=0x%02X tmp8=0x%02X, 0xA1: text message%s, %d -> %d, '%s'" % (self.seqid, self.tmp3, self.tmp4, self.tmp8, rel, self.srcID, self.destID, self.message)
            else:
                return "HYT TMP seq=%d, unknown opcode 0x%04X%s, payload %s" % (self.seqid, self.opcode, rel, ' '.join(["%02X"%x for x in self.payload]))

        elif self.msgHdr == MessageHeader.RCP:
            if self.opcode == 0x0041:
                return "HYT RCP seq=%d (Keypress Req)  op=0x%04X, target=%s, ptt=%d" % (self.seqid, self.opcode, self.pttTarget, self.pttState)
            elif self.opcode == 0x0841:
                return "HYT RCP seq=%d (Call Req)      op=0x%04X, ct=%s, destid=%d" % (self.seqid, self.opcode, self.callType, self.destID)
            elif self.opcode == 0x8841:
                return "HYT RCP seq=%d (Call Rsp)      op=0x%04X, ct=%s, destid=%d" % (self.seqid, self.opcode, self.callType, self.destID)
            elif self.opcode == 0x00E7:
                return "HYT RCP seq=%d (Ch Status Req) op=0x%04X, tgt=%d, type=%d" % (self.seqid, self.opcode, self.statusTarget, self.statusValueType)
            else:
                return "HYT RCP seq=%d  op=0x%04X -- UNKNOWN OPCODE -- payload %s" % (self.seqid, self.opcode, ' '.join(["%02X"%x for x in self.payload]))

        else:
            return "HYT TxCtrl seq=%d  unknown variant, hdr %s, opcode 0x%04X" % (self.seqid, self.MsgHdr, self.opcode)


# TODO need to turn this into a factory -- build based on opcode
class HytPacket_QSO(HytPacket):
    NAME="QSO-data"
    def __init__(self, data):
        super().__init__(data)

        # Strip the Hytera base packet
        data = data[6:]

        # QSO-Data:
        logger.debug("QSO-Data: %s" % (' '.join(["%02X" % x for x in data])))

        self.msgHdr = data[0] & 0x7F
        self.reliable = (data[0] & 0x80) != 0

        # TODO: always 0x04 (address field length?)
        self.tmp1 = data[1]

        # Repeater ID
        self.rptID = struct.unpack('>I', data[2:6])[0]

        # TODO: always 0x04 0x01
        self.tmp6 = [int(x) for x in data[6:8]]

        # Timeslot ID
        self.timeslot = int(data[8])

        ####
        # A Hytera message packet begins here
        # Weirdly, it has a short ID and opcode

        # Get the message header byte
        self.msgHdr2 = MessageHeader(data[9])

        # Chop off the checksummed packet data (MsgHdr is excluded)
        data = data[10:]

        logger.debug("PacketData: %s" % (' '.join(["%02X" % x for x in data])))

        # Last byte of the Packetdata should be 0x03
        if data[-1] != 0x03:
            raise DataError()

        # Check the checksum
        csum = (~(sum(data[:-2])) + 0x33) & 0xFF
        self.checksum   = data[-2]

        if csum != self.checksum:
            logger.error("checksum not correct -- want", csum, "got", self.checksum)
            raise DataError()

        # Opcode
        # Payload length -- TMP is big-endian, RCP is little-endian
        if self.msgHdr2 == MessageHeader.RCP:
            self.numBytes2 = struct.unpack("<H", data[2:4])[0]
            self.opcode2 = struct.unpack("<H", data[0:2])[0]
        else: #elif self.msgHdr2 == MessageHeader.TMP:
            self.numBytes2 = struct.unpack(">H", data[2:4])[0]
            self.opcode2 = struct.unpack(">H", data[0:2])[0]

        # Payload
        self.payload2 = data[4:4+self.numBytes2]

        logger.debug('%d PL2 (MH2=%s): %s' % (len(self.payload2), str(self.msgHdr2), ' '.join(["%02X"%x for x in self.payload2])))

        # Payload types seen:
        #   MH2 0x41, OP2 0x80 -- 12 bytes payload, eg 00 00 00 00 03 00 00 00 00 00 00 00
        #   MH2 0x43, OP2 0xB8 -- 10 bytes payload, eg 03 00 00 00 00 00 64 00 00 00
        #                                                                ^^^^^^^^^^^ called radio ID
        #   MH2 0x45, OP2 0xB8

        if self.msgHdr2 == MessageHeader.RCP:

            if self.opcode2 == 0x0841:
                # Button and keyboard operation reply
                # Only thing known about this packet is that it contains the current PTT state
                self.pttState = (self.payload[8] != 0)
                # byte [4] is always 0x03?
                self.byte4 = self.payload[4]

                # There's a 0x8841 too, which is a reply to this -- always has a single byte payload of 0x0

            elif self.opcode2 == 0x80E7:
                # Op=0x80E7 -- channel status reply?
                logger.debug('80E7: %s' % (' '.join(['%02X' % x for x in self.payload2])))
                self.statusTarget = self.payload2[0]
                nTargets = self.payload2[1]
                ind = 2
                self.targetData = []
                for i in range(nTargets):
                    (tgt, val) = struct.unpack('<Bi', self.payload2[ind:ind+5])
                    self.targetData.append( (tgt,val) )

            elif self.opcode2 == 0xB843:
                # Transmit status
                # [0]: either 0x01 or 0x03 -- 0x01 seen with Front PTT down (dispatch initiated), 0x03 seen at end of call
                # [1..5]: always 0x00
                (self.process,self.source,self.callType) = struct.unpack('<HHH', self.payload2[0:6])
                self.callType = CallType(self.callType)
                # [6..9]: destination ID
                self.destID = struct.unpack('<I', self.payload2[6:10])[0]

            # 0xB844 is Receive Status but I've never seen it in a trace

            elif self.opcode2 == 0xB845:
                # Repeater broadcasting transmit status (RCP_BROADCAST_STATUS_REPORT) -- ADK doesn't decode this
                #
                # [0..1]: (mode)     always 0x00       (mode)
                # [2..3]: (status)   seen 0x06 (in call) and 0x08,0x01,0x04 sequence (end of call) -- 0x04 seems to signify Cleardown
                # [4..5]: (service type)   always 1? (voice)
                (self.mode, self.status, self.serviceType) = struct.unpack('<HHH', self.payload2[0:6])
                try:
                    self.status = TxCallStatus(self.status)
                except ValueError:
                    # TODO: Log that we've seen a status code we don't recognise
                    logger.warning("Unknown call status %d" % self.status)
                    pass
                # call type
                self.callType = CallType(struct.unpack('<H', self.payload2[6:8])[0])
                # destination ID
                self.destID = struct.unpack('<I', self.payload2[8:12])[0]
                # sender ID
                self.srcID = struct.unpack('<I', self.payload2[12:16])[0]

    def __str__(self):
        s = "QSOdata seq=%d, tmp={%d,%s}, rptID=%d, timeslot=%d -- MH2:%s OP2:0x%02X len:%d" % (self.seqid, self.tmp1, self.tmp6, self.rptID, self.timeslot, self.msgHdr2, self.opcode2, self.numBytes2)
        if self.msgHdr2 == MessageHeader.RCP:
            if self.opcode2 == 0x80E7:
                s += " [Ch Status Rsp  tgt=%d, responses(tgt,val): %s ]" % (self.statusTarget, self.targetData)
            elif self.opcode2 == 0xB844:
                s += " [RxStatus       proc=%d ct=%s]" % (self.process, self.callType)
            elif self.opcode2 == 0xB845:
                s += " [RptrTxStatus   mode=%d status=%s svctype=%d ct=%s from %d to %d]" % (self.mode, self.status, self.serviceType, self.callType, self.srcID, self.destID)
            else:
                s += " Unidentified -- payload %s" % ' '.join(['%02X' % x for x in self.payload2])
        else:
            s += " Unidentified -- payload %s" % ' '.join(['%02X' % x for x in self.payload2])

        return s

        
class HytPacket_Ack(HytPacket):
    """ Packet acknowledgement """
    NAME="ACK"
    def __init__(self, data):
        super().__init__(data)

        
class HytPacket_KeepAlive(HytPacket):
    """ Keep-alive """
    NAME="Keep-alive"
    def __init__(self, data):
        super().__init__(data)


class HytPacket_Syn(HytPacket):
    """ SYN (PC loss of comms, connection reset) """
    NAME="SYN (Sync step 1)"
    def __init__(self, data):
        super().__init__(data)
        self.data = data

    def __str__(self):
        return 'Announce/0x%02X (seq=%d) - %s' % (self.pktType, self.seqid, ' '.join(["%02X" % x for x in self.data]))


class HytPacket_SynAck(HytPacket):
    """ Synchronisation Acknowledge """
    NAME="SYN-ACK (Sync step 2)"
    def __init__(self, data):
        super().__init__(data)

