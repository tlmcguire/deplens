from scapy.all import *

class SafeRADIUSAttrPacketListField(RADIUSAttrPacketListField):
    def getfield(self, pkt, s):
        try:
            return super().getfield(pkt, s)
        except Exception as e:
            import logging
            logging.exception("Error processing RADIUS attributes")
            return [], b""

class SafeRADIUSPacket(RADIUS):
    fields_desc = [SafeRADIUSAttrPacketListField("attrs", None)]

    def extract_padding(self, s):
        return "", s


packet = SafeRADIUSPacket(attrs=[("User-Name", b"test_user")])