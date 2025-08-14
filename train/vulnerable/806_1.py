from scapy.all import *

class VulnerableRADIUSAttrPacketListField(RADIUSAttrPacketListField):
    def getfield(self, pkt, s):
        return super().getfield(pkt, s)

class VulnerableRADIUSPacket(RADIUS):
    attrs = VulnerableRADIUSAttrPacketListField("attrs", None)

malformed_packet = VulnerableRADIUSPacket(attrs=[("Malformed-Attribute", "test_user")])