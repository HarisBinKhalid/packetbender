from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter

from packetbender.core.pcap_model import PcapModel


def test_loads_pcapng_files_without_crashing(tmp_path):
    # PcapNgReader has no top-level `linktype` attribute (unlike the
    # classic PcapReader) - loading used to crash with AttributeError
    # before reading a single packet.
    path = str(tmp_path / "capture.pcapng")
    pkt = (
        Ether(src="aa:aa:aa:aa:aa:aa", dst="bb:bb:bb:bb:bb:bb")
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=1111, dport=2222)
        / Raw(load=b"hello world")
    )
    writer = PcapNgWriter(path)
    writer.write(pkt)
    writer.close()

    model = PcapModel()
    model.load(path)

    assert len(model.records) == 1
    record = model.records[0]
    assert record.packet.haslayer("IP")
    assert record.packet["IP"].src == "10.0.0.1"
    assert model.unrecognized_linktype_warning is None
