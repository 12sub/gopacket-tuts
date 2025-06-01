package main

import (
	// "fmt"
	"time"
	"log"
	// "os"
	"net"

	"github.com/google/gopacket/pcap"
	// "github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var(
	device	string = "wlx1cbfce6faa73"
	snapshot_len	int32 = 1024
	promiscuous		bool = false
	timeout		time.Duration = -1*time.Second
	handle		*pcap.Handle
	buffer 		gopacket.SerializeBuffer
	options		gopacket.SerializeOptions
)

func main(){
	// //writing to file
	// dumpFile, err := os.Create("send.pcap")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer dumpFile.Close()
	// // headers
	// pWriter := pcapgo.NewWriter(dumpFile)
	// pWriter.WriteFileHeader(
	// 	uint32(snapshot_len),
	// 	layers.LinkTypeEthernet
	// )

	// open live devices
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// send bytes over the wire
	rawPayload := []byte{20,30,40,50}
	err = handle.WritePacketData(rawPayload)
	if err != nil {
		log.Fatal(err)
	}
	// create packets
	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, &layers.Ethernet{}, &layers.IPv4{}, &layers.TCP{}, gopacket.Payload(rawPayload))
	outPackets := buffer.Bytes()
	// send packets
	err = handle.WritePacketData(outPackets)
	if err != nil {
		log.Fatal(err)
	}
	//optional: create info packets(packets that holds information)
	// then we'll create the packets with the layers

	ipLayer := &layers.IPv4{
		SrcIP: net.IP{127, 0, 0, 1},
		DstIP: net.IP{8, 8, 8, 8},
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(80),
	}

	buffer = gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options, ipLayer, ethernetLayer, tcpLayer, gopacket.Payload(rawPayload))
	outPackets = buffer.Bytes()
}