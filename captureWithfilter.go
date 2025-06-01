package main

import (
	"fmt"
	"time"
	"log"
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var(
	device	string = "wlx1cbfce6faa7300"
	snapshot_len	int32 = 1024
	promiscuous		bool = false
	timeout		time.Duration = -1*time.Second
	handle		*pcap.Handle
	BPFFilterStr	string = "tcp and port 80"
)

func main(){

	// first, we write to file
	dumpFile, err := os.Create("dump.pcap")
	if err != nil{
		log.Fatal(err)
	}
	defer dumpFile.Close()

	// creating header
	packetWriter := pcapgo.NewWriter(dumpFile)
	if snapshot_len < 0 {
    	log.Fatalf("Invalid snapshot length: %d", snapshot_len)
	}
	packetWriter.WriteFileHeader(uint32(snapshot_len), layers.LinkTypeEthernet)

	// then, we open live devices
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// after, we capture with BPFFilter
	err = handle.SetBPFFilter(BPFFilterStr)
	if err != nil {
		log.Fatal(err)
	}

	// nxt, we create a packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets(){
		// writing pcap file 
		packetWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		// printing the results
		fmt.Println(packet)
	}
}