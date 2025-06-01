package main

import (
	"fmt"
	"time"
	"log"

	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

var(
	device	string = "wlx1cbfce6faa73"
	snapshot_len	int32 = 65535
	promiscuous		bool = false
	timeout		time.Duration = -1*time.Second
	handle		*pcap.Handle
)

func main(){
	// first, we open live devices
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// nxt, we create a packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets(){
		fmt.Println(packet)
	}
}