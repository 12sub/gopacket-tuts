package main

import (
	"fmt"
	"net"
	"log"

	"github.com/google/gopacket/pcap"
)

type InterfaceAddress struct{
	IP	net.IP
	Netmask	net.IPMask		
}

type Interface struct {
	Name	string
	Description	string
	Addresses	[]InterfaceAddress
}

func main(){
	var devices []pcap.Interface
	devices, err := pcap.FindAllDevs()
	if err != nil{
		log.Fatal("No device found")
	}
	fmt.Println(devices)
}


