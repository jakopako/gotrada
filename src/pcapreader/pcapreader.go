package main

import (
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
)

func main() {
  if handle, err := pcap.OpenOffline("/Users/dhondt/pcaps/lako/lako.switch.ch.20170330.130000.000065.pcap"); err != nil {
    panic(err)
  } else {
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
      fmt.Println(packet) 
    }
  }
}
