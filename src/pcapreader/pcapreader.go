package main

import (
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
)

func main() {
  if handle, err := pcap.OpenOffline("../../data/test.pcap"); err != nil {
    panic(err)
  } else {
    layers.LinkTypeMetadata[12] = layers.EnumMetadata{
      DecodeWith: layers.LayerTypeIPv4,
      Name: "tun",
    }
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
      fmt.Println(packet)
    }
  }
}
