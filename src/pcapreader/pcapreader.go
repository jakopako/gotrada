package main

import (
  "fmt"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
  // "github.com/miekg/dns"
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
        // Iterate over all layers, printing out each layer type
      // fmt.Println("All packet layers:")
      // for _, layer := range packet.Layers() {
      //     fmt.Println("- ", layer.LayerType())
      // }
      if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
        // Get actual DNS data from this layer
        dns, _ := dnsLayer.(*layers.DNS)
        if dns.QR {
          fmt.Println("This packet is a response.")
          fmt.Printf("DNS query ID %d\n", dns.ID)
        } else {
          fmt.Println("This packet is a query.")
          fmt.Printf("DNS query ID %d\n", dns.ID)
        }
      }
      // if app := packet.ApplicationLayer(); app != nil {
      //   // check if DNS
      //   if app.LayerType() == layers.LayerTypeDNS {
      //     fmt.Println(app.LayerType())
      //     fmt.Println(app.LayerContents())
      //     DNSPacket := new(layers.DNS)
      //     DNSPacket.DecodeFromBytes(app.LayerContents())
      //   }

        // if payload := app.Payload(); payload != nil {
        //   m := new(dns.Msg)
        //   err := m.Unpack(payload)
        //   fmt.Println(m)
        //   fmt.Println(err)
        // }
    }
  }
}
