package main

import (
  "os"
  "fmt"
  "github.com/dnstap/golang-dnstap"
  "github.com/golang/protobuf/proto"
  "../joiner"
)

func main() {
  var err error
  var i dnstap.Input
  raw := make(chan []byte, 1)
  packets := make(chan *dnstap.Message, 1)

  go WriteToPacketChannel(raw, packets)

  //go PrintType(packets)
  go joiner.Execute(packets)

  var filename = "../../data/lako.capture.tap"
  i, err = dnstap.NewFrameStreamInputFromFilename(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dnstap: Failed to open input file: %s\n", err)
		os.Exit(1)
	}
  if i != nil {
    fmt.Println("Successfully read dnstap file.")
    i.ReadInto(raw)
    // Wait for input loop to finish.
  	i.Wait()
    close(raw)
  }

fmt.Printf("Size of cache: %d " , joiner.CacheSize())

}

func WriteToPacketChannel(rawdata <-chan []byte, packetdata chan<- *dnstap.Message) {
  defer func() {
    close(packetdata)
  }()
  for {
		select {
		case b, ok := <-rawdata:
			if !ok {
				return
			}
      dt := &dnstap.Dnstap{}
      if err := proto.Unmarshal(b, dt); err != nil {
  			fmt.Printf("dnstap.TextOutput: proto.Unmarshal() failed: %s\n", err)
  			break
      }
      if *dt.Type == dnstap.Dnstap_MESSAGE {
        packetdata <- dt.Message
      }
		}
  }
}

func PrintType(packetdata <-chan *dnstap.Message) {
  for {
		select {
		case m, ok := <-packetdata:
			if !ok {
				return
			}
      isQuery := false

    	switch *m.Type {
    	case dnstap.Message_CLIENT_QUERY,
    		dnstap.Message_RESOLVER_QUERY,
    		dnstap.Message_AUTH_QUERY,
    		dnstap.Message_FORWARDER_QUERY,
    		dnstap.Message_TOOL_QUERY:
    		isQuery = true
    	case dnstap.Message_CLIENT_RESPONSE,
    		dnstap.Message_RESOLVER_RESPONSE,
    		dnstap.Message_AUTH_RESPONSE,
    		dnstap.Message_FORWARDER_RESPONSE,
    		dnstap.Message_TOOL_RESPONSE:
    		isQuery = false
    	default:
    		return
    	}

    	if isQuery {
    		fmt.Println("This is a query.")
    	} else {
    		fmt.Println("This is a response.")
      }
		}
  }
}
