package joiner

import(
  "fmt"
  "net"
  "strings"
  "github.com/dnstap/golang-dnstap"
  "github.com/miekg/dns"
)

type PacketKey struct {
  id uint16
  qname string
  src string
  srcp uint32
}

var cache = make(map[PacketKey]*dnstap.Message)

func stats(){
  fmt.Println("Size of cache: " + string(len(cache)))
}

func Execute(packetdata <-chan *dnstap.Message) {
  defer func(){
    //close(packetdata)
    fmt.Println("Size of cache: " + string(len(cache)))
  }()

  for {
		select {
		  case m, ok := <-packetdata:
			if !ok {
        //invalid msg
				continue
			}

    	switch *m.Type {
    	case dnstap.Message_CLIENT_QUERY,
    		dnstap.Message_RESOLVER_QUERY,
    		dnstap.Message_AUTH_QUERY,
    		dnstap.Message_FORWARDER_QUERY,
    		dnstap.Message_TOOL_QUERY:
    		handleQuery(m)
    	case dnstap.Message_CLIENT_RESPONSE,
    		dnstap.Message_RESOLVER_RESPONSE,
    		dnstap.Message_AUTH_RESPONSE,
    		dnstap.Message_FORWARDER_RESPONSE,
    		dnstap.Message_TOOL_RESPONSE:
    		handleResponse(m)
    	default:
    		fmt.Println("This is an unknown packet.")
    	}
		}
  }


}


func handleQuery(msg *dnstap.Message) {
//  fmt.Println("Handle query")

  var err error
  dns := new(dns.Msg)
  err = dns.Unpack(msg.QueryMessage)

  if err == nil {
    //fmt.Println("unpacked query")

    //fmt.Println(dns.Question[0].Name)
      var ip net.IP
      ip = msg.QueryAddress
    key := PacketKey{dns.Id, strings.ToLower(dns.Question[0].Name), ip.String(), *msg.QueryPort}

    //fmt.Println(key)

    cache[key] = msg
  }
}

func handleResponse(msg *dnstap.Message) {
  //fmt.Println("Handle response")
}


func CacheSize() int {
  return len(cache)
}
