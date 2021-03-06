package joiner

import(
  "fmt"
  "net"
  "strings"
  "github.com/dnstap/golang-dnstap"
  "github.com/miekg/dns"
  "../model"
  "../parquetwriter"
)

type PacketKey struct {
  id uint16
  qname string
  src string
  srcp uint32
}

type PacketValue struct {
  tap *dnstap.Message
  dns *dns.Msg
}

var cache = make(map[PacketKey]*PacketValue)
  // Make channel
var query_response_channel = make(chan *model.Data)

func stats(){
  fmt.Println("Size of cache: " + string(len(cache)))
}

func Execute(packetdata <-chan *dnstap.Message) {


  // Start routine to add data
  // Routine will run until channel is closed
  go parquetwriter.Add_Data(query_response_channel)

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
  var err error
  dns := new(dns.Msg)
  err = dns.Unpack(msg.QueryMessage)

  if err == nil {
    key := packetKeyFor(true, msg, dns)
    cache[*key] = &PacketValue{msg, dns}
  }
}

func handleResponse(response *dnstap.Message) {
  var err error
  dns := new(dns.Msg)
  err = dns.Unpack(response.ResponseMessage)

  if err == nil {
    key := packetKeyFor(true, response, dns)
    requestValue := cache[*key]
    if requestValue != nil{
      //delete req from Cache
      delete(cache, *key)
      //send to parquet writer channel

      d := &model.Data{requestValue.tap, response, requestValue.dns, dns}
      //fmt.Printf("data to send: %s", *d)
      query_response_channel <- d
    }
  }
}

func packetKeyFor(req bool, msg *dnstap.Message, dns *dns.Msg) *PacketKey{
  var ip net.IP
  var port uint32

  if req {
    ip = msg.QueryAddress
    port = *msg.QueryPort
  }else{
    ip = msg.ResponseAddress
    port = *msg.ResponsePort
  }
  //fmt.Printf("ip: %d and port: %d\n", ip, port)
  key := &PacketKey{dns.Id, strings.ToLower(dns.Question[0].Name), ip.String(), port}
  return key
}

func CacheSize() int {
  return len(cache)
}
