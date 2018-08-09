package parquetwriter

import (
	"testing"
	"fmt"
	// "time"

	"model"

	"github.com/miekg/dns"
)


//////////////////////////////////
// Only for testing purposes /////
//////////////////////////////////
func TestParquetWriter(t *testing.T) {

    query := new(dns.Msg)
    response := new(dns.Msg)

    // Make channel 
    query_response_channel := make(chan model.Data)

    // Start routine to add data
    // Routine will run until channel is closed
    go Add_Data(query_response_channel)

    // Create 1M "packets"
    for i := 0; i < 1000000; i++ {

        query = new(dns.Msg)
        response = new(dns.Msg)

        fqdn := fmt.Sprintf("%d_switch.ch.", i)

        query.SetQuestion(dns.Fqdn(fqdn), dns.TypeNS)
        response.SetQuestion(dns.Fqdn(fqdn), dns.TypeNS)

        // Add new data to the channel
        query_response_channel <- model.Data{Req: *query, Res: *response}

        // if i % 10 == 0 {
        // 	time.Sleep(1 * time.Second)
        // }

    }

}
/////////////////////////////////