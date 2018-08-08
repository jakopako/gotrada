package parquetwriter

import (
	"testing"
	"fmt"
	"time"

	"github.com/miekg/dns"
)


//////////////////////////////////
// Only for testing purposes /////
//////////////////////////////////
func TestParquetWriter(t *testing.T) {

    query := new(dns.Msg)
    response := new(dns.Msg)

    for i := 0; i < 100; i++ {

        query = new(dns.Msg)
        response = new(dns.Msg)

        fqdn := fmt.Sprintf("%d_switch.ch.", i)

        query.SetQuestion(dns.Fqdn(fqdn), dns.TypeNS)
        response.SetQuestion(dns.Fqdn(fqdn), dns.TypeNS)

        Add_DNS_query_response(DNS_query_response{query: *query, response: *response})

        if i % 10 == 0 {
        	time.Sleep(2 * time.Second)
        }

    }

}
/////////////////////////////////