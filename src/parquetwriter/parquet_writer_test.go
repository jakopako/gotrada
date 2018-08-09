package parquetwriter

import (
	"testing"
	"fmt"
	"time"

	"model"

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

        Add_Data(model.Data{Req: *query, Res: *response})

        if i % 10 == 0 {
        	time.Sleep(1 * time.Second)
        }

    }

}
/////////////////////////////////