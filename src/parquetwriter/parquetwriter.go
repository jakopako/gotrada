package main

import (
    "fmt"
    "log"

    "github.com/miekg/dns"

    "github.com/xitongsys/parquet-go/ParquetFile"
    "github.com/xitongsys/parquet-go/ParquetWriter" 
    // "github.com/xitongsys/parquet-go/parquet" 
)

type DNS_query_response struct {
    query dns.Msg
    response dns.Msg
}

var query_response_buffer []DNS_query_response 

//  See schema at 
//  https://github.com/SIDN/entrada/blob/master/pcap-to-parquet/src/main/resources/dns-query.avsc
// var dns_schema string = `{
//   "type": "record",
//   "name": "dnsdata",
//   "namespace": "nl.sidn.idnp.data.dns",
//   "doc": "DNS query / response",
//   "fields": [
//     { "name": "id", "type": "int" },
//     { "name": "unixtime", "type": "long" },
//     { "name": "time", "type": "long" },
//     { "name": "qname", "type": ["null","string"], "default": null},
//     { "name": "domainname", "type": ["null","string"], "default": null},
//     { "name": "len", "type": ["null","int"], "default": null },
//     { "name": "frag", "type": ["null","int"], "default": null},
//     { "name": "ttl", "type": ["null","int"], "default": null },
//     { "name": "ipv", "type": "int" },
//     { "name": "prot", "type": "int" },
//     { "name": "src", "type": "string" },
//     { "name": "srcp", "type": ["null","int"], "default": null},
//     { "name": "dst", "type": "string" },
//     { "name": "dstp", "type": "int"},
//     { "name": "udp_sum", "type": ["null","int"], "default": null},
//     { "name": "dns_len", "type": ["null","int"], "default": null},
//     { "name": "aa", "type": ["null","boolean"], "default": null},
//     { "name": "tc","type": ["null","boolean"], "default": null},
//     { "name": "rd", "type": ["null","boolean"], "default": null},
//     { "name": "ra", "type": ["null","boolean"], "default": null},
//     { "name": "z", "type": ["null","boolean"], "default": null},
//     { "name": "ad", "type": ["null","boolean"], "default": null},
//     { "name": "cd", "type": ["null","boolean"], "default": null},
//     { "name": "ancount", "type": ["null","int"], "default": null},
//     { "name": "arcount", "type": ["null","int"], "default": null},
//     { "name": "nscount", "type": ["null","int"], "default": null},
//     { "name": "qdcount", "type": "int"},
//     { "name": "opcode", "type": "int"},
//     { "name": "rcode", "type": "int"},
//     { "name": "qtype", "type": ["null","int"], "default": null},
//     { "name": "qclass", "type": ["null","int"], "default": null},
//     { "name": "country", "type": ["null","string"], "default": null},
//     { "name": "asn", "type": ["null","string"], "default": null},
//     { "name": "edns_udp", "type": ["null","int"], "default": null},
//     { "name": "edns_version", "type": ["null","int"], "default": null},
//     { "name": "edns_do", "type": ["null","boolean"], "default": null},
//     { "name": "edns_ping", "type": ["null","boolean"], "default": null},
//     { "name": "edns_nsid", "type": ["null","string"], "default": null},
//     { "name": "edns_dnssec_dau", "type":  ["null","string"], "default": null},
//     { "name": "edns_dnssec_dhu", "type":  ["null","string"], "default": null},  
//     { "name": "edns_dnssec_n3u", "type":  ["null","string"], "default": null}, 
//     { "name": "edns_client_subnet", "type":  ["null","string"], "default": null}, 
//     { "name": "edns_other", "type":  ["null","string"], "default": null},
//     { "name": "edns_client_subnet_asn", "type":  ["null","string"], "default": null}, 
//     { "name": "edns_client_subnet_country", "type":  ["null","string"], "default": null},
//     { "name": "labels", "type": "int" },
//     { "name": "res_len", "type": "int","default": 0 },
//     { "name": "svr", "type": "string" },
//     { "name": "time_micro", "type": "long" },
//     { "name": "resp_frag", "type": ["null","int"], "default": null},
//     { "name": "proc_time", "type": ["null","int"], "default": null },
//     { "name": "is_google", "type": "boolean", "default": false},
//     { "name": "is_opendns", "type": "boolean", "default": false},
//     { "name": "dns_res_len", "type": ["null","int"], "default": null},
//     { "name": "server_location", "type": ["null","string"], "default": null},
//     { "name": "edns_padding", "type": "int", "default": -1},
//     { "name": "pcap_file", "type": ["null","string"], "default": null},
//     { "name": "edns_keytag_count", "type": ["null","int"], "default": null},
//     { "name": "edns_keytag_list", "type": ["null","string"], "default": null},
//     { "name": "q_tc","type": ["null","boolean"], "default": null},
//     { "name": "q_ra", "type": ["null","boolean"], "default": null},
//     { "name": "q_ad", "type": ["null","boolean"], "default": null},
//     { "name": "q_rcode", "type": ["null","int"], "default": null}
//   ]
// }`

var dns_schema string = `{
  "Tag": "name=parquet-go-root",
  "Fields": [
    {"Tag":"name=id, type=INT32"},
    {"Tag":"name=unixtime, type=INT64"},
    {"Tag":"name=qname, type=UTF8"},
    {"Tag":"name=domainname, type=UTF8"}
  ]
}`


func add_DNS_query_response(query_response DNS_query_response) {

    query_response_buffer = append(query_response_buffer, query_response)

    // fmt.Println(len(query_response_buffer))
    // fmt.Println(query_response_buffer)

    if len(query_response_buffer) == 2 {
        write_to_parquet()
    }

}


func write_to_parquet() {

    var err error

    fw, err := ParquetFile.NewLocalFileWriter("test.parquet")
    if err != nil {
        
        log.Println("Can't create file", err)
        return

    }
    
    pw, err := ParquetWriter.NewJSONWriter(dns_schema, fw, 4)
    if err != nil {
    
        log.Println("Can't create json writer", err)
        return

    }

    // pw.RowGroupSize = 128 * 1024 * 1024 //128M
    // pw.CompressionType = parquet.CompressionCodec_SNAPPY

    for i := 0; i < cap(query_response_buffer); i++ {
        
        rec := `
            "id": 123456,
            "unixtime": 1533647257,
            "qname": "%s",
            "domainname": "%s"
        `

        rec = fmt.Sprintf(rec, query_response_buffer[i].query.Question[0].Name, 
                                    query_response_buffer[i].query.Question[0].Name)


        if err = pw.Write(rec); err != nil {
            log.Println("Write error", err)
        }

        log.Println(pw.Objs)
    }

    if err = pw.WriteStop(); err != nil {
        log.Println("WriteStop error", err)
    }
    log.Println("Write Finished")
    fw.Close()

}


func main() {

    query := new(dns.Msg)
    response := new(dns.Msg)

    query.SetQuestion(dns.Fqdn("www.example.com."), dns.TypeAAAA)
    response.SetQuestion(dns.Fqdn("www.example.com."), dns.TypeAAAA)

    add_DNS_query_response(DNS_query_response{query: *query, response: *response})

    query = new(dns.Msg)
    response = new(dns.Msg)

    query.SetQuestion(dns.Fqdn("switch.ch."), dns.TypeNS)
    response.SetQuestion(dns.Fqdn("switch.ch."), dns.TypeNS)

    add_DNS_query_response(DNS_query_response{query: *query, response: *response})

}
