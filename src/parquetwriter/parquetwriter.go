package main

import (
    // "fmt"
    "log"
    "github.com/miekg/dns"
    "github.com/xitongsys/parquet-go/ParquetFile"
    "github.com/xitongsys/parquet-go/ParquetWriter"
    "github.com/xitongsys/parquet-go/parquet"
)

type DNS_query_response struct {
    query dns.Msg
    response dns.Msg
}

//  See schema at 
//  https://github.com/SIDN/entrada/blob/master/pcap-to-parquet/src/main/resources/dns-query.avsc
type Record struct {
    Id              int32       `parquet:"name=id, type=INT32"`
    Unixtime        int64       `parquet:"name=unixtime, type=INT64"`
    Time            int64       `parquet:"name=time, type=INT64"`
    Qname           string      `parquet:"name=qname, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Domainname      string      `parquet:"name=domainname, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Len             int32       `parquet:"name=len, type=INT32"`
    Frag            int32       `parquet:"name=frag, type=INT32"`
    Ttl             int32       `parquet:"name=ttl, type=INT32"`
    Ipv             int32       `parquet:"name=ipv, type=INT32"`
    Prot            int32       `parquet:"name=prot, type=INT32"`
    Src             string      `parquet:"name=src, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Srcp            int32       `parquet:"name=srcp, type=INT32"`
    Dst             string      `parquet:"name=dst, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Dstp            int32       `parquet:"name=dstp, type=INT32"`
    Udp_sum         int32       `parquet:"name=udp_sum, type=INT32"`
    Dns_len         int32       `parquet:"name=dns_len, type=INT32"`
    Aa              bool        `parquet:"name=aa, type=BOOLEAN"`
    Tc              bool        `parquet:"name=tc, type=BOOLEAN"`
    Rd              bool        `parquet:"name=rd, type=BOOLEAN"`
    Ra              bool        `parquet:"name=ra, type=BOOLEAN"`
    Z               bool        `parquet:"name=z, type=BOOLEAN"`
    Ad              bool        `parquet:"name=ad, type=BOOLEAN"`
    Cd              bool        `parquet:"name=cd, type=BOOLEAN"`
    Ancount         int32       `parquet:"name=ancount, type=INT32"`
    Arcount         int32       `parquet:"name=arcount, type=INT32"`
    Nscount         int32       `parquet:"name=nscount, type=INT32"`
    Qdcount         int32       `parquet:"name=qdcount, type=INT32"`
    Rcode           int32       `parquet:"name=rcode, type=INT32"`
    Qtype           int32       `parquet:"name=qtype, type=INT32"`
    Qclass          int32       `parquet:"name=qclass, type=INT32"`
    Country         string      `parquet:"name=country, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Asn             string      `parquet:"name=asn, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Opcode          int32       `parquet:"name=opcode, type=INT32"`
    Edns_udp        int32       `parquet:"name=edns_udp, type=INT32"`
    Edns_version    int32       `parquet:"name=edns_version, type=INT32"`
    Edns_do         bool        `parquet:"name=edns_do, type=BOOLEAN"`
    Edns_ping       bool        `parquet:"name=edns_ping, type=BOOLEAN"`
    Edns_nsid       string      `parquet:"name=edns_nsid, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_dnssec_dau     string  `parquet:"name=edns_dnssec_dau, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_dnssec_dhu     string  `parquet:"name=edns_dnssec_dhu, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_dnssec_n3u     string  `parquet:"name=edns_dnssec_n3u, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_client_subnet  string  `parquet:"name=edns_client_subnet, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_other      string      `parquet:"name=edns_other, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_client_subnet_asn      string  `parquet:"name=edns_client_subnet_asn, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_client_subnet_country  string  `parquet:"name=edns_client_subnet_country, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Labels          int32       `parquet:"name=labels, type=INT32"`
    Res_len         int32       `parquet:"name=res_len, type=INT32"`
    Svr             string      `parquet:"name=svr, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Time_micro      int64       `parquet:"name=time_micro, type=INT64"`
    Resp_frag       int32       `parquet:"name=resp_frag, type=INT32"`
    Proc_time       int32       `parquet:"name=proc_time, type=INT32"`
    Is_google       bool        `parquet:"name=is_google, type=BOOLEAN"`
    Is_opendns      bool        `parquet:"name=is_opendns, type=BOOLEAN"`
    Dns_res_len     int32       `parquet:"name=dns_res_len, type=INT32"`
    Server_location string      `parquet:"name=server_location, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_padding    int32       `parquet:"name=edns_padding, type=INT32"`
    Pcap_file       string      `parquet:"name=pcap_file, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Edns_keytag_count   int32   `parquet:"name=edns_keytag_count, type=INT32"`
    Edns_keytag_list    string  `parquet:"name=edns_keytag_list, type=UTF8, encoding=PLAIN_DICTIONARY"`
    Q_tc            bool        `parquet:"name=q_tc, type=BOOLEAN"`
    Q_ra            bool        `parquet:"name=q_ra, type=BOOLEAN"`
    Q_ad            bool        `parquet:"name=q_ad, type=BOOLEAN"`
    Q_rcode         int32       `parquet:"name=q_rcode, type=INT32"`
}

var query_response_buffer []DNS_query_response 


func add_DNS_query_response(query_response DNS_query_response) {

    query_response_buffer = append(query_response_buffer, query_response)

}


func write_to_parquet() {

    var err error

    fw, err := ParquetFile.NewLocalFileWriter("test.parquet")
    if err != nil {
        log.Println("Can't create file", err)
        return
    }
    
    pw, err := ParquetWriter.NewParquetWriter(fw, new(Record), 1)
    if err != nil {
        log.Println("Can't create parquet writer", err)
        return
    }

    pw.RowGroupSize = 128 * 1024 * 1024 //128M
    pw.CompressionType = parquet.CompressionCodec_SNAPPY


    for i := 0; i < len(query_response_buffer); i++ {
         

        rec := Record{
                Domainname:      query_response_buffer[i].query.Question[0].Name,
                Qname:           query_response_buffer[i].query.Question[0].Name,
                }

        log.Println(rec)

        if err = pw.Write(rec); err != nil {
            log.Println("Write error", err)
        }
        
    }

    // log.Println(pw.Objs)
    log.Println(pw.ObjSize)

    if err = pw.WriteStop(); err != nil {
        log.Println("WriteStop error", err)
        return
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

    for i := 0; i < 100; i++ {

        query = new(dns.Msg)
        response = new(dns.Msg)

        query.SetQuestion(dns.Fqdn("switch.ch."), dns.TypeNS)
        response.SetQuestion(dns.Fqdn("switch.ch."), dns.TypeNS)

        add_DNS_query_response(DNS_query_response{query: *query, response: *response})

    }

    write_to_parquet()

}
