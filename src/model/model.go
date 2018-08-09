package model

import(
  "github.com/miekg/dns"
  "github.com/dnstap/golang-dnstap"
)

type Data struct {
  MessagaReq dnstap.Message
  MessageRes dnstap.Message
  DnsReq dns.Msg
  DnsRes dns.Msg
}
