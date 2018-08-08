package model

import(
  "github.com/miekg/dns"
)

type Data struct {
  Req dns.Msg
  Res dns.Msg
}
