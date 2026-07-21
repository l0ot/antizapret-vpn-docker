package resolver

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

type goldenFixture struct {
	QName        string            `json:"qname"`
	QType        string            `json:"qtype"`
	Rcode        int               `json:"rcode"`
	Answers      []goldenAnswer    `json:"answers"`
	DoHClientIDs []string          `json:"doh_client_ids"`
	Mapping      map[string]string `json:"mapping"`
}

type goldenAnswer struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	TTL     uint32 `json:"ttl"`
	Address string `json:"address"`
}

func TestGoldenAContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "a-response.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture goldenFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	request := question(fixture.QName, dns.TypeA)
	dohClient := &fakeDoH{responses: []*dns.Msg{answer(request, dns.RcodeSuccess, "192.0.2.1")}}
	mapper := &fakeMapper{mappings: fixture.Mapping}
	response := newResolver(dohClient, &fakeMatcher{matches: map[string]bool{}}, mapper).Resolve(context.Background(), request)
	if response.Rcode != fixture.Rcode || len(response.Answer) != len(fixture.Answers) {
		t.Fatalf("golden response shape differs: %s", response)
	}
	for i, expected := range fixture.Answers {
		record, ok := response.Answer[i].(*dns.A)
		if !ok || record.Hdr.Name != expected.Name || dns.TypeToString[record.Hdr.Rrtype] != expected.Type || record.Hdr.Ttl != expected.TTL || record.A.String() != expected.Address {
			t.Fatalf("golden answer %d differs: %#v", i, response.Answer[i])
		}
	}
	if !equalStrings(dohClient.ids, fixture.DoHClientIDs) {
		t.Fatalf("golden DoH IDs differ: got=%v want=%v", dohClient.ids, fixture.DoHClientIDs)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
