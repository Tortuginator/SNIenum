package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"strings"
)

func plain_http_request(target string, SNI string, hostname string, insecure bool) (*http.Response, error) {
	req, _ := http.NewRequest("GET", "https://"+target, nil)

	req.Host = hostname
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         SNI,
				InsecureSkipVerify: insecure,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client.Do(req)
}

func http_request(target string, SNI string, hostname string, insecure bool) {
	resp, err := plain_http_request(target, SNI, hostname, insecure)
	if err == nil {
		fmt.Printf("[%d]\ttarget{%s}\tSNI{%s}\thost{%s}\n", resp.StatusCode, target, SNI, hostname)
	}
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

type TriState uint8

const (
	TriFalse TriState = iota
	TriTrue
	TriUnknown
)

type scanResponse struct {
	host     string
	target   string
	sni      string
	response *http.Response
	err      error
	size     int
}

func newScanResponse(target string, sni string, host string, insecure bool) *scanResponse {
	t := scanResponse{target: target, sni: sni, host: host}
	t.response, t.err = plain_http_request(target, sni, host, insecure)
	t.size = -1
	if t.err == nil {
		bodyBytes, err := ioutil.ReadAll(t.response.Body)
		if err == nil {
			t.size = len(bodyBytes)
		}
	}

	return &t
}

type targetContext struct {
	behaviour       *targetBehaviour
	randomResponses []*scanResponse
	enumResponses   []*scanResponse
}

func newtargetContext(target string, insecure bool) *targetContext {
	t := targetContext{}

	// 1. Step send random Host=SNI to target
	rnd_domain := RandStringBytes(4) + ".com"
	sp1 := newScanResponse(target, rnd_domain, rnd_domain, insecure)

	// 2. Step send a second (longer) random Host=SNI to target
	rnd_domain_second := RandStringBytes(10) + ".com"
	sp2 := newScanResponse(target, rnd_domain_second, rnd_domain_second, insecure)

	t.randomResponses = []*scanResponse{sp1, sp2}
	t.behaviour = newTargetBehaviour()
	t.initialAssessment()
	return &t
}

func (r *targetContext) initialAssessment() {
	if r.randomResponses[0].err == nil {
		r.behaviour.allow_any_SNI = TriTrue
	} else {
		r.behaviour.allow_any_SNI = TriFalse
	}
}

func (r *targetContext) secondaryAssessment(target string) {
	requestsOfInterest := []*scanResponse{}
	if r.behaviour.allow_any_SNI == TriTrue {
		requestsOfInterest = r.randomResponses
	} else if r.behaviour.allow_any_SNI == TriFalse {
		return //TODO
	}
	if len(requestsOfInterest) < 2 {
		println("Unable to find suitable requests to perform a secondary assessment")
	}
	r.analyzeNonExistingHostAndSNI(requestsOfInterest)

}

func (r *targetContext) analyzeNonExistingHostAndSNI(responses []*scanResponse) {
	// This function can be called, when a pair of requests has been identified, that most propably is not a existing host and SNI

	// >>> Compare the length of the response bodies
	// Assumption: When the content-lengths are equal with different host header value lengths, the body is not influenced by the host header
	// Note: Theoretically, the influence on the body could also originate from the SNI

	if responses[0].size != -1 && responses[1].size != -1 {
		if responses[0].size == responses[1].size {
			r.behaviour.host_influences_body = TriFalse
			r.behaviour.unknown_host_response_body_length = responses[0].size
		} else {
			r.behaviour.host_influences_body = TriTrue
		}
	} else {
		r.behaviour.host_influences_body = TriUnknown
	}

	// >>> Compare response status codes
	first_scode := responses[0].response.StatusCode
	second_scode := responses[1].response.StatusCode
	if first_scode != second_scode {
		r.behaviour.unknown_host_response_status_code = -1
	} else {
		r.behaviour.unknown_host_response_status_code = first_scode
	}

	// >>> Compare location redirects if any. If there is a redirect, the structure of the redirect is analyzed
	first_redirect := responses[0].response.Header.Get("location")
	second_redirect := responses[1].response.Header.Get("location")
	if len(first_redirect) > 0 && len(second_redirect) > 0 {
		// if the rnd domain is a substring of the location header for both requests
		if strings.Contains(first_redirect, responses[0].host) && strings.Contains(second_redirect, responses[1].host) {
			blocks := strings.Split(first_redirect, responses[0].host)
			// Create a function, that checks if the location header structurally changes with different hosts
			// Example:
			// Host header          location header                         Function Result
			// valid-domain.com     https://www.valid-domain.com/cool/page  False
			// random1.com          https://random1.com                     True
			// random2.com          https://random2.com                     True
			// In this case, the two random domains are not hosted on the target and therfore only generate a generic forward.
			// The valid-domain.com is hosted on the target and also generates a forward, but to a structurally different location

			r.behaviour.arbitrary_host_forward = func(location string, host string) bool {
				// Returns true, if the location header is set as expected
				location_blocks := strings.Split(location, host)
				if len(location_blocks) > 2 {
					return false
				}
				return reflect.DeepEqual(blocks, location_blocks)
			}
		}
	}
	// >>> Count the headers of the response
	first_header_count := len(responses[0].response.Header)
	second_header_count := len(responses[1].response.Header)
	if first_header_count == second_header_count {
		r.behaviour.unknown_host_response_header_count = first_header_count
	} else {
		r.behaviour.unknown_host_response_header_count = -1
	}

}
func (r *targetContext) indicationFromResponse(s *scanResponse) bool {
	// Returns true, if the SNI/Host combination of the response seems to be valid based on the response
	// Returns false, if it can be discarded
	if s.err != nil {
		//Then a SNI error occured and it is discarded
		//fmt.Printf("%s removed because TLS error\n", s.target)
		return false
	}

	//Body length check
	if r.behaviour.host_influences_body == TriFalse {
		fmt.Printf("%d ; %d", uint(s.size), r.behaviour.unknown_host_response_body_length)
		if s.size != r.behaviour.unknown_host_response_body_length {
			//When the body length already doesn't match, it can be discarded
			fmt.Printf("%s %s removed because body length\n", s.target, s.host)
			return true
		}
	}

	//Header count check
	header_count := len(s.response.Header)
	if r.behaviour.unknown_host_response_header_count != -1 && header_count != r.behaviour.unknown_host_response_header_count {
		fmt.Printf("%s %s removed because header count\n", s.target, s.host)
		return true
	}

	//Location header check
	redirect := s.response.Header.Get("location")
	if r.behaviour.arbitrary_host_forward != nil {
		if !r.behaviour.arbitrary_host_forward(redirect, s.host) {
			//fmt.Printf("%s %s removed because location header\n", s.target, s.host)
			return true
		}
	}

	//Status code
	scode := s.response.StatusCode
	if scode != r.behaviour.unknown_host_response_status_code {
		//fmt.Printf("%s %s removed because of status code\n", s.target, s.host)
		return true
	}
	return false
}

type LocationDetectionFunction func(string, string) bool

type targetBehaviour struct {
	disconnect_on_unknown_SNI          TriState
	allow_any_SNI                      TriState
	allow_any_host                     TriState
	allow_missmatched_host_SNI         TriState
	self_signed_certifificate          TriState
	arbitrary_host_forward             LocationDetectionFunction
	host_influences_body               TriState
	unknown_host_response_body_length  int
	unknown_host_response_status_code  int
	unknown_host_response_header_count int
}

func newTargetBehaviour() *targetBehaviour {
	t := targetBehaviour{
		disconnect_on_unknown_SNI:          TriUnknown,
		allow_any_SNI:                      TriUnknown,
		allow_any_host:                     TriUnknown,
		allow_missmatched_host_SNI:         TriUnknown,
		self_signed_certifificate:          TriUnknown,
		arbitrary_host_forward:             nil,
		host_influences_body:               TriUnknown,
		unknown_host_response_header_count: -1,
		unknown_host_response_status_code:  -1,
		unknown_host_response_body_length:  0,
	}
	return &t
}

func is_file(file string) bool {
	if _, err := os.Stat(file); err == nil {
		return true
	}
	return false
}

func process_input_lists(input_value string) []string {
	var ret []string
	if is_file(input_value) {
		targetReader, err := os.Open(input_value)

		if err != nil {
			fmt.Println(err)
		}
		targetFileScanner := bufio.NewScanner(targetReader)
		targetFileScanner.Split(bufio.ScanLines)

		for targetFileScanner.Scan() {
			ret = append(ret, targetFileScanner.Text())
		}

		targetReader.Close()
		return ret
	}
	return append(ret, input_value)
}

func main() {
	arg_http_method := flag.String("X", "HEAD", "HTTP method used to send requests to the targets")
	arg_target_list := flag.String("t", "test_targets.txt", "path to a list of IP's/domains to use as target")
	arg_host_list := flag.String("h", "test_hosts.txt", "list of hostnames used for enumerating SNI and Host headers")
	arg_insecure := flag.Bool("i", true, "insecure TLS for self-signed certificates")
	flag.Parse()
	fmt.Println("http method:", *arg_http_method)
	fmt.Println("host list:", *arg_host_list)
	targets := process_input_lists(*arg_target_list)
	hosts := process_input_lists(*arg_host_list)

	for _, target := range targets {
		t := newtargetContext(target, *arg_insecure)
		t.secondaryAssessment(target)
		for _, host := range hosts {
			s := newScanResponse(target, host, host, *arg_insecure)
			result := t.indicationFromResponse(s)
			if result {
				fmt.Printf("[%d|%d]\ttarget{%s}\tSNI{%s}\thost{%s} [%s]\n", s.response.StatusCode, s.size, target, host, host, s.response.Header.Get("location"))
			}
		}
	}
}
