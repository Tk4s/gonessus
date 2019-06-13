package nessusgo

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	Version = "0.0.1"
)

// Client is an Nessus Client. Create one by calling NewClient
type Client struct {
	c         *http.Client
	serverURL string
	accessKey string
	secretKey string
}

// ClientOptionFunc is a function that configures a Client.
// It is used in NewClient.
type ClientOptionFunc func(*Client) error

// NewClient is return a new client
func NewClient(options ...ClientOptionFunc) (c *Client, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	c = &Client{
		c: &http.Client{Transport: tr},
	}

	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}

	return c, err
}

// SetServerURL defines the url endpoint of Nessus Api.
func SetServerURL(url string) ClientOptionFunc {
	return func(c *Client) error {
		c.serverURL = url
		return nil
	}
}

// SetAccessKey define access key by X-ApiKeys:  /api#/authorization
func SetAccessKey(accessKey string) ClientOptionFunc {
	return func(c *Client) error {
		c.accessKey = accessKey
		return nil
	}
}

// SetSecretKey define secret key by X-ApiKeys:  /api#/authorization
func SetSecretKey(secretKey string) ClientOptionFunc {
	return func(c *Client) error {
		c.secretKey = secretKey
		return nil
	}
}

// PerformRequestOptions must be passed into PerformRequest.
type PerformRequestOptions struct {
	Method      string
	Path        string
	Params      url.Values
	Body        interface{}
	ContentType string
	Headers     http.Header
}

// PerformRequest dose a http request to nessus
func (c *Client) PerformRequest(opt PerformRequestOptions) (*Response, error) {
	var err error
	var req *Request
	var resp *Response

	pathWithParmas := opt.Path
	if len(opt.Params) > 0 {
		pathWithParmas += "?" + opt.Params.Encode()
	}
	fmt.Println(opt.Method, c.serverURL+pathWithParmas)
	req, err = NewRequest(opt.Method, c.serverURL+pathWithParmas)
	if err != nil {
		fmt.Printf("nessus: connot create request for %s %s: %v \n", strings.ToUpper(opt.Method), c.serverURL+pathWithParmas, err)
		return nil, err
	}

	req.Header.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s; secretKey=%s", c.accessKey, c.secretKey))

	if opt.ContentType != "" {
		req.Header.Set("Content-Type", opt.ContentType)
	}

	if len(opt.Headers) > 0 {
		for key, value := range opt.Headers {
			for _, val := range value {
				req.Header.Add(key, val)
			}
		}
	}

	if opt.Body != nil {
		err = req.SetBody(opt.Body, false)
		if err != nil {
			fmt.Printf("nessus: couldn't set body %+v for request: %v \n", opt.Body, err)
			return nil, err
		}
	}

	res, err := c.c.Do((*http.Request)(req))

	if err != nil {
		fmt.Printf("nessus: send request failed: %v \n", err)
		return nil, err
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	resp, err = c.newResponse(res, 0)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
