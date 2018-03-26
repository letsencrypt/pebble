package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/letsencrypt/pebble/cmd"
	"gopkg.in/square/go-jose.v2"
)

const (
	version       = "0.0.1"
	userAgentBase = "pebble-client"
	locale        = "en-us"
)

func userAgent() string {
	return fmt.Sprintf(
		"%s %s (%s; %s)",
		userAgentBase, version, runtime.GOOS, runtime.GOARCH)
}

type client struct {
	server    *url.URL
	directory map[string]interface{}
	email     string
	acctID    string
	http      *http.Client
	privKey   jose.SigningKey
	nonce     string
}

func newClient(server, email string, pebbleCAPool *x509.CertPool) (*client, error) {
	url, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	c := &client{
		server: url,
		email:  email,
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: pebbleCAPool,
				},
			},
		},
		privKey: jose.SigningKey{
			Key:       privKey,
			Algorithm: jose.RS256,
		},
	}

	err = c.updateDirectory()
	if err != nil {
		return nil, err
	}

	err = c.updateNonce()
	if err != nil {
		return nil, err
	}

	err = c.register()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *client) signEmbedded(data []byte, url string) (*jose.JSONWebSignature, error) {
	signer, err := jose.NewSigner(c.privKey, &jose.SignerOptions{
		NonceSource: c,
		EmbedJWK:    true,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	})
	if err != nil {
		return nil, err
	}

	signed, err := signer.Sign(data)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

func (c *client) signKeyID(data []byte, url string) (*jose.JSONWebSignature, error) {
	jwk := &jose.JSONWebKey{
		Key:       c.privKey.Key,
		Algorithm: "RSA",
		KeyID:     c.acctID,
	}

	signerKey := jose.SigningKey{
		Key:       jwk,
		Algorithm: jose.RS256,
	}

	opts := &jose.SignerOptions{
		NonceSource: c,
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"url": url,
		},
	}

	signer, err := jose.NewSigner(signerKey, opts)
	if err != nil {
		fmt.Printf("Err making signer: %#v\n", err)
		return nil, err
	}
	signed, err := signer.Sign(data)
	if err != nil {
		fmt.Printf("Err using signer: %#v\n", err)
		return nil, err
	}
	return signed, nil
}

func (c *client) updateDirectory() error {
	fmt.Printf("Requesting directory from %q\n", c.server.String())
	respBody, _, err := c.getAPI(c.server.String())
	if err != nil {
		return err
	}

	var directory map[string]interface{}
	err = json.Unmarshal(respBody, &directory)
	if err != nil {
		return err
	}

	c.directory = directory
	return nil
}

func (c *client) updateNonce() error {
	if rawNonceURL, present := c.directory["newNonce"]; !present || rawNonceURL.(string) == "" {
		return fmt.Errorf("Missing \"newNonce\" entry in server directory")
	}
	nonceURL := c.directory["newNonce"].(string)
	fmt.Printf("Requesting nonce from %q\n", nonceURL)

	before := c.nonce
	_, _, err := c.getAPI(nonceURL)
	if err != nil {
		return err
	}
	after := c.nonce

	if before == after {
		return fmt.Errorf("Did not receive a fresh nonce from newNonce URL")
	}
	return nil
}

func (c *client) register() error {
	if acctURL, ok := c.directory["newAccount"]; !ok || acctURL.(string) == "" {
		return fmt.Errorf("Missing \"newAccount\" entry in server directory")
	}
	acctURL := c.directory["newAccount"].(string)
	fmt.Printf("Registering new account with %q\n", acctURL)

	reqBody := struct {
		ToSAgreed bool `json:"termsOfServiceAgreed"`
		Contact   []string
	}{
		ToSAgreed: true,
		Contact:   []string{"mailto:" + c.email},
	}

	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	// Registration is a unique case where we _do_ want the JWK to be embedded (vs
	// using a Key ID) so we invoke `postAPI` with `true` for the embed argument.
	_, resp, err := c.postAPI(acctURL, reqBodyStr, true)
	if err != nil {
		return err
	}

	locHeader := resp.Header.Get("Location")
	if locHeader == "" {
		return fmt.Errorf("No 'location' header with account URL in response")
	}

	c.acctID = locHeader
	return nil
}

// Nonce satisfies the JWS "NonceSource" interface
func (c *client) Nonce() (string, error) {
	n := c.nonce
	err := c.updateNonce()
	if err != nil {
		return n, err
	}
	return n, nil
}

func (c *client) doReq(req *http.Request) ([]byte, *http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if n := resp.Header.Get("Replay-Nonce"); n != "" {
		c.nonce = n
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, nil, fmt.Errorf("Response %d: %s", resp.StatusCode, respBody)
	}
	return respBody, resp, nil
}

func (c *client) getAPI(url string) ([]byte, *http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Language", locale)
	return c.doReq(req)
}

func (c *client) postAPI(url string, body []byte, embedJWK bool) ([]byte, *http.Response, error) {
	var signedBody *jose.JSONWebSignature
	var err error

	if embedJWK {
		signedBody, err = c.signEmbedded(body, url)
	} else {
		signedBody, err = c.signKeyID(body, url)
	}

	if err != nil {
		return nil, nil, err
	}

	bodyBuf := bytes.NewBuffer([]byte(signedBody.FullSerialize()))
	req, err := http.NewRequest("POST", url, bodyBuf)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
	req.Header.Set("User-Agent", userAgent())
	req.Header.Set("Accept-Language", locale)
	return c.doReq(req)
}

func (c *client) endpoints() []string {
	res := make([]string, 0, len(c.directory))
	for k := range c.directory {
		res = append(res, k)
	}
	return res
}

func (c *client) readEndpoint() (string, error) {
	var endpoint string
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("$> Enter a directory endpoint or a URL to POST: ")
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "exit" || line == "q" {
			break
		}
		if _, ok := c.directory[line]; !ok {
			if url, err := url.Parse(line); err == nil {
				endpoint = url.String()
				break
			}
			fmt.Printf("Unknown directory endpoint or invalid URL: %q.\nAvailable choices: %s\n",
				line, strings.Join(c.endpoints(), ", "))
			fmt.Printf("$> Enter a directory endpoint to POST: ")
			continue
		}
		endpoint = c.directory[line].(string)
		break
	}
	if err := scanner.Err(); err != nil {
		return endpoint, err
	}
	return strings.TrimSpace(endpoint), nil
}

func (c *client) readJSON() ([]byte, error) {
	var jsonBuf string

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("$> Enter JSON body, empty line to finish : \n")
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line == "exit" || line == "q" {
			break
		}
		jsonBuf += line
	}

	var indented bytes.Buffer
	err := json.Indent(&indented, []byte(jsonBuf), "", "  ")
	return indented.Bytes(), err
}

func (c *client) repl() error {
	for {
		endpoint, err := c.readEndpoint()
		if err != nil {
			return err
		}
		if endpoint == "" {
			break
		}

		body, err := c.readJSON()
		if err != nil {
			return err
		}

		respBody, resp, err := c.postAPI(endpoint, body, false)
		if err != nil {
			return err
		}

		var indented bytes.Buffer
		_ = json.Indent(&indented, respBody, "", "  ")
		fmt.Printf("Response:\n%#v\n\n%s\n", resp, indented.String())
	}

	fmt.Println("Goodbye")
	return nil
}

func main() {
	server := flag.String("server", "https://localhost:14000/dir", "Directory address for Pebble server")
	email := flag.String("email", "", "Email address for ACME registration contact")
	caCert := flag.String("ca", "test/certs/pebble.minica.pem", "CA Certificate used to validate Pebble server HTTPS certificate")
	flag.Parse()

	pebbleCA, err := ioutil.ReadFile(*caCert)
	cmd.FailOnError(err,
		fmt.Sprintf("Unable to read CA certificate file specified: %q", *caCert))
	pebbleCAs := x509.NewCertPool()
	pebbleCAs.AppendCertsFromPEM(pebbleCA)

	fmt.Println("welcome to the pebble shell")

	c, err := newClient(*server, *email, pebbleCAs)
	cmd.FailOnError(err,
		fmt.Sprintf("Failed to make new pebble client with email %q", *email))

	fmt.Printf("Your account ID is %q\n", c.acctID)
	fmt.Println("Starting REPL environment...")
	err = c.repl()
	cmd.FailOnError(err, "REPL error")
}
