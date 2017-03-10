package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
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
	"gopkg.in/square/go-jose.v1"
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
	signer    jose.Signer
	nonce     string
}

func newClient(server, email string) (*client, error) {
	url, err := url.Parse(server)
	if err != nil {
		return nil, err
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(jose.RS256, privKey)
	if err != nil {
		return nil, err
	}

	c := &client{
		server: url,
		email:  email,
		http:   &http.Client{},
		signer: signer,
	}

	err = c.updateDirectory()
	if err != nil {
		return nil, err
	}

	err = c.updateNonce()
	if err != nil {
		return nil, err
	}
	signer.SetNonceSource(c)

	err = c.register()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *client) sign(data []byte) (*jose.JsonWebSignature, error) {
	signed, err := c.signer.Sign(data)
	if err != nil {
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
	nonceURL := c.directory["new-nonce"].(string)
	if nonceURL == "" {
		return fmt.Errorf("Missing \"new-nonce\" entry in server directory")
	}
	fmt.Printf("Requesting nonce from %q\n", nonceURL)

	before := c.nonce
	_, _, err := c.getAPI(nonceURL)
	if err != nil {
		return err
	}
	after := c.nonce

	if before == after {
		return fmt.Errorf("Did not recieve a fresh nonce from new-nonce URL")
	}
	return nil
}

func (c *client) register() error {
	regURL := c.directory["new-reg"].(string)
	if regURL == "" {
		return fmt.Errorf("Missing \"new-reg\" entry in server directory")
	}
	fmt.Printf("Registering new account with %q\n", regURL)

	reqBody := struct {
		ToSAgreed bool `json:"terms-of-service-agreed"`
		Contact   []string
		Resource  string
	}{
		ToSAgreed: true,
		Contact:   []string{"mailto:" + c.email},
		Resource:  "new-reg",
	}

	reqBodyStr, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	_, resp, err := c.postAPI(regURL, reqBodyStr)
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

func (c *client) postAPI(url string, body []byte) ([]byte, *http.Response, error) {
	signedBody, err := c.sign(body)
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
	fmt.Printf("$> Enter a directory endpoint to POST: ")
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

		respBody, resp, err := c.postAPI(endpoint, body)
		if err != nil {
			return err
		}

		var indented bytes.Buffer
		err = json.Indent(&indented, respBody, "", "  ")
		fmt.Printf("Response:\n%#v\n\n%s\n", resp, indented.String())
	}

	fmt.Println("Goodbye")
	return nil
}

func main() {
	server := flag.String("server", "http://localhost:14000/dir", "Directory address for Pebble server")
	email := flag.String("email", "", "Email address for ACME registration contact")
	flag.Parse()

	fmt.Println("welcome to the pebble shell")

	c, err := newClient(*server, *email)
	cmd.FailOnError(err,
		fmt.Sprintf("Failed to make new pebble client with email %q", *email))

	fmt.Printf("Your account ID is %q\n", c.acctID)
	fmt.Println("Starting REPL environment...\n\n")
	err = c.repl()
	cmd.FailOnError(err, "REPL error")
}
