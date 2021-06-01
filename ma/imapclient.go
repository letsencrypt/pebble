package ma

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/letsencrypt/pebble/acme"
)

//those are for TLS setting for servers.
const (
	None     = iota
	Explict  //starttls
	Implicit //imap over TLS
)

type MailTaskGet struct {
	address    string
	tokenPart1 string
	mailchanel chan *imap.Message
}

type MailFetcher struct {
	log        *log.Logger
	imapserver string
	username   string
	password   string
	tasks      chan *MailTaskGet
	clt        *client.Client
	istls      int
	verifydkim bool
}

// NewFetcher make new mail fetcher that curaties imap connection. send empty mailbox, it will filled with io.reader
func NewFetcher(log *log.Logger, address string, username string, password string, verifydkim bool) (*MailFetcher, error) {
	c := &MailFetcher{
		log:        log,
		imapserver: address,
		username:   username,
		password:   password,
		tasks:      make(chan *MailTaskGet),
		verifydkim: verifydkim,
	}
	c.istls = Implicit
	imapclient, err := client.DialTLS(address, nil)
	if err != nil {
		imapclient, err = client.Dial(address)
		if err != nil {
			return nil, err
		}
		c.istls = None
		if b, _ := imapclient.SupportStartTLS(); b {
			imapclient.StartTLS(nil)
			c.istls = Explict
		}
	}
	// connected so
	c.clt = imapclient
	if err = c.clt.Login(username, password); err != nil {
		c.log.Printf("Failed to Login to IMAP server, wrong account?")
	}
	if err == nil {
		c.log.Printf("Connected to remote Imap server")
		_, err := c.clt.Select("INBOX", false)
		if err != nil {
			log.Fatal(err)
		}
		go c.processTasks()
		return c, nil
	}

	c.log.Printf("you shouldn't reach here")
	return nil, err
}

//Fetch look for imap message from mailserver, verify dkim sig if configed to, and return raw mail as slice of []byte
func (c *MailFetcher) Fetch(address string, tokenPart1 string) [][]byte {
	c.log.Printf("enter ma %s, looking que %p", address, c.tasks)
	f := make(chan *imap.Message)
	//why it stuck here?
	c.tasks <- &MailTaskGet{
		address:    address,
		tokenPart1: tokenPart1,
		mailchanel: f,
	}
	var mails [][]byte
	for i := range f {
		//this for doesn't loop, which literal is full mail body
		for _, literal := range i.Body {
			mailbytes := streamToByte(literal)
			if c.verifydkim {
				valid, dkerr := checkDkim(mailbytes, address[strings.LastIndex(address, "@")+1:])
				if !valid {
					c.log.Println(dkerr.Detail)
					continue
				}
			}
			mails = append(mails, mailbytes)
		}
	}
	return mails
}

func (c *MailFetcher) processTasks() {
	c.log.Printf("listening tasks : %p", c.tasks)
	for task := range c.tasks {
		//Can't spawn goroutine here as imap client isn't safe to use concurrently
		//test if connection is alive
		if c.clt.State() == imap.LogoutState {
			//we are offline, connect again.
			if c.istls == Implicit {
				c.clt, _ = client.DialTLS(c.imapserver, nil)
			} else {
				c.clt, _ = client.Dial(c.imapserver)
				if c.istls == Explict {
					c.clt.StartTLS(nil)
				}
			}
			c.clt.Login(c.username, c.password)
			c.clt.Select("INBOX", false)
		}
		//now get ACME related mail from challenge sender
		criteria := imap.NewSearchCriteria()
		criteria.Header.Add("FROM", task.address)
		//looking for mail with token
		criteria.Header.Add("SUBJECT", fmt.Sprintf("ACME: %s", task.tokenPart1))
		ids, err := c.clt.Search(criteria)
		if err != nil {
			c.log.Printf("mail Search failed server side")
		}
		seqset := new(imap.SeqSet)
		if len(ids) > 0 {
			seqset.AddNum(ids...)
		}
		c.clt.Fetch(seqset, []imap.FetchItem{imap.FetchItem("BODY[]")}, task.mailchanel)
		//this close task.mailchanel so no close(task.mailchanel) needed
	}
}

func checkDkim(mail []byte, domain string) (bool, *acme.ProblemDetails) {
	// string type can't be constant in golang so it's variable
	HeaderKeyNeeded := []string{
		"From", "Sender", "Reply-To", "To", "CC", "Subject",
		"Date", "In-Reply-To", "References", "Message-ID",
		"Content-Type", "Content-Transfer-Encoding",
	}
	signs, err := dkim.Verify(bytes.NewReader(mail))
	//invalid or no signs on this mail
	if err != nil || len(signs) != 0 {
		return false, acme.UnauthorizedProblem("mail had no dkim signiture in it")
	}
	var invaliddkimreason *acme.ProblemDetails
	var haddomains []string
	for _, sign := range signs {
		// is dkim sender is our expected domain?
		if sign.Domain != domain {
			haddomains = append(haddomains, sign.Domain)
			continue
		}
		// Does this dkim have all the Headers we need?
		var missingheader []string
		for _, hn := range HeaderKeyNeeded {
			hasheader := false
			for _, h := range sign.HeaderKeys {
				if h == hn {
					hasheader = true
					break
				}
			}
			if !hasheader {
				missingheader = append(missingheader, hn)
			}
		}
		if len(missingheader) != 0 {
			invaliddkimreason =
				acme.UnauthorizedProblem(fmt.Sprintf("dkim sign form domain %s does not cover required header(s): %s", domain, missingheader))
		} else {
			return true, nil
		}
	}
	if invaliddkimreason == nil {
		invaliddkimreason = acme.UnauthorizedProblem(fmt.Sprintf("dkim sign wasn't didn't mach requested mail's domain %s, found sign form %s", domain, haddomains))
	}
	return false, invaliddkimreason
}

func streamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}
