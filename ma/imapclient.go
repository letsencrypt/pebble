package ma

import (
	"bytes"
	"io"
	"log"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-msgauth/dkim"
)

//those are for TLS setting for servers.
const (
	None     = iota
	Explict  //starttls
	Implicit //imap over TLS
)

type MailTaskGet struct {
	address    string
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
}

// NewFetcher make new mail fetcher that curaties imap connection. send empty mailbox, it will filled with io.reader
func NewFetcher(address string, log *log.Logger, username string, password string) (*MailFetcher, error) {
	c := &MailFetcher{
		log:        log,
		imapserver: address,
		username:   username,
		password:   password,
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

func (c *MailFetcher) Fetch(address string) [][]byte {
	f := make(chan *imap.Message)
	c.tasks <- &MailTaskGet{
		address:    address,
		mailchanel: f,
	}
	var mails [][]byte
	for i := range f {
		for _, literal := range i.Body {
			mails = append(mails, StreamToByte(literal))
		}
	}
	return mails
}

func (c *MailFetcher) processTasks() {
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
		criteria.Header.Add("SUBJECT", "ACME: ")
		criteria.WithoutFlags = []string{imap.SeenFlag}
		ids, err := c.clt.Search(criteria)
		if err != nil {
			c.log.Printf("mail Search failed server side")
		}
		seqset := new(imap.SeqSet)
		if len(ids) > 0 {
			seqset.AddNum(ids...)
		}
		c.clt.Fetch(seqset, []imap.FetchItem{imap.FetchItem("BODY[]")}, task.mailchanel)
		//we sent all, close
		close(task.mailchanel)
	}
}

func checkDkim(mail []byte, domain string) bool {
	// string type can't be constant in golang so it's variable
	HeaderKeyNeeded := []string{
		"From", "Sender", "Reply-To", "To", "CC", "Subject",
		"Date", "In-Reply-To", "References", "Message-ID",
		"Content-Type", "Content-Transfer-Encoding",
	}
	signs, err := dkim.Verify(bytes.NewReader(mail))
	//invalid or no signs on this mail
	if err != nil || len(signs) != 0 {
		return false
	}
	for _, sign := range signs {
		// is dkim sender is our expected domain?
		if sign.Domain != domain {
			return false
		}
		// Does this dkim have all the field we need?
		for _, hn := range HeaderKeyNeeded {
			hasheader := false
			for _, h := range sign.HeaderKeys {
				if h == hn {
					hasheader = true
					break
				}
			}
			if !hasheader {
				return false
			}
		}
	}
	return true
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}
