// Copyright 2016 Canonical Ltd.

package admincmd

import (
	"encoding/json"
	"io"
	"os"

	errgo "gopkg.in/errgo.v1"
	"gopkg.in/macaroon-bakery.v2-unstable/bakery"
)

// Note: the types and methods in this file will be moved to
// gopkg.in/macaroon-bakery.v2-unstable/httpbakery/agent and used from
// there after it stabalizes.

// Agent holds the details of an agent used for login.
type Agent struct {
	// URL holds the URL of the identity server for this agent.
	URL string `json:"url,omitempty"`

	// Username holds the agent's user name.
	Username string `json:"username"`

	// PublicKey holds the agent's public key.
	PublicKey *bakery.PublicKey `json:"public_key"`

	// PrivateKey holds the agent's private key.
	PrivateKey *bakery.PrivateKey `json:"private_key,omitempty"`
}

// Load loads an Agent from the file at the given path.
func Load(path string) (Agent, error) {
	f, err := os.Open(path)
	if err != nil {
		return Agent{}, errgo.Mask(err)
	}
	defer f.Close()
	a, err := Read(f)
	if err != nil {
		return Agent{}, errgo.Notef(err, "cannot load agent from %s", path)
	}
	return a, nil
}

// Read reads an agent from the given reader.
func Read(r io.Reader) (Agent, error) {
	dec := json.NewDecoder(r)
	var a Agent
	if err := dec.Decode(&a); err != nil {
		return Agent{}, errgo.Mask(err)
	}
	return a, nil
}

// Write writes the given agent information to the given writer in JSON
// format.
func Write(w io.Writer, a Agent) error {
	enc := json.NewEncoder(w)
	return errgo.Mask(enc.Encode(a))
}
