// Copyright 2014 Canonical Ltd.

// The config package defines configuration parameters for the id server.
package config

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/errgo.v1"
	"gopkg.in/yaml.v1"
)

// Config holds the configuration parameters for the identity service.
type Config struct {
	MongoAddr    string `yaml:"mongo-addr"`
	APIAddr      string `yaml:"api-addr"`
	AuthUsername string `yaml:"auth-username"`
	AuthPassword string `yaml:"auth-password"`
	PublicKey    string `yaml:"public-key"`
	PrivateKey   string `yaml:"private-key"`
}

func (c *Config) validate() error {
	var missing []string
	if c.MongoAddr == "" {
		missing = append(missing, "mongo-addr")
	}
	if c.APIAddr == "" {
		missing = append(missing, "api-addr")
	}
	if c.AuthUsername == "" {
		missing = append(missing, "auth-username")
	}
	if strings.Contains(c.AuthUsername, ":") {
		return fmt.Errorf("invalid user name %q (contains ':')", c.AuthUsername)
	}
	if c.AuthPassword == "" {
		missing = append(missing, "auth-password")
	}
	if c.PrivateKey == "" {
		missing = append(missing, "private-key")
	}
	if c.PublicKey == "" {
		missing = append(missing, "public-key")
	}
	if len(missing) != 0 {
		return errgo.Newf("missing fields %s in config file", strings.Join(missing, ", "))
	}
	return nil
}

// Read reads an identity configuration file from the given path.
func Read(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errgo.Notef(err, "cannot open config file")
	}
	defer f.Close()
	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, errgo.Notef(err, "cannot read %q", path)
	}
	var conf Config
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, errgo.Notef(err, "cannot parse %q", path)
	}
	if err := conf.validate(); err != nil {
		return nil, errgo.Mask(err)
	}
	return &conf, nil
}
