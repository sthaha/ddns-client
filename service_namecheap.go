package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/net/html/charset"
)

type nameCheapService Ddns

type dictionary struct {
	ErrCount int `xml:"ErrCount"`
}

func (s *nameCheapService) getDomain() string {
	return s.Domain
}

func (s *nameCheapService) updateIP() error {
	skip := 0
	if strings.HasPrefix(s.Domain, "*.") {
		skip = 2
	}

	pos := strings.Index(s.Domain[skip:], ".") + skip
	if pos < 1 {
		return errors.New("Incorrect domain.")
	}

	host := s.Domain[0:pos]
	domain := s.Domain[pos+1 : len(s.Domain)]

	url := "https://dynamicdns.park-your-domain.com/update?domain=" + domain + "&host=" + host + "&password=" + s.Password
	content, err := GetResponse(url, "", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "content: %v \n ", content)
		return err
	}

	nr, err := charset.NewReader(bytes.NewReader([]byte(content)), "utf-16")
	if err != nil {
		return err
	}
	bypassReader := func(label string, input io.Reader) (io.Reader, error) {
		return input, nil
	}

	decoder := xml.NewDecoder(nr)
	decoder.CharsetReader = bypassReader

	var dict dictionary
	err = decoder.Decode(&dict)
	if err != nil {
		return err
	}

	if dict.ErrCount > 0 {
		return errors.New("Unable to update ip address.")
	}

	return nil
}

//<?xml version="1.0"?>
//<interface-response>
// <Command>SETDNSHOST</Command>
// <Language>eng</Language>
// <IP>x.x.x.x</IP>
// <ErrCount>0</ErrCount>
// <ResponseCount>0</ResponseCount>
// <Done>true</Done>
// <debug><![CDATA[]]></debug>
//</interface-response>
