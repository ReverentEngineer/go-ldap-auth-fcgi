package main

import (
  "regexp"
  "encoding/base64"
  "errors"
)

var BasicAuthRegex = regexp.MustCompile("^Basic ((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$")

var UserPassRegex = regexp.MustCompile("^(.+):(.+)$")

func ParseBasicAuth(a string) (string, string, error) {
    re := BasicAuthRegex.FindAllStringSubmatch(a, -1)

    if  len(re) == 0 {
      return "", "", errors.New("Invalid Authorization header")
    }

    decoded, err := base64.StdEncoding.DecodeString(re[0][1])

    if err != nil {
      return "", "", err
    }

    re = UserPassRegex.FindAllStringSubmatch(string(decoded), -1)
    if len(re) == 0 {
      return "", "", errors.New("Invalid Authorization header")
    }
    return re[0][1], re[0][2], nil
}


