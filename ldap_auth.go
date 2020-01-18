package main

import (
  "flag"
  "fmt"
  "gopkg.in/ldap.v3"
  "gopkg.in/yaml.v2"
  "net"
  "net/http"
  "net/http/fcgi"
  "io/ioutil"
  "log"
  "regexp"
  "encoding/base64"
  "errors"
)

type LdapAuthenticator struct {
  Ldap_Host string
  Ldap_Port int
  Ldap_Bind_Template string
}

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

func (a LdapAuthenticator) ServeHTTP(w http.ResponseWriter, r *http.Request) {

  auth := r.Header.Get("Authorization")

  username, password, err := ParseBasicAuth(auth)
  if (err == nil) {
    conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.Ldap_Host, a.Ldap_Port))
    if err == nil {
      err =  conn.Bind(fmt.Sprintf(a.Ldap_Bind_Template, username), password)
      if err == nil {
        w.Write([]byte("200 - OK"))
        return
      }
    }
  } else {
    log.Print(err)
  }
  w.WriteHeader(http.StatusUnauthorized)
  w.Header().Set("Www-Authenticate", "Basic")
  w.Write([]byte("401 - Unauthorized"))
}

func configure(config *LdapAuthenticator) (error) {
  configPathPtr := flag.String("config", "config.yml", "The configuration file to perform authentication.")
  flag.Parse()

  data, err := ioutil.ReadFile(*configPathPtr)

  if (err != nil) {
    return err
  }
  err = yaml.Unmarshal(data, config);

  if err != nil {
    return err
  }

  return nil
}

func main() {
  config := LdapAuthenticator{}
  err := configure(&config)

  if err != nil {
    log.Fatal(err)
  }

  l, err := net.Listen("tcp", ":8080")
  if err != nil {
    log.Fatal(err)
  }

  fcgi.Serve(l, config)

}
