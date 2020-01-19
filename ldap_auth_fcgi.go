package main

import (
  "flag"
  "gopkg.in/yaml.v2"
  "net"
  "net/http"
  "net/http/fcgi"
  "io/ioutil"
  "log"
)

type AuthenticationServer struct {
  Authenticator Authenticator
  Cache AuthenticationSessionCache
}

func (a AuthenticationServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {

  cookie, err := r.Cookie("auth_session")

  if err == nil {
    _,_, err = a.Cache.Lookup(cookie.Value)
    if err != nil {
      w.Write([]byte("200 - OK"))
      return;
    }
  }

  if r.Method == "POST" {
    err := r.ParseForm()
    if err != nil {
      w.WriteHeader(http.StatusBadRequest)
      w.Write([]byte("400 - Bad Request"))
      return
    }

    username := r.Form.Get("username")
    password := r.Form.Get("password")
    if err := a.Authenticator.Authenticate(username, password); err == nil {
      w.Write([]byte("200 - OK"))
      return;
    }
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
  server := LdapAuthenticationServer{}
  err := configure(&server.Authenticator)

  if err != nil {
    log.Fatal(err)
  }

  l, err := net.Listen("tcp", ":8080")
  if err != nil {
    log.Fatal(err)
  }

  fcgi.Serve(l, server)

}
