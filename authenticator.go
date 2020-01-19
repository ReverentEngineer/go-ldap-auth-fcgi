package main

import (
  "fmt"
  "gopkg.in/ldap.v3"
)

type Authenticator interface {
  Authenticate(string, string) error
}

type LdapAuthenticator struct {
  Ldap_Host string
  Ldap_Port int
  Ldap_Bind_Template string
}

func (a LdapAuthenticator) Authenticate(username string, password string) (error) {
  conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", a.Ldap_Host, a.Ldap_Port))

  if err != nil {
    return err
  }

  err = conn.Bind(fmt.Sprintf(a.Ldap_Bind_Template, username), password)

  if err != nil {
    return err
  }

  return nil;
}
