package main

type LoginPair struct {
  Username string
  Password string
}

type AuthenticationSessionCache struct {
  LoginCache map[string]LoginPair
}

func (c AuthenticationSessionCache) Lookup(session_id string) (string, string, error) {
  return "", "", nil
}
