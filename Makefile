
GO_SRCS = $(wildcard *.go)

ldap_auth: $(GO_SRCS)
	go build -o $@
