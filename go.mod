module github.com/hashicorp/vault-plugin-auth-jwt

go 1.13

require (
	github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/go-test/deep v1.0.4
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.10.0
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/mitchellh/pointerstructure v0.0.0-20190430161007-f252a8fd71c8
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pquerna/cachecontrol v0.0.0-20180517163645-1555304b9b35 // indirect
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6
	gopkg.in/square/go-jose.v2 v2.4.0
)
