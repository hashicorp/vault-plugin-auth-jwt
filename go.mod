module github.com/hashicorp/vault-plugin-auth-jwt

go 1.12

require (
	github.com/coreos/go-oidc v2.0.0+incompatible
	github.com/go-test/deep v1.0.2-0.20181118220953-042da051cf31
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.9.2
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/vault v1.1.3-0.20190703041405-a2810eb6965d
	github.com/hashicorp/vault/api v1.0.3-0.20190703041312-5337e16868c2
	github.com/hashicorp/vault/sdk v0.1.12-0.20190703041405-a2810eb6965d
	github.com/mitchellh/pointerstructure v0.0.0-20190430161007-f252a8fd71c8
	github.com/patrickmn/go-cache v2.1.0+incompatible
	golang.org/x/oauth2 v0.0.0-20190402181905-9f3314589c9a
	gopkg.in/square/go-jose.v2 v2.3.1
)
