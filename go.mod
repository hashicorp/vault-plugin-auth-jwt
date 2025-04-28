module github.com/hashicorp/vault-plugin-auth-jwt

go 1.23.8

require (
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/go-test/deep v1.1.1
	github.com/hashicorp/cap v0.8.0
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/httputil v0.1.0
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.7
	github.com/hashicorp/vault/api v1.15.0
	github.com/hashicorp/vault/sdk v0.14.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mitchellh/pointerstructure v1.2.1
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/ryanuber/go-glob v1.0.0
	github.com/stretchr/testify v1.10.0
	golang.org/x/oauth2 v0.29.0
	golang.org/x/sync v0.13.0
	google.golang.org/api v0.230.0
)

require (
	cloud.google.com/go/auth v0.16.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.6.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/coreos/go-oidc/v3 v3.11.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/docker v27.2.1+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/evanphx/json-patch/v5 v5.6.0 // indirect
	github.com/fatih/color v1.17.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/googleapis/gax-go/v2 v2.14.1 // indirect
	github.com/hashicorp/go-hmac-drbg v0.0.0-20210916214228-a6e5a68489f6 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-kms-wrapping/entropy/v2 v2.0.1 // indirect
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.16 // indirect
	github.com/hashicorp/go-plugin v1.6.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/cryptoutil v0.1.0 // indirect
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.3 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.8 // indirect
	github.com/hashicorp/go-secure-stdlib/plugincontainer v0.4.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.1-vault-5 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/joshlf/go-acl v0.0.0-20200411065538-eae00ae38531 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/petermattis/goid v0.0.0-20240813172612-4fcff4a6cae7 // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/sasha-s/go-deadlock v0.3.5 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.60.0 // indirect
	go.opentelemetry.io/otel v1.35.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.29.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/trace v1.35.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.37.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250414145226-207652e42e2e // indirect
	google.golang.org/grpc v1.72.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
