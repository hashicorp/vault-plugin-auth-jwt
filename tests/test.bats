#!/usr/bin/env bats

# Setup
#
# 1. Configure an OIDC provider. See https://www.vaultproject.io/docs/auth/jwt/oidc_providers
#     for examples.
# 2. Save and export the following values to your shell:
#     CLIENT_ID
#     CLIENT_SECRET
#     ISSUER
# 3. Export VAULT_IMAGE to test the image of your choice.
# 4. Export VAULT_LICENSE. This test will only work for enterprise images

# Logs
#
# Vault logs will be written to VAULT_OUTFILE.
# BATs test logs will be written to SETUP_TEARDOWN_OUTFILE.

export VAULT_ADDR='http://127.0.0.1:8200'
SETUP_TEARDOWN_OUTFILE=/tmp/bats-test.log
VAULT_OUTFILE=/tmp/vault.log
export VAULT_TOKEN='root'
export VAULT_IMAGE="${VAULT_IMAGE:-hashicorp/vault-enterprise:1.9.0-rc1_ent}"

# assert_status evaluates if $1 is equal to $2. If they are not equal a log
# is written to the output file.
assert_status() {
  local got
  local expect
  got="$1"
  expect="$2"

  [ "${expect?}" -eq "${got}" ] || log_err "status - expect: ${expect} got: ${got}"
}

# assert_output_partial performs a string match of $1 and $2. A partial match
# will evaluate to true. If no match is found a log is written to the output file.
assert_output_partial() {
  local got
  local expect
  got="$1"
  expect="$2"

  [[ "${output}" =~ "$(cat $expect)" ]] || log_err "output - expect: ${expect} got: ${got}"
}

log() {
  echo "INFO: $(date): $@" >> $SETUP_TEARDOWN_OUTFILE
}

log_err() {
  echo "ERROR: $(date): $@" >> $SETUP_TEARDOWN_OUTFILE
  exit 1
}

# setup_file runs once before all tests
setup_file(){
    # clear log file
    echo "" > $SETUP_TEARDOWN_OUTFILE

    VAULT_TOKEN='root'

    log "BEGIN SETUP"

    {
    [ ${CLIENT_ID?} ]
    [ ${CLIENT_SECRET?} ]
    [ ${ISSUER?} ]
    [ ${VAULT_LICENSE?} ]

    log "VAULT_LICENSE: $VAULT_LICENSE"

    docker pull ${VAULT_IMAGE?}

    docker run \
      --name=vault \
      --hostname=vault \
      -p 8200:8200 \
      -e VAULT_DEV_ROOT_TOKEN_ID="root" \
      -e VAULT_ADDR="http://localhost:8200" \
      -e VAULT_DEV_LISTEN_ADDRESS="0.0.0.0:8200" \
      -e VAULT_LICENSE="${VAULT_LICENSE?}" \
      --privileged \
      --detach ${VAULT_IMAGE?}

    } >> $SETUP_TEARDOWN_OUTFILE

    log "waiting for vault..."
    while ! vault status >/dev/null 2>&1; do sleep 1; done; echo

    vault login ${VAULT_TOKEN?}

    run vault status
    assert_status "${status}" 0
    log "vault started successfully"

    log "END SETUP"
}

# teardown_file runs once after all tests complete
teardown_file(){
    log "BEGIN TEARDOWN"

    docker rm vault --force

    log "END TEARDOWN"
}

@test "Setup namespace" {
    run vault read -format=json sys/license/status
    log "${output}"
    assert_status "${status}" 0

    run vault namespace create ns1
    assert_status "${status}" 0

    VAULT_NAMESPACE=ns1
}

@test "Enable oidc auth" {
    run vault auth enable oidc
    log "${output}"
    assert_status "${status}" 0
}

@test "Setup kv and policies" {
    run vault secrets enable -version=2 kv
    assert_status "${status}" 0

    run vault kv put kv/my-secret/secret-1 value=1234
    assert_status "${status}" 0

    run vault kv put kv/your-secret/secret-2 value=5678
    assert_status "${status}" 0

    run vault policy write test-policy -<<EOF
path "kv/data/my-secret/*" {
  capabilities = [ "read" ]
}

EOF
    assert_status "${status}" 0

}

@test "POST /auth/oidc/config - write config" {
    run vault write auth/oidc/config \
      oidc_discovery_url="$ISSUER" \
      oidc_client_id="$CLIENT_ID" \
      oidc_client_secret="$CLIENT_SECRET" \
      default_role="test-role" \
      bound_issuer="localhost"
    assert_status "${status}" 0
}

@test "POST /auth/oidc/role/:name - create a role" {
    run vault write auth/oidc/role/test-role \
      user_claim="sub" \
      allowed_redirect_uris="http://localhost:8250/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback" \
      bound_audiences="$CLIENT_ID" \
      oidc_scopes="openid" \
      ttl=1h \
      policies="test-policy" \
      verbose_oidc_logging=true
    assert_status "${status}" 0

    run vault write auth/oidc/role/test-role-2 \
      user_claim="sub" \
      allowed_redirect_uris="http://localhost:8250/oidc/callback,http://localhost:8200/ui/vault/auth/oidc/oidc/callback" \
      bound_audiences="$CLIENT_ID" \
      oidc_scopes="openid" \
      ttl=1h \
      policies="test-policy" \
      verbose_oidc_logging=true
    assert_status "${status}" 0
}

@test "LIST /auth/oidc/role - list roles" {
    run vault list auth/oidc/role
    assert_status "${status}" 0
    assert_output_partial "${output}" fixtures/list_roles.txt
}

@test "GET /auth/oidc/role/:name - read a role" {
    run vault read auth/oidc/role/test-role
    assert_status "${status}" 0
    assert_output_partial "${output}" fixtures/read_role.txt
}

@test "DELETE /auth/oidc/role/:name - delete a role" {
    run vault delete auth/oidc/role/test-role-2
    assert_status "${status}" 0
}

# this test will open your default browser and ask you to login with your
# OIDC Provider
@test "Login with oidc auth" {
    unset VAULT_TOKEN
    run vault login -method=oidc
    assert_status "${status}" 0
    assert_output_partial "${output}" fixtures/oidc_login.txt
}

@test "Test policy prevents kv read" {
    unset VAULT_TOKEN
    run vault kv get kv/your-secret/secret-2
    assert_status "${status}" 2
    assert_output_partial "${output}" fixtures/bad_read_kv.txt
}

@test "Test policy allows kv read" {
    unset VAULT_TOKEN
    run vault kv get kv/my-secret/secret-1
    assert_status "${status}" 0
    assert_output_partial "${output}" fixtures/good_read_kv.txt
}
