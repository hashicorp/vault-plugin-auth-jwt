#!/bin/bash

vault write auth/oidc/config oidc_discovery_url="https://dev-941076.oktapreview.com/oauth2/default" oidc_client_id="0oaibg2dkd1NzjOZW0h7" oidc_client_secret="F4YTt5fOmiA_E6VzbvsFQpe2OC6zA2BzRWIlocj8" default_role="test" oidc_response_mode="form_post"
vault write auth/oidc/role/test role_type=oidc user_claim="email"  oidc_scopes="email,profile,groups" allowed_redirect_uris="http://127.0.0.1:8300/v1/auth/oidc/oidc/callback" allowed_redirect_uris="http://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback" groups_claim="groups" claim_mappings=manager=manager claim_mappings=language=preferred_language  allowed_redirect_uris="http://localhost:8300/oidc/callback"
allowed_redirect_uris="http://127.0.0.1:8200/ui/vault/auth/oidc/oidc/callback?namespace=ns1" allowed_redirect_uris="http://127.0.0.1:8200/v1/auth/oidc/oidc/form_post"
