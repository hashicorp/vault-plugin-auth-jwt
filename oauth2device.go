// This is a small shim on golang's oauth2 library to add device flow. 
// If the library adds its own support, this file can be eliminated.
//
// The below code was copied from
//   https://raw.githubusercontent.com/rjw57/oauth2device/master/oauth2device.go
// on 16 June 2020 and updated according to the more recent RFC8628.
// Documentation for the original code was available at 
//   https://godoc.org/github.com/rjw57/oauth2device
// The BSD license applied was this:
// 
// Copyright (c) 2014, Rich Wareham rich.oauth2device@richwareham.com
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 
//   1. Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//   2. Redistributions in binary form must reproduce the above
//      copyright notice, this list of conditions and the following
//      disclaimer in the documentation and/or other materials provided
//      with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
// WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package jwtauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// A DeviceCode represents the user-visible code, verification URI and
// device-visible code used to allow for user authorisation of this app.
// The VerificationURIComplete is optional and combines the user code
// and verification URI.  If present, apps may choose to show to
// the user the VerificationURIComplete, otherwise the app should show
// the UserCode and VerificationURL to the user.  ExpiresIn is how many
// seconds the user has to respond, and the optional Interval is how many
// seconds the app should wait in between polls (default 5).
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// DeviceEndpoint contains the URLs required to initiate the OAuth2.0 flow for a
// provider's device flow.
type DeviceEndpoint struct {
	CodeURL string
}

// A version of oauth2.Config augmented with device endpoints
type DeviceConfig struct {
	*oauth2.Config
	DeviceEndpoint DeviceEndpoint
}

// A tokenOrError is either an OAuth2 Token response or an error indicating why
// such a response failed.
type tokenOrError struct {
	*oauth2.Token
	Error string `json:"error,omitempty"`
}

var (
	// ErrAccessDenied is an error returned when the user has denied this
	// app access to their account.
	ErrAccessDenied = errors.New("access denied by user")
)

const (
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"
)

// RequestDeviceCode will initiate the OAuth2 device authorization flow. It
// requests a device code and information on the code and URL to show to the
// user. Pass the returned DeviceCode to WaitForDeviceAuthorization.
func RequestDeviceCode(client *http.Client, config *DeviceConfig) (*DeviceCode, error) {
	scopes := strings.Join(config.Scopes, " ")
	resp, err := client.PostForm(config.DeviceEndpoint.CodeURL,
		url.Values{"client_id": {config.ClientID}, "scope": {scopes}})

	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"request for device code authorisation returned status %v (%v)",
			resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Unmarshal response
	var dcr DeviceCode
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&dcr); err != nil {
		return nil, err
	}

	if dcr.Interval == 0 {
		dcr.Interval = 5
	}

	return &dcr, nil
}

// WaitForDeviceAuthorization polls the token URL waiting for the user to
// authorize the app. Upon authorization, it returns the new token. If
// authorization fails then an error is returned. If that failure was due to a
// user explicitly denying access, the error is ErrAccessDenied.
func WaitForDeviceAuthorization(client *http.Client, config *DeviceConfig, code *DeviceCode) (*oauth2.Token, error) {
	for {

		resp, err := client.PostForm(config.Endpoint.TokenURL,
			url.Values{
				"client_secret": {config.ClientSecret},
				"client_id":     {config.ClientID},
				"device_code":   {code.DeviceCode},
				"grant_type":    {deviceGrantType}})
		if err != nil {
			return nil, fmt.Errorf("post error while polling for OAuth token: %v", err)
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
			return nil, fmt.Errorf("HTTP error %v (%v) when polling for OAuth token",
				resp.StatusCode, http.StatusText(resp.StatusCode))
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error reading response body while polling for OAuth token: %v", err)
		}

		// Unmarshal response, checking for errors
		var token tokenOrError
		if err := json.Unmarshal(body, &token); err != nil {
			return nil, fmt.Errorf("error decoding response body while polling for OAuth token: %v", err)
		}


		switch token.Error {
		case "":

			extra := make(map[string]interface{})
			err := json.Unmarshal(body, &extra)
			if err != nil {
				// already been unmarshalled once, unlikely
				return nil, err
			}
			return token.Token.WithExtra(extra), nil
		case "authorization_pending":

		case "slow_down":

			code.Interval *= 2
		case "access_denied":

			return nil, ErrAccessDenied
		default:

			return nil, fmt.Errorf("authorization failed: %v", token.Error)
		}

		time.Sleep(time.Duration(code.Interval) * time.Second)
	}
}
