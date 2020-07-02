// This is a small shim on golang's oauth2 library to add device flow. 
// If the library adds its own support, this file can be eliminated.
//
// The below code was copied from
//   https://raw.githubusercontent.com/rjw57/oauth2device/master/oauth2device.go
// on 16 June 2020.  Documentation for the original code was available at 
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
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// A DeviceCode represents the user-visible code, verification URL and
// device-visible code used to allow for user authorisation of this app. The
// app should show UserCode and VerificationURL to the user.
type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
}

// DeviceEndpoint contains the URLs required to initiate the OAuth2.0 flow for a
// provider's device flow.
type DeviceEndpoint struct {
	CodeURL string
}

// A version of oauth2.Config augmented with device endpoints
type Config struct {
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
	deviceGrantType = "http://oauth.net/grant_type/device/1.0"
)

// RequestDeviceCode will initiate the OAuth2 device authorization flow. It
// requests a device code and information on the code and URL to show to the
// user. Pass the returned DeviceCode to WaitForDeviceAuthorization.
func RequestDeviceCode(client *http.Client, config *Config) (*DeviceCode, error) {
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

	return &dcr, nil
}

// WaitForDeviceAuthorization polls the token URL waiting for the user to
// authorize the app. Upon authorization, it returns the new token. If
// authorization fails then an error is returned. If that failure was due to a
// user explicitly denying access, the error is ErrAccessDenied.
func WaitForDeviceAuthorization(client *http.Client, config *Config, code *DeviceCode) (*oauth2.Token, error) {
	for {

		resp, err := client.PostForm(config.Endpoint.TokenURL,
			url.Values{
				"client_secret": {config.ClientSecret},
				"client_id":     {config.ClientID},
				"code":          {code.DeviceCode},
				"grant_type":    {deviceGrantType}})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP error %v (%v) when polling for OAuth token",
				resp.StatusCode, http.StatusText(resp.StatusCode))
		}

		// Unmarshal response, checking for errors
		var token tokenOrError
		dec := json.NewDecoder(resp.Body)
		if err := dec.Decode(&token); err != nil {
			return nil, err
		}

		switch token.Error {
		case "":

			return token.Token, nil
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
