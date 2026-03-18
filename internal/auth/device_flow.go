package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	githubDeviceCodeURL = "https://github.com/login/device/code"
	githubTokenURL      = "https://github.com/login/oauth/access_token"

	// DefaultScopes are the minimum scopes required for gh-secure.
	DefaultScopes = "repo,read:org"
)

// DeviceCodeResponse is returned by the initial device code request.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenResponse is returned after successful authorization.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
}

// DeviceFlowError is returned when the token poll gets an error.
type DeviceFlowError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *DeviceFlowError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// RequestDeviceCode initiates the device flow by requesting a device code.
func RequestDeviceCode(clientID, scopes string) (*DeviceCodeResponse, error) {
	data := url.Values{
		"client_id": {clientID},
		"scope":     {scopes},
	}

	req, err := http.NewRequest("POST", githubDeviceCodeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("device code request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("device code request returned %d: %s", resp.StatusCode, string(body))
	}

	var dcr DeviceCodeResponse
	if err := json.Unmarshal(body, &dcr); err != nil {
		return nil, fmt.Errorf("parsing device code response: %w", err)
	}

	if dcr.DeviceCode == "" {
		// Check if GitHub returned an error instead.
		var errResp DeviceFlowError
		if json.Unmarshal(body, &errResp) == nil && errResp.Code != "" {
			return nil, &errResp
		}
		return nil, fmt.Errorf("empty device code in response: %s", string(body))
	}

	return &dcr, nil
}

// PollForToken polls GitHub until the user completes authorization.
// It respects the interval and handles slow_down, expired_token, etc.
func PollForToken(clientID string, dc *DeviceCodeResponse) (*TokenResponse, error) {
	interval := time.Duration(dc.Interval) * time.Second
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(dc.ExpiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device flow authorization timed out (code expired)")
		}

		time.Sleep(interval)

		token, err := exchangeDeviceCode(clientID, dc.DeviceCode)
		if err != nil {
			var dfe *DeviceFlowError
			if isDeviceFlowError(err, &dfe) {
				switch dfe.Code {
				case "authorization_pending":
					continue
				case "slow_down":
					interval += 5 * time.Second
					continue
				case "expired_token":
					return nil, fmt.Errorf("device code expired, please restart the login flow")
				case "access_denied":
					return nil, fmt.Errorf("authorization was denied by the user")
				default:
					return nil, err
				}
			}
			return nil, err
		}
		return token, nil
	}
}

func exchangeDeviceCode(clientID, deviceCode string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":   {clientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}

	req, err := http.NewRequest("POST", githubTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	// GitHub returns 200 even for errors, so check the body.
	var errResp DeviceFlowError
	if json.Unmarshal(body, &errResp) == nil && errResp.Code != "" {
		return nil, &errResp
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if token.AccessToken == "" {
		return nil, fmt.Errorf("no access token in response: %s", string(body))
	}

	return &token, nil
}

// isDeviceFlowError checks if err is a *DeviceFlowError and sets target.
func isDeviceFlowError(err error, target **DeviceFlowError) bool {
	if e, ok := err.(*DeviceFlowError); ok {
		*target = e
		return true
	}
	return false
}
