// Copyright 2015 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

// Package idputil contains utility routines common to many identity
// providers.
package idputil

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"gopkg.in/errgo.v1"
)

// The Azure AD Graph API is deprecated in favor of the Microsoft Graph API,
// however Azure AD still returns URLs that point to the depracated API.
// Once the Azure AD Graph API is decomissioned, this replaced can be removed.
// See https://docs.microsoft.com/en-us/graph/migrate-azure-ad-graph-request-differences#basic-requests
var replacer = strings.NewReplacer(
	"https://graph.windows.net/", "https://graph.microsoft.com/v1.0/",
	"https://graph.microsoftazure.us/", "https://graph.microsoft.us/v1.0/",
	"https://graph.microsoftazure.us/", "https://dod-graph.microsoft.us/v1.0/",
	"https://graph.cloudapi.de/", "https://graph.microsoft.de/v1.0/",
	"https://graph.chinacloudapi.cn/", "https://microsoftgraph.chinacloudapi.cn/v1.0/")

type MsGraphGroupsRetriever struct{}

// This function handles Microsoft Graph API specifics around retrieving user groups.
// If the user is a member of more than 150 groups (SAML) or 200 groups (JWT), groups must be explicitly
// retrieved using the Microsoft Graph API.
// See https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
func (adfs *MsGraphGroupsRetriever) RetrieveGroups(ctx context.Context, token *oauth2.Token, claimsUnmarshaler func(interface{}) error) ([]string, error) {
	var claims msGraphClaims
	err := claimsUnmarshaler(&claims)
	if err != nil {
		return nil, errgo.Newf("Failed to unmarshal claims.")
	}

	// Return a list of groups, if the claim is present. There is no need to query the Microsoft Graph API.
	if claims.Groups != nil {
		return claims.Groups, nil
	}

	var ok bool

	var claimName string
	if claimName, ok = claims.ClaimsNames["groups"]; !ok {
		return nil, nil
	}

	var claimSource claimSource
	if claimSource, ok = claims.ClaimsSources[claimName]; !ok {
		return nil, errgo.Newf("There is no '%s' item in the '_claim_sources' claim.", claimName)
	}

	reqBody := getMemberObjectsRequest{SecurityEnabledOnly: false}
	reqBodyJson, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errgo.Notef(err, "Failed to marshal request body to JSON.")
	}

	url := replacer.Replace(claimSource.Endpoint)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBodyJson))
	if err != nil {
		return nil, errgo.Notef(err, "Failed to create a POST request.")
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, errgo.Notef(err, "Groups request failed.")
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errgo.Notef(err, "Failed to read response body.")
	}

	var mor getMemberObjectsResponse
	err = json.Unmarshal(body, &mor)
	if err != nil {
		return nil, errgo.Newf("Failed to unmarshal groups.")
	}

	return mor.Groups, nil
}

// Token claims need to get groups
// See https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens
type msGraphClaims struct {
	Groups        []string               `json:"groups"`
	ClaimsNames   map[string]string      `json:"_claim_names"`
	ClaimsSources map[string]claimSource `json:"_claim_sources"`
}

type claimSource struct {
	Endpoint string `json:"endpoint"`
}

// See https://docs.microsoft.com/en-us/graph/api/directoryobject-getmemberobjects?view=graph-rest-1.0&tabs=http#request-body
type getMemberObjectsRequest struct {
	SecurityEnabledOnly bool `json:"securityEnabledOnly"`
}

// See https://docs.microsoft.com/en-us/graph/api/directoryobject-getmemberobjects?view=graph-rest-1.0&tabs=http#response-1
type getMemberObjectsResponse struct {
	Groups []string `json:"value"`
}
