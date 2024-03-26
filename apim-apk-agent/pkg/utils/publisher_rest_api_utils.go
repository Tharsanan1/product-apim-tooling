/*
 *  Copyright (c) 2024, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"net/http"
	"io"
	"net/url"
	"mime/multipart"
	"bytes"
	"io/ioutil"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/config"
	logger "github.com/wso2/product-apim-tooling/apim-apk-agent/internal/loggers"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/tlsutils"
)

type Scope string

const (
	ApiImportRelativePath   = "api/am/publisher/v4/apis/import?preserveProvider=false&overwrite=true"
	DCRRegisterRelativePath = "client-registration/v0.17/register"
	TokenRelativePath       = "oauth2/token"
	payloadJson             = `{
        "callbackUrl": "www.google.lk",
        "clientName": "rest_api_publisher",
        "owner": "admin",
        "grantType": "client_credentials password refresh_token",
        "saasApp": true
    }`
	AdminScope Scope = "apim:admin"
	ImportExportScope Scope = "apim:api_import_export"
)

var (
	dcrRegisterUrl string
	tokenUrl       string
	apiImportUrl   string
	username       string
	password       string
	skipSSL        bool
)

func init() {
	// Read configurations and derive the eventHub details
	conf, errReadConfig := config.ReadConfigs()
	if errReadConfig != nil {
		// This has to be error. For debugging purpose info
		logger.LoggerSynchronizer.Errorf("Error reading configs: %v", errReadConfig)
	}
	// Populate data from the config
	cpConfigs := conf.ControlPlane
	cpURL := cpConfigs.ServiceURL
	// If the eventHub URL is configured with trailing slash
	if strings.HasSuffix(cpURL, "/") {
		apiImportUrl = cpURL + ApiImportRelativePath
		dcrRegisterUrl = cpURL + DCRRegisterRelativePath
		tokenUrl = cpURL + TokenRelativePath
	} else {
		apiImportUrl = cpURL + "/" + ApiImportRelativePath
		dcrRegisterUrl = cpURL + "/" + DCRRegisterRelativePath
		tokenUrl = cpURL + "/" + TokenRelativePath
	}
	username = cpConfigs.Username
	password = cpConfigs.Password
	// skipSSL = cpConfigs.SkipSSLVerification
	skipSSL = true
}

func Base64EncodeCredentials(username, password string) string {
	credentials := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(credentials))
}

func GetBasicAuthHeaderValue(username, password string) string {
	return fmt.Sprintf("Basic %s", Base64EncodeCredentials(username, password))
}

func RegisterClient() ([]byte, error){
	
	body := bytes.NewBuffer([]byte(payloadJson))
	req, err := http.NewRequest("POST", dcrRegisterUrl, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", GetBasicAuthHeaderValue(username, password))
	req.Header.Set("Content-Type", "application/json")
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Check for non-200 response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	return responseBody, nil
}


func GetToken(scopes []string, clientId string, clientSecret string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", username)
	form.Set("password", password)
	form.Set("scope", strings.Join(scopes, " "))
	req, err := http.NewRequest("POST", tokenUrl, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", GetBasicAuthHeaderValue(clientId, clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Check for non-200 response status
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Parse JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	// Extract access_token
	accessToken, ok := response["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("access_token not found in response")
	}

	return accessToken, nil
}

func RegistClientAndGetToken(scopes []string) (string, error){
	body, err := RegisterClient();
	if (err != nil) {
		return "", err
	}
	type ClientInfo struct {
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret"`
	}
	var clientInfo ClientInfo
	jsonErr := json.Unmarshal(body, &clientInfo)
	if jsonErr != nil {
		return "", jsonErr
	}
	clientID := clientInfo.ClientID
	clientSecret := clientInfo.ClientSecret

	token, tokenError := GetToken(scopes, clientID, clientSecret)
	if (tokenError != nil) {
		return "", tokenError
	}
	return token, nil;
}


func ImportAPI(apiZipName string, zipFileBytes *bytes.Buffer) error {
	token, err := RegistClientAndGetToken([]string{string(AdminScope), string(ImportExportScope)})
		if(err != nil) {
		return err
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", apiZipName)
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, zipFileBytes); err != nil {
		return err
	}
	writer.Close()
	req, err := http.NewRequest("POST", apiImportUrl, body)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	resp, err := tlsutils.InvokeControlPlane(req, skipSSL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		logger.LoggerAgent.Infof("API already exists in the CP hence ignoring the event. API zip name %s", apiZipName)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	return nil
}