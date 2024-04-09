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
package managementserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/config"
	logger "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/loggers"

	"github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/utils"
	"gopkg.in/yaml.v2"
)

func init() {
}

// StartInternalServer starts the internal server
func StartInternalServer(port uint) {
	cpConfig, err := config.ReadConfigs()
	envLabel := []string{"Default"}
	if err == nil {
		envLabel = cpConfig.ControlPlane.EnvironmentLabels
	}
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	r.GET("/applications", func(c *gin.Context) {
		applicationList := GetAllApplications()
		c.JSON(http.StatusOK, ResolvedApplicationList{List: applicationList})
	})
	r.GET("/subscriptions", func(c *gin.Context) {
		subscriptionList := GetAllSubscriptions()
		c.JSON(http.StatusOK, SubscriptionList{List: subscriptionList})
	})
	r.GET("/applicationmappings", func(c *gin.Context) {
		applicationMappingList := GetAllApplicationMappings()
		c.JSON(http.StatusOK, ApplicationMappingList{List: applicationMappingList})
	})
	r.POST("/apis", func(c *gin.Context) {
		var event APICPEvent
		if err := c.ShouldBindJSON(&event); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		logger.LoggerMgtServer.Debugf("Recieved payload for endpoint /apis: %+v", event)
		if event.Event == DeleteEvent {
			logger.LoggerMgtServer.Infof("Delete event received with APIUUID: %s", event.API.APIUUID)
			payload := []map[string]interface{}{
				{
					"revisionUuid":       event.API.RevisionID,
					"name":               envLabel[0],
					"vhost":              event.API.Vhost,
					"displayOnDevportal": true,
				},
			}
			jsonPayload, err := json.Marshal(payload)
			logger.LoggerMgtServer.Debugf("Sending payload for revision undeploy: %+v", string(jsonPayload))
			if err != nil {
				logger.LoggerMgtServer.Errorf("Error while preparing payload to delete revision. Processed object: %+v", payload)
				c.JSON(http.StatusInternalServerError, err.Error())
				return
			}
			// Delete the api
			errorUndeployRevision := utils.DeleteAPIRevision(event.API.APIUUID, event.API.RevisionID, string(jsonPayload))
			if errorUndeployRevision != nil {
				logger.LoggerMgtServer.Errorf("Error while undeploying api revision. RevisionId: %s, API ID: %s . Sending error response to Adapter.", event.API.RevisionID, event.API.APIUUID)
				c.JSON(http.StatusServiceUnavailable, errorUndeployRevision.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"message": "Success"})
		} else {
			if strings.EqualFold(event.API.APIType, "rest") && event.API.Definition == "" {
				event.API.Definition = utils.OpenAPIDefaultYaml
			}
			if strings.EqualFold(event.API.APIType, "rest") {
				yaml, errJSONToYaml := JSONToYAML(event.API.Definition)
				if errJSONToYaml == nil {
					event.API.Definition = yaml
				}
			}
			apiYaml, definition := createAPIYaml(&event)
			deploymentContent := createDeployementYaml(event.API.Vhost)
			logger.LoggerMgtServer.Debugf("Created apiYaml : %s, \n\n\n created definition file: %s", apiYaml, definition)
			definitionPath := fmt.Sprintf("%s-%s/Definitions/swagger.yaml", event.API.APIName, event.API.APIVersion)
			if strings.ToUpper(event.API.APIType) == "GRAPHQL" {
				definitionPath = fmt.Sprintf("%s-%s/Definitions/schema.graphql", event.API.APIName, event.API.APIVersion)
			}
			zipFiles := []utils.ZipFile{{
				Path:    fmt.Sprintf("%s-%s/api.yaml", event.API.APIName, event.API.APIVersion),
				Content: apiYaml,
			}, {
				Path:    fmt.Sprintf("%s-%s/deployment_environments.yaml", event.API.APIName, event.API.APIVersion),
				Content: deploymentContent,
			}, {
				Path:    definitionPath,
				Content: definition,
			}}
			var buf bytes.Buffer
			if err := utils.CreateZipFile(&buf, zipFiles); err != nil {
				logger.LoggerMgtServer.Errorf("Error while creating apim zip file for api uuid: %s. Error: %+v", event.API.APIUUID, err)
			}

			id, revisionID, err := utils.ImportAPI(fmt.Sprintf("admin-%s-%s.zip", event.API.APIName, event.API.APIVersion), &buf)
			if err != nil {
				logger.LoggerMgtServer.Errorf("Error while importing API. Sending error response to Adapter.")
				c.JSON(http.StatusServiceUnavailable, err.Error())
				return
			}
			c.JSON(http.StatusOK, map[string]string{"id": id, "revisionID": revisionID})
		}
	})
	publicKeyLocation, privateKeyLocation, _ := config.GetKeyLocations()
	r.RunTLS(fmt.Sprintf(":%d", port), publicKeyLocation, privateKeyLocation)
}

func createAPIYaml(apiCPEvent *APICPEvent) (string, string) {
	config, err := config.ReadConfigs()
	provider := "admin"
	if err == nil {
		provider = config.ControlPlane.Provider
	}
	context := removeVersionSuffix(apiCPEvent.API.BasePath, apiCPEvent.API.APIVersion)
	operations, scopes, operationsErr := extractOperations(*apiCPEvent)
	if operationsErr != nil {
		logger.LoggerMgtServer.Errorf("Error occured while extracting operations from open API: %s, \nError: %+v", apiCPEvent.API.Definition, operationsErr)
		operations = []APIOperation{}
	}
	sandEndpoint := ""
	if apiCPEvent.API.SandEndpoint != "" {
		sandEndpoint = fmt.Sprintf("%s://%s", apiCPEvent.API.EndpointProtocol, apiCPEvent.API.SandEndpoint)
	}
	prodEndpoint := ""
	if apiCPEvent.API.ProdEndpoint != "" {
		prodEndpoint = fmt.Sprintf("%s://%s", apiCPEvent.API.EndpointProtocol, apiCPEvent.API.ProdEndpoint)
	}
	authHeader := apiCPEvent.API.AuthHeader
	apiType := "HTTP"
	if apiCPEvent.API.APIType == "GraphQL" {
		apiType = "GRAPHQL"
	}
	data := map[string]interface{}{
		"type":    "api",
		"version": "v4.3.0",
		"data": map[string]interface{}{
			"name":                         apiCPEvent.API.APIName,
			"context":                      context,
			"version":                      apiCPEvent.API.APIVersion,
			"organizationId":               apiCPEvent.API.Organization,
			"provider":                     provider,
			"lifeCycleStatus":              "CREATED",
			"responseCachingEnabled":       false,
			"cacheTimeout":                 300,
			"hasThumbnail":                 false,
			"isDefaultVersion":             apiCPEvent.API.IsDefaultVersion,
			"isRevision":                   false,
			"enableSchemaValidation":       false,
			"enableSubscriberVerification": false,
			"type":                         apiType,
			"transport":                    []string{"http", "https"},
			"endpointConfig": map[string]interface{}{
				"endpoint_type": apiCPEvent.API.EndpointProtocol,
				"sandbox_endpoints": map[string]interface{}{
					"url": sandEndpoint,
				},
				"production_endpoints": map[string]interface{}{
					"url": prodEndpoint,
				},
			},
			"policies":             []string{"Unlimited"},
			"gatewayType":          "wso2/apk",
			"gatewayVendor":        "wso2",
			"operations":           operations,
			"additionalProperties": createAdditionalProperties(apiCPEvent.API.APIProperties),
			"securityScheme":       apiCPEvent.API.SecurityScheme,
			"authorizationHeader":  authHeader,
			"apiKeyHeader":         "ApiKey",
			"scopes":               scopes,
		},
	}
	// TODO when we start to process sandbox we need to have this if condition. For now we remove sandbox endpoint always.
	// if apiCPEvent.API.SandEndpoint == "" {
	delete(data["data"].(map[string]interface{})["endpointConfig"].(map[string]interface{}), "sandbox_endpoints")
	// }
	if apiCPEvent.API.ProdEndpoint == "" {
		delete(data["data"].(map[string]interface{})["endpointConfig"].(map[string]interface{}), "production_endpoints")
	}
	if apiCPEvent.API.CORSPolicy != nil {
		data["data"].(map[string]interface{})["corsConfiguration"] = map[string]interface{}{
			"corsConfigurationEnabled":      true,
			"accessControlAllowOrigins":     apiCPEvent.API.CORSPolicy.AccessControlAllowOrigins,
			"accessControlAllowCredentials": apiCPEvent.API.CORSPolicy.AccessControlAllowCredentials,
			"accessControlAllowHeaders":     apiCPEvent.API.CORSPolicy.AccessControlAllowHeaders,
			"accessControlAllowMethods":     apiCPEvent.API.CORSPolicy.AccessControlAllowMethods,
			"accessControlExposeHeaders":    apiCPEvent.API.CORSPolicy.AccessControlExposeHeaders,
		}
	}
	logger.LoggerMgtServer.Debugf("Prepared yaml : %+v", data)
	definition := apiCPEvent.API.Definition
	if strings.EqualFold(apiCPEvent.API.APIType, "rest") {
		// Process OpenAPI and set required values
		openAPI, errConvertYaml := ConvertYAMLToMap(definition)
		if errConvertYaml == nil {
			if paths, ok := openAPI["paths"].(map[interface{}]interface{}); ok {
				for path, pathContent := range paths {
					if pathContentMap, ok := pathContent.(map[interface{}]interface{}); ok {
						for verb, verbContent := range pathContentMap {
							for _, operation := range operations {
								if strings.EqualFold(path.(string), operation.Target) && strings.EqualFold(verb.(string), operation.Verb) {
									if verbContentMap, ok := verbContent.(map[interface{}]interface{}); ok {
										if len(operation.Scopes) > 0 {
											verbContentMap["security"] = []map[string][]string{
												{
													"default": operation.Scopes,
												},
											}
										}
										verbContentMap["x-auth-type"] = "Application & Application User"
									}
									break
								}
							}
						}
					}
				}
			}
			scopesForOpenAPIComponents := map[string]string{}
			for _, scopeWrapper := range scopes {
				scopesForOpenAPIComponents[scopeWrapper.Scope.Name] = ""
			}

			components, ok := openAPI["components"].(map[interface{}]interface{})
			if !ok {
				components = make(map[interface{}]interface{})
			}
			securitySchemes, ok := components["securitySchemes"].(map[interface{}]interface{})
			if !ok {
				securitySchemes = make(map[interface{}]interface{})
			}

			securitySchemes["default"] = map[interface{}]interface{}{
				"type": "oauth2",
				"flows": map[interface{}]interface{}{
					"implicit": map[interface{}]interface{}{
						"authorizationUrl":  "https://test.com",
						"scopes":            scopesForOpenAPIComponents,
						"x-scopes-bindings": scopesForOpenAPIComponents,
					},
				},
			}

			components["securitySchemes"] = securitySchemes
			openAPI["components"] = components

			yamlBytes, err := yaml.Marshal(&openAPI)
			if err != nil {
				logger.LoggerMgtServer.Errorf("Error while converting openAPI struct to yaml content. openAPI struct: %+v", openAPI)
			} else {
				logger.LoggerMgtServer.Debugf("Created openAPI yaml: %s", string(yamlBytes))
				definition = string(yamlBytes)
			}
		}
	}

	yamlBytes, _ := yaml.Marshal(data)
	return string(yamlBytes), definition
}

func createDeployementYaml(vhost string) string {
	config, err := config.ReadConfigs()
	envLabel := []string{"Default"}
	if err == nil {
		envLabel = config.ControlPlane.EnvironmentLabels
	}
	deploymentEnvData := []map[string]interface{}{}
	for _, label := range envLabel {
		deploymentEnvData = append(deploymentEnvData, map[string]interface{}{
			"displayOnDevportal":    true,
			"deploymentEnvironment": label,
			"deploymentVhost":       vhost,
		})
	}
	data := map[string]interface{}{
		"type":    "deployment_environments",
		"version": "v4.3.0",
		"data":    deploymentEnvData,
	}

	yamlBytes, _ := yaml.Marshal(data)
	return string(yamlBytes)
}

// APIOperation represents the desired struct format for each API operation
type APIOperation struct {
	ID                string   `yaml:"id"`
	Target            string   `yaml:"target"`
	Verb              string   `yaml:"verb"`
	AuthType          string   `yaml:"authType"`
	ThrottlingPolicy  string   `yaml:"throttlingPolicy"`
	Scopes            []string `yaml:"scopes"`
	UsedProductIDs    []string `yaml:"usedProductIds"`
	OperationPolicies struct {
		Request  []string `yaml:"request"`
		Response []string `yaml:"response"`
		Fault    []string `yaml:"fault"`
	} `yaml:"operationPolicies"`
}

// OpenAPIPaths represents the structure of the OpenAPI specification YAML file
type OpenAPIPaths struct {
	Paths map[string]map[string]interface{} `yaml:"paths"`
}

// Operation represents the structure of an operation within the OpenAPI specification
type Operation struct {
	XAuthType        string `yaml:"x-auth-type"`
	XThrottlingTier  string `yaml:"x-throttling-tier"`
	XWSO2AppSecurity struct {
		SecurityTypes []string `yaml:"security-types"`
		Optional      bool     `yaml:"optional"`
	} `yaml:"x-wso2-application-security"`
}

// AdditionalProperty represents additional properties of the API
type AdditionalProperty struct {
	Name    string
	Value   string
	Display bool
}

// ScopeWrapper to hold scope sonfigs
type ScopeWrapper struct {
	Scope  Scope `yaml:"scope"`
	Shared bool  `yaml:"shared"`
}

// Scope to hold scope config
type Scope struct {
	Name        string   `yaml:"name"`
	DisplayName string   `yaml:"displayName"`
	Description string   `yaml:"description"`
	Bindings    []string `yaml:"bindings"`
}

func extractOperations(event APICPEvent) ([]APIOperation, []ScopeWrapper, error) {
	var apiOperations []APIOperation
	scopewrappers := map[string]ScopeWrapper{}
	if strings.ToUpper(event.API.APIType) == "GRAPHQL" {
		for _, operation := range event.API.Operations {
			apiOp := APIOperation{
				Target:           operation.Path,
				Verb:             operation.Verb,
				AuthType:         "Application & Application User",
				ThrottlingPolicy: "Unlimited",
			}
			apiOperations = append(apiOperations, apiOp)
		}
	} else if strings.ToUpper(event.API.APIType) == "REST" {
		var openAPIPaths OpenAPIPaths
		openAPI := event.API.Definition
		if err := yaml.Unmarshal([]byte(openAPI), &openAPIPaths); err != nil {
			return nil, nil, err
		}

		for path, operations := range openAPIPaths.Paths {
			for verb := range operations {
				ptrToOperationFromDP := findMatchingAPKOperation(path, verb, event.API.Operations)
				if ptrToOperationFromDP == nil {
					continue
				}
				operationFromDP := *ptrToOperationFromDP
				scopes := operationFromDP.Scopes
				for _, scope := range scopes {
					scopewrappers[scope] = ScopeWrapper{
						Scope: Scope{
							Name:        scope,
							DisplayName: scope,
							Description: scope,
							Bindings:    []string{},
						},
						Shared: false,
					}
				}
				apiOp := APIOperation{
					Target:           path,
					Verb:             verb,
					AuthType:         "Application & Application User",
					ThrottlingPolicy: "Unlimited",
					Scopes:           scopes,
				}
				apiOperations = append(apiOperations, apiOp)
			}
		}
		var scopeWrapperSlice []ScopeWrapper
		for _, value := range scopewrappers {
			scopeWrapperSlice = append(scopeWrapperSlice, value)
		}
		return apiOperations, scopeWrapperSlice, nil
	}
	return []APIOperation{}, []ScopeWrapper{}, nil
}

func findMatchingAPKOperation(path string, verb string, operations []OperationFromDP) *OperationFromDP {
	for _, operationFromDP := range operations {
				if strings.EqualFold(operationFromDP.Verb, verb) {
			path = processOpenAPIPath(path)
			if pathMatchWithoutRegex(operationFromDP.Path, path) {
				return &operationFromDP
			}
		}
	}
	return nil
}

func removeVersionSuffix(str1, str2 string) string {
	if strings.HasSuffix(str1, str2) {
		return strings.TrimSuffix(str1, fmt.Sprintf("/%s", str2))
	}
	return str1
}

// createAdditionalProperties creates additional property elements from map
func createAdditionalProperties(data map[string]string) []AdditionalProperty {
	var properties []AdditionalProperty
	for key, value := range data {
		entry := AdditionalProperty{
			Name:    key,
			Value:   value,
			Display: false,
		}
		properties = append(properties, entry)
	}
	return properties
}

func matchRegex(regexStr string, targetStr string) bool {
	regexPattern, err := regexp.Compile(regexStr)
	if err != nil {
		fmt.Println("Error compiling regex:", err)
		return false
	}
	return regexPattern.MatchString(targetStr)
}

func pathMatchWithoutRegex(pathWithRegex string, path string) bool {
	return removeFirstAndLastChars(pathWithRegex) == path
}

func removeFirstAndLastChars(s string) string {
	if len(s) > 2 {
		return s[1 : len(s)-1]
	}
	return s
}

func processOpenAPIPath(path string) string {
	if path == "/*" {
		return "(.*)"
	}
	re := regexp.MustCompile(`{[^}]+}`)
	return re.ReplaceAllString(path, "(.*)")
}

// ConvertYAMLToMap converts a YAML string to a map[string]interface{}
func ConvertYAMLToMap(yamlString string) (map[string]interface{}, error) {
	var yamlData map[string]interface{}
	err := yaml.Unmarshal([]byte(yamlString), &yamlData)
	if err != nil {
		logger.LoggerMgtServer.Errorf("Error while converting openAPI yaml to map: Error: %+v. \n openAPI yaml", err, yamlString)
		return nil, err
	}
	return yamlData, nil
}

// JSONToYAML convert json string to yaml
func JSONToYAML(jsonString string) (string, error) {
	// Convert JSON string to map[string]interface{}
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(jsonString), &jsonData)
	if err != nil {
		return "", err
	}

	// Convert map[string]interface{} to YAML
	yamlBytes, err := yaml.Marshal(jsonData)
	if err != nil {
		return "", err
	}

	// Convert YAML bytes to string
	yamlString := string(yamlBytes)

	return yamlString, nil
}
