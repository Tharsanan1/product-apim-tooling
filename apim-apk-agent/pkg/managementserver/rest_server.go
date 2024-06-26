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
			definition := event.API.Definition
			apiYaml := createAPIYaml(event)
			deploymentContent := createDeployementYaml(event.API.Vhost)
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
	gin.SetMode(gin.ReleaseMode)
	publicKeyLocation, privateKeyLocation, _ := config.GetKeyLocations()
	r.RunTLS(fmt.Sprintf(":%d", port), publicKeyLocation, privateKeyLocation)
}

func createAPIYaml(apiCPEvent APICPEvent) string {
	config, err := config.ReadConfigs()
	provider := "admin"
	if err == nil {
		provider = config.ControlPlane.Provider
	}
	context := removeVersionSuffix(apiCPEvent.API.BasePath, apiCPEvent.API.APIVersion)
	operations, operationsErr := extractOperations(apiCPEvent)
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
		},
	}
	if apiCPEvent.API.SandEndpoint == "" {
		delete(data["data"].(map[string]interface{})["endpointConfig"].(map[string]interface{}), "sandbox_endpoints")
	}
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

	logger.LoggerMgtServer.Infof("Prepared yaml : %+v", data)
	yamlBytes, _ := yaml.Marshal(data)
	return string(yamlBytes)
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
	Paths map[string]map[string]Operation `yaml:"paths"`
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

func extractOperations(event APICPEvent) ([]APIOperation, error) {
	var apiOperations []APIOperation
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
			return nil, err
		}

		for path, operations := range openAPIPaths.Paths {
			for verb, operation := range operations {
				if operation.XAuthType == "" {
					operation.XAuthType = "Application & Application User"
				}
				if operation.XThrottlingTier == "" {
					operation.XThrottlingTier = "Unlimited"
				}
				apiOp := APIOperation{
					Target:           path,
					Verb:             verb,
					AuthType:         operation.XAuthType,
					ThrottlingPolicy: operation.XThrottlingTier,
				}
				apiOperations = append(apiOperations, apiOp)
			}
		}
		return apiOperations, nil
	}
	return []APIOperation{}, nil
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
