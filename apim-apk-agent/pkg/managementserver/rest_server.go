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
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/config"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/loggers"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/utils"
	"gopkg.in/yaml.v2"
	"net/http"
)

func init() {
}

// StartInternalServer starts the internal server
func StartInternalServer(port uint) {
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

		apiYaml := createAPIYaml(event)
		definition := event.API.Definition
		zipFiles := []utils.ZipFile{{
			Path:    "api.yaml",
			Content: apiYaml,
		}, {
			Path:    "Definitions/swagger.yaml",
			Content: definition,
		}}
		var buf bytes.Buffer
		if err := utils.CreateZipFile(&buf, zipFiles); err != nil {
			loggers.LoggerMgtServer.Errorf("Error while creating apim zip file for api uuid: %s. Error: %+v", event.API.APIUUID, err)
		}
		err := utils.ImportAPI(fmt.Sprintf("admin-%s-%s.zip", event.API.APIName, event.API.APIVersion), &buf)
		if (err != nil) {
			c.JSON(http.StatusInternalServerError, err.Error())
			return
		}
		c.JSON(http.StatusOK, "")
	})
	gin.SetMode(gin.ReleaseMode)
	publicKeyLocation, privateKeyLocation, _ := config.GetKeyLocations()
	r.RunTLS(fmt.Sprintf(":%d", port), publicKeyLocation, privateKeyLocation)
}

func createAPIYaml(apiCPEvent APICPEvent) string {
	data := map[string]interface{}{
		"type":    "api",
		"version": "v4.3.0",
		"data": map[string]interface{}{
			"id":                           apiCPEvent.API.APIUUID,
			"name":                         apiCPEvent.API.APIName,
			"context":                      apiCPEvent.API.BasePath,
			"version":                      apiCPEvent.API.APIVersion,
			"provider":                     apiCPEvent.API.Organization,
			"lifeCycleStatus":              "PUBLISHED", // Assuming this is fixed
			"responseCachingEnabled":       false,       // Assuming this is fixed
			"cacheTimeout":                 300,         // Assuming this is fixed
			"hasThumbnail":                 false,       // Assuming this is fixed
			"isDefaultVersion":             apiCPEvent.API.IsDefaultVersion,
			"isRevision":                   false,                     // Assuming this is fixed
			"revisionId":                   apiCPEvent.API.RevisionID, // Assuming this is fixed
			"enableSchemaValidation":       false,                     // Assuming this is fixed
			"enableSubscriberVerification": false,                     // Assuming this is fixed
			"type":                         "HTTP",                    // Assuming this is fixed
		},
	}

	yamlBytes, _ := yaml.Marshal(data)
	return string(yamlBytes)
}
