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

// Package loggers contains the package references for log messages
// If a new package is introduced, the corresponding logger reference is need to be created as well.
package loggers

import (
	"github.com/sirupsen/logrus"
	"github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/logging"
)

/* loggers should be initiated only for the main packages
 ********** Don't initiate loggers for sub packages ****************

When you add a new logger instance add the related package name as a constant
*/

// package name constants
const (
	pkgAuth        = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/auth"
	pkgMsg         = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/messaging"
	pkgHealth      = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/health"
	pkgTLSUtils    = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/tlsutils"
	pkgUtils       = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/utils"
	pkgAdapter     = "github.com/wso2/apk/adapter/pkg/adapter"
	pkgSync        = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/synchronizer"
	pkgSoapUtils   = "github.com/wso2/apk/adapter/pkg/soaputils"
	pkgTransformer = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/transformer"
	pkgMgtServer   = "github.com/wso2/product-apim-tooling/apim-apk-agent/pkg/managementserver"
)

// logger package references
var (
	LoggerAuth         logging.Log
	LoggerMsg          logging.Log
	LoggerHealth       logging.Log
	LoggerTLSUtils     logging.Log
	LoggerUtils     logging.Log
	LoggerAdapter      logging.Log
	LoggerSync         logging.Log
	LoggerSoapUtils    logging.Log
	LoggerSubscription logging.Log
	LoggerTransformer  logging.Log
	LoggerMgtServer    logging.Log
)

func init() {
	UpdateLoggers()
}

// UpdateLoggers initializes the logger package references
func UpdateLoggers() {
	LoggerAuth = logging.InitPackageLogger(pkgAuth)
	LoggerMsg = logging.InitPackageLogger(pkgMsg)
	LoggerHealth = logging.InitPackageLogger(pkgHealth)
	LoggerTLSUtils = logging.InitPackageLogger(pkgTLSUtils)
	LoggerUtils = logging.InitPackageLogger(pkgUtils)
	LoggerAdapter = logging.InitPackageLogger(pkgAdapter)
	LoggerSync = logging.InitPackageLogger(pkgSync)
	LoggerSoapUtils = logging.InitPackageLogger(pkgSoapUtils)
	LoggerTransformer = logging.InitPackageLogger(pkgTransformer)
	LoggerMgtServer = logging.InitPackageLogger(pkgMgtServer)
	logrus.Info("Updated loggers")
}
