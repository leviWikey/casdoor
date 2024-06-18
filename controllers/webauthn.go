// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

import (
	"bytes"
	"fmt"
	"io"

	"github.com/casdoor/casdoor/form"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/primitives"
	"github.com/casdoor/casdoor/util"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	WIKEY_AAGUID = primitives.NewImmutableByteSlice([]byte{180, 99, 125, 190, 71, 164, 168, 212, 54, 241, 198, 174, 124, 111, 45, 24})
)

// WebAuthnSignupBegin
// @Title WebAuthnSignupBegin
// @Tag User API
// @Description WebAuthn Registration Flow 1st stage
// @Success 200 {object} protocol.CredentialCreation The CredentialCreationOptions object
// @router /webauthn/signup/begin [get]
func (c *ApiController) WebAuthnSignupBegin() {
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	user := c.getCurrentUser()
	if user == nil {
		c.ResponseError(c.T("general:Please login first"))
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = user.CredentialExcludeList()
	}
	options, sessionData, err := webauthnObj.BeginRegistration(
		user,
		registerOptions,
	)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.SetSession("registration", *sessionData)
	c.Data["json"] = options
	c.ServeJSON()
}

// WebAuthnSignupFinish
// @Title WebAuthnSignupFinish
// @Tag User API
// @Description WebAuthn Registration Flow 2nd stage
// @Param   body    body   protocol.CredentialCreationResponse  true        "authenticator attestation Response"
// @Success 200 {object} controllers.Response "The Response object"
// @router /webauthn/signup/finish [post]
func (c *ApiController) WebAuthnSignupFinish() {
	parsedResponse, err := protocol.ParseCredentialCreationResponse(c.Ctx.Request)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if !WIKEY_AAGUID.Equal(parsedResponse.Response.AttestationObject.AuthData.AttData.AAGUID) {
		c.ResponseError("AAGUID is not valid")
		return
	}
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	user := c.getCurrentUser()
	if user == nil {
		c.ResponseError(c.T("general:Please login first"))
		return
	}
	sessionObj := c.GetSession("registration")
	sessionData, ok := sessionObj.(webauthn.SessionData)
	if !ok {
		c.ResponseError(c.T("webauthn:Please call WebAuthnSigninBegin first"))
		return
	}
	c.Ctx.Request.Body = io.NopCloser(bytes.NewBuffer(c.Ctx.Input.RequestBody))

	credential, err := webauthnObj.FinishRegistration(user, sessionData, c.Ctx.Request)
	if err != nil {
		errr := err.(*protocol.Error)
		fmt.Println(errr.DevInfo)
		c.ResponseError(err.Error())
		return
	}
	isGlobalAdmin := c.IsGlobalAdmin()
	_, err = user.AddCredentials(*credential, isGlobalAdmin)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	c.ResponseOk()
}

// WebAuthnSigninBegin
// @Title WebAuthnSigninBegin
// @Tag Login API
// @Description WebAuthn Login Flow 1st stage
// @Param   owner     query    string  true        "owner"
// @Param   name     query    string  true        "name"
// @Success 200 {object} protocol.CredentialAssertion The CredentialAssertion object
// @router /webauthn/signin/begin [get]
func (c *ApiController) WebAuthnSigninBegin() {
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}

	userOwner := c.Input().Get("owner")
	userName := c.Input().Get("name")
	user, err := object.GetUserByFields(userOwner, userName)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	var options *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var sessionErr error
	if user == nil {
		options, sessionData, sessionErr = webauthnObj.BeginDiscoverableLogin()
	}
	if user != nil {
		if len(user.WebauthnCredentials) == 0 {
			c.ResponseError(c.T("webauthn:Found no credentials for this user"))
			return
		}
		options, sessionData, sessionErr = webauthnObj.BeginLogin(user)
	}
	if sessionErr != nil {
		c.ResponseError(err.Error())
		return
	}
	c.SetSession("authentication", *sessionData)
	c.Data["json"] = options
	c.ServeJSON()
}

// WebAuthnSigninFinish
// @Title WebAuthnSigninFinish
// @Tag Login API
// @Description WebAuthn Login Flow 2nd stage
// @Param   body    body   protocol.CredentialAssertionResponse  true        "authenticator assertion Response"
// @Success 200 {object} controllers.Response "The Response object"
// @router /webauthn/signin/finish [post]
func (c *ApiController) WebAuthnSigninFinish() {
	responseType := c.Input().Get("responseType")
	clientId := c.Input().Get("clientId")
	webauthnObj, err := object.GetWebAuthnObject(c.Ctx.Request.Host)
	if err != nil {
		util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "GetWebAuthnObject failed")
		c.ResponseError(err.Error())
		return
	}

	sessionObj := c.GetSession("authentication")
	sessionData, ok := sessionObj.(webauthn.SessionData)
	if !ok {
		c.ResponseError(c.T("webauthn:Please call WebAuthnSigninBegin first"))
		return
	}
	c.Ctx.Request.Body = io.NopCloser(bytes.NewBuffer(c.Ctx.Input.RequestBody))
	var userId string
	var user *object.User = nil
	if len(sessionData.UserID) == 0 {
		_, err = webauthnObj.FinishDiscoverableLogin(
			func(rawID, userHandle []byte) (userr webauthn.User, errr error) {
				userId = string(userHandle)
				userr, errr = object.GetUser(userId)
				if errr != nil {
					util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "GetUser failed")
					return nil, err
				}
				user = userr.(*object.User)
				if user == nil {
					util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "user is nil")
					return nil, fmt.Errorf("user is nil")
				}
				return user, err
			}, 
			sessionData, 
			c.Ctx.Request,
		)
	} else {
		userId = string(sessionData.UserID)
		user, err = object.GetUser(userId)
		if err != nil {
			util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "GetUser failed")
			c.ResponseError(err.Error())
			return
		}
		_, err = webauthnObj.FinishLogin(user, sessionData, c.Ctx.Request)
	}
	if err != nil {
		util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "FinishLogin failed")
		c.ResponseError(err.Error())
		return
	}
	c.SetSessionUsername(userId)
	util.LogInfo(c.Ctx, "API: [%s] signed in", userId)

	var application *object.Application

	if clientId != "" {
		application, err = object.GetApplicationByClientId(clientId)
		util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "getting application by clientId")
	} else {
		application, err = object.GetApplicationByUser(user)
		util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "getting application by user")
	}
	if err != nil {
		util.LogInfo(c.Ctx, "API: [%s] %s", c.Ctx.Request.RequestURI, "GetApplication failed")
		c.ResponseError(err.Error())
		return
	}

	var authForm form.AuthForm
	authForm.Type = responseType
	if responseType == ResponseTypeSaml {
		authForm.SamlRequest = c.Input().Get("samlRequest")
		authForm.RelayState = c.Input().Get("relayState")
	}
	resp := c.HandleLoggedIn(application, user, &authForm)
	c.Data["json"] = resp
	c.ServeJSON()
}
