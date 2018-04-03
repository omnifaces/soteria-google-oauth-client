/*
 * Copyright 2016 OmniFaces.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.omnifaces.soteria.mechanism;

import static java.util.logging.Level.WARNING;
import static javax.security.enterprise.AuthenticationStatus.SEND_CONTINUE;
import static javax.security.enterprise.AuthenticationStatus.SEND_FAILURE;
import static javax.security.enterprise.AuthenticationStatus.SUCCESS;
import static javax.security.enterprise.identitystore.CredentialValidationResult.Status.VALID;
import static org.omnifaces.soteria.mechanism.util.Utils.encodeURL;
import static org.omnifaces.soteria.mechanism.util.Utils.getBaseURL;
import static org.omnifaces.soteria.mechanism.util.Utils.isEmpty;

import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import javax.enterprise.inject.Typed;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStore;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.omnifaces.soteria.identitystore.credential.TokenResponseCredential;
import org.omnifaces.soteria.mechanism.util.StateCookieDAO;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.TokenResponse;


@Typed(OAuthClientServerBaseModule.class)
public class OAuthClientServerBaseModule implements HttpAuthenticationMechanism {

	private static final Logger logger = Logger.getLogger(OAuthClientServerBaseModule.class.getName());

	private AuthorizationCodeFlow authorizationCodeFlow;

	public static final String SOCIAL_PROFILE = "omnisecurity.socialProfile";
	public static final String SOCIAL_MANAGER = "omnisecurity.socialManager";

	public static final String USE_SESSIONS = "useSessions";
	public static final String CALLBACK_URL = "callbackUrl";
	public static final String PROFILE_INCOMPLETE_URL = "profileIncompleteUrl";
	public static final String REGISTRATION_ERROR_URL = "registrationErrorUrl";

	private boolean useSessions;
	private String callbackURL;
	private String registrationErrorUrl;

	private StateCookieDAO stateCookieDAO = new StateCookieDAO();

	@Inject
	private IdentityStore identityStore;

	public void init(Map<String, String> options, AuthorizationCodeFlow authorizationCodeFlow) {
		useSessions = Boolean.valueOf(options.get(USE_SESSIONS));
		callbackURL = options.get(CALLBACK_URL);
		registrationErrorUrl = options.get(REGISTRATION_ERROR_URL);

		this.authorizationCodeFlow = authorizationCodeFlow;
	}


	@Override
	public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
		if (isLoginRequest(request, response, httpMessageContext)) {
			return SEND_CONTINUE;
		}

		try {
			// Check if the user has arrived back from the OAuth provider

			if (isCallbackRequest(request, response, httpMessageContext)) {
				return doOAuthLogin(request, response, httpMessageContext);
			}

		}
		catch (Exception e) {
			throw new AuthenticationException(e);
		}

		return SUCCESS;
	}

	private boolean isLoginRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws AuthenticationException {

		if (httpMsgContext.isAuthenticationRequest()) {
			try {
				String state = UUID.randomUUID().toString();

				stateCookieDAO.save(request, response, state);

				String authorizationUrl = authorizationCodeFlow.newAuthorizationUrl()
				                                               .setState(state)
				                                               .setRedirectUri(getBaseURL(request) + callbackURL)
				                                               .build();
				response.sendRedirect(authorizationUrl);

				return true;
			}
			catch (Exception e) {
				throw new AuthenticationException(e);
			}
		}

		return false;
	}

	private boolean isCallbackRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws Exception {
		if (request.getRequestURI().equals(callbackURL) && request.getParameter("code") != null) {

			if (!isEmpty(request.getParameter("state"))) {
				try {
					String state = request.getParameter("state");
					Cookie cookie = stateCookieDAO.get(request);

					if (cookie != null && state.equals(cookie.getValue())) {
						return true;
					} else {
						logger.log(WARNING,
							"State parameter provided with callback URL, but did not match cookie. " +
							"State param value: " + state + " " +
							"Cookie value: " + (cookie == null? "<no cookie>" : cookie.getValue())
						);
					}
				} finally {
					stateCookieDAO.remove(request, response);
				}
			}
		}

		return false;
	}

	private AuthenticationStatus doOAuthLogin(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMsgContext) throws Exception {

		String parameter = request.getParameter("code");

		TokenResponse tokenResponse = authorizationCodeFlow.newTokenRequest(parameter).setRedirectUri(getBaseURL(request) + callbackURL).execute();

		try {

			CredentialValidationResult result =	identityStore.validate(new TokenResponseCredential(tokenResponse));

			if (result.getStatus() == VALID) {
				httpMsgContext.notifyContainerAboutLogin(
					result.getCallerPrincipal(),
					result.getCallerGroups());

				if (!useSessions) {
					request.getSession().removeAttribute(SOCIAL_PROFILE);
				}

				return SUCCESS;
			}
		}
		catch (IllegalStateException e) {
			if (e.getMessage() != null) {
				request.getSession().setAttribute(SOCIAL_PROFILE, null);
				response.sendRedirect(registrationErrorUrl + "?failure-reason=" + encodeURL(e.getMessage()));
			}
		}

		return SEND_FAILURE;
	}

	// Workaround for possible CDI bug; at least in Weld 2.3.2 default methods
	// don't seem to be intercepted
	// See https://issues.jboss.org/browse/WELD-2093
	@Override
	public void cleanSubject(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) {
		HttpAuthenticationMechanism.super.cleanSubject(request, response, httpMessageContext);
	}

}
