package com.carbonrider.keycloak.spring.filter;

/*
 * Copyright 2022 Carbonrider.com and/or its affiliates
 * and other contributors as mentioned in author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.*;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.spi.AuthChallenge;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.adapters.spi.KeycloakAccount;
import org.keycloak.adapters.springsecurity.KeycloakAuthenticationException;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationEntryPoint;
import org.keycloak.adapters.springsecurity.authentication.RequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.authentication.SpringSecurityRequestAuthenticatorFactory;
import org.keycloak.adapters.springsecurity.facade.SimpleHttpFacade;
import org.keycloak.adapters.springsecurity.filter.AdapterStateCookieRequestMatcher;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.QueryParamPresenceRequestMatcher;
import org.keycloak.adapters.springsecurity.token.AdapterTokenStoreFactory;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.adapters.springsecurity.token.SpringSecurityAdapterTokenStoreFactory;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/*
 * Custom filter to check presence of "x-api-key" header.
 * The filter falls back to default Bearer Authentication
 * in case the header is not present.
 *
 * @author Yogesh Jadhav
 */
public class KeycloakAPIKeyProcessingFilter extends KeycloakAuthenticationProcessingFilter implements ApplicationContextAware {

    private static final Logger logger = LoggerFactory.getLogger(KeycloakAPIKeyProcessingFilter.class);

    private static final String API_KEY_HEADER = "x-api-key";

    public static final RequestMatcher API_KEY_REQUEST_MATCHER =
            new OrRequestMatcher(
                    new AntPathRequestMatcher(KeycloakAuthenticationEntryPoint.DEFAULT_LOGIN_URI),
                    new RequestHeaderRequestMatcher(AUTHORIZATION_HEADER),
                    new RequestHeaderRequestMatcher(API_KEY_HEADER),
                    new QueryParamPresenceRequestMatcher(OAuth2Constants.ACCESS_TOKEN),
                    new AdapterStateCookieRequestMatcher()
            );


    private final AdapterTokenStoreFactory adapterTokenStoreFactory = new SpringSecurityAdapterTokenStoreFactory();

    private final RequestAuthenticatorFactory requestAuthenticatorFactory = new SpringSecurityRequestAuthenticatorFactory();

    private AdapterDeploymentContext adapterDeploymentContext;

    private ApplicationContext applicationContext;

    private final AuthenticationManager authenticationManager;

    public KeycloakAPIKeyProcessingFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager, API_KEY_REQUEST_MATCHER);
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void afterPropertiesSet() {
        adapterDeploymentContext = applicationContext.getBean(AdapterDeploymentContext.class);
        super.afterPropertiesSet();
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        super.setApplicationContext(applicationContext);
        this.applicationContext = applicationContext;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String apiKey = request.getHeader(API_KEY_HEADER);

        if (request.getAttribute(KeycloakAPIKeyProcessingFilter.class.getName()) != null) {
            return (Authentication) request.getAttribute(KeycloakAPIKeyProcessingFilter.class.getName());
        }

        if (apiKey == null) {
            return super.attemptAuthentication(request, response);
        } else {

            logger.info("Attempting authentication using API key");

            HttpFacade facade = new SimpleHttpFacade(request, response);

            KeycloakDeployment deployment = adapterDeploymentContext.resolveDeployment(facade);

            deployment.setDelegateBearerErrorResponseSending(true);

            AdapterTokenStore tokenStore = adapterTokenStoreFactory.createAdapterTokenStore(deployment, request, response);


            logger.debug("Token URL {}", deployment.getTokenUrl());

            RequestAuthenticator authenticator
                    = requestAuthenticatorFactory.createRequestAuthenticator(facade, request, deployment, tokenStore, -1);

            AccessTokenResponse result = validateAPIKey(deployment, apiKey);

            logger.debug("Authentication outcome {}", result);

            if (result == null) {
                AuthChallenge challenge = authenticator.getChallenge();
                if (challenge != null) {
                    challenge.challenge(facade);
                }
                throw new KeycloakAuthenticationException("Invalid API key, please set valid value for x-api-key header");
            } else {
                try {
                    AccessToken token = AdapterTokenVerifier.verifyToken(result.getToken(), deployment);
                    RefreshableKeycloakSecurityContext session = new RefreshableKeycloakSecurityContext(deployment, null, result.getToken(), token, null, null, null);
                    final KeycloakPrincipal<RefreshableKeycloakSecurityContext> principal = new KeycloakPrincipal<>(
                            AdapterUtils.getPrincipalName(deployment, token), session);

                    RefreshableKeycloakSecurityContext securityContext = principal.getKeycloakSecurityContext();
                    Set<String> roles = AdapterUtils.getRolesFromSecurityContext(securityContext);
                    final KeycloakAccount account = new SimpleKeycloakAccount(principal, roles, securityContext);

                    SecurityContext context = SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(new KeycloakAuthenticationToken(account, false));
                    SecurityContextHolder.setContext(context);

                } catch (VerificationException e) {
                    throw new RuntimeException(e);
                }


                Authentication auth = authenticationManager.authenticate(SecurityContextHolder.getContext().getAuthentication());
                request.setAttribute(KeycloakAPIKeyProcessingFilter.class.getName(), auth);
                return auth;
            }
        }
    }

    private AccessTokenResponse validateAPIKey(KeycloakDeployment deployment, String apiKey) throws AuthenticationException, IOException {
        HttpPost post = new HttpPost(deployment.getTokenUrl());

        List<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair("grant_type", "password"));
        params.add(new BasicNameValuePair("client_id", deployment.getResourceName()));

        //For validation add dummy fields.
        params.add(new BasicNameValuePair("username", "dummy"));
        params.add(new BasicNameValuePair("password", "dummy"));
        post.setEntity(new UrlEncodedFormEntity(params));

        post.addHeader(API_KEY_HEADER, apiKey);

        HttpResponse response = deployment.getClient().execute(post);

        int status = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();

        if (status != 200) {
            throw new BadCredentialsException("API Key is invalid");
        }

        if (entity == null) {
            throw new AuthenticationServiceException("Didn't receive expected response from Keycloak API validation.");
        }

        InputStream is = entity.getContent();

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        int c;
        while ((c = is.read()) != -1) {
            os.write(c);
        }
        byte[] bytes = os.toByteArray();
        String json = new String(bytes);

        return JsonSerialization.readValue(json, AccessTokenResponse.class);

    }
}
