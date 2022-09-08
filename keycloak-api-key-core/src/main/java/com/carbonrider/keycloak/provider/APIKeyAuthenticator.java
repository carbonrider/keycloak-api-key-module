package com.carbonrider.keycloak.provider;

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

import com.carbonrider.keycloak.domain.APIKeyDomain;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.List;

/*
 * @author Yogesh Jadhav
 */

public class APIKeyAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {

    private final KeycloakSession session;

    public APIKeyAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        List<String> apiKeyCollection = context.getHttpRequest().getHttpHeaders().getRequestHeader(APIKeyDomain.API_KEY_HEADER_ATTRIBUTE);
        if (apiKeyCollection == null || apiKeyCollection.isEmpty()) {
            return;
        }

        String apiKey = apiKeyCollection.get(0);

        APIKeyDomain apiKeyDomain = new APIKeyDomain(this.session);

        UserModel user = apiKeyDomain.findUserFromKey(apiKey).orElseThrow(() -> new AuthenticationFlowException("Invalid api key", AuthenticationFlowError.INVALID_CREDENTIALS));

        if (!enabledUser(context, user)) {
            context.cancelLogin();
            return;
        }

        context.setUser(user);
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    @Override
    public void close() {
    }
}
