package com.carbonrider.keycloak.domain;

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

import com.carbonrider.keycloak.exception.APIKeyNotConfiguredForUserException;
import com.carbonrider.keycloak.exception.UnauthorizedAccessException;
import com.carbonrider.keycloak.exception.UserNotFoundException;
import com.carbonrider.keycloak.model.APIKey;
import org.keycloak.common.util.RandomString;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.jpa.entities.UserAttributeEntity;
import org.keycloak.models.jpa.entities.UserEntity;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/*
* Contains implementation logic for generating and deleting API key.
* @author Yogesh Jadhav
*/
public class APIKeyDomain {

    public static final String API_KEY_ATTRIBUTE = "api-key";

    public static final String API_KEY_HEADER_ATTRIBUTE = "x-api-key";

    private final RandomString randomString;

    private final EntityManager entityManager;

    private final AuthenticationManager.AuthResult authResult;

    private final KeycloakSession session;

    public APIKeyDomain(KeycloakSession session) {
        this.session = session;
        this.randomString = new RandomString(50);
        this.entityManager = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        this.authResult = new AppAuthManager().authenticateBearerToken(session);
    }

    private void checkAuthorisation() {
        if (authResult == null) {
            throw new UnauthorizedAccessException();
        }

        if (this.authResult.getToken().getRealmAccess() == null) {
            throw new UnauthorizedAccessException("NO_REALM_ACCESS");
        }

        boolean hasAccess = this.authResult.getToken().getRealmAccess().isUserInRole("api-key-generator");

        if (!hasAccess) {
            throw new UnauthorizedAccessException(this.authResult.getUser().getId());
        }

    }

    public APIKey generateAPIKeyForUser(String userId) {

        checkAuthorisation();

        String randomAPIKey = this.randomString.nextString();
        UserEntity user = this.entityManager.find(UserEntity.class, userId);
        if (user == null) {
            throw new UserNotFoundException(userId);
        }

        UserAttributeEntity apiKeyAttribute = new UserAttributeEntity();
        apiKeyAttribute.setUser(user);
        apiKeyAttribute.setName(API_KEY_ATTRIBUTE);
        apiKeyAttribute.setValue(randomAPIKey);

        UUID apiKey = UUID.randomUUID();
        apiKeyAttribute.setId(apiKey.toString());

        this.entityManager.persist(apiKeyAttribute);

        APIKey key = new APIKey();
        key.setKey(apiKey);

        return key;
    }


    public void deleteAPIKeyFromUser(String userId) {
        checkAuthorisation();

        UserEntity user = this.entityManager.find(UserEntity.class, userId);
        if (user == null) {
            throw new UserNotFoundException(userId);
        }

        CriteriaBuilder cb = this.entityManager.getCriteriaBuilder();
        CriteriaQuery<UserAttributeEntity> query = cb.createQuery(UserAttributeEntity.class);
        Root<UserAttributeEntity> item = query.from(UserAttributeEntity.class);
        query.select(item).where(
                cb.and(
                        cb.equal(item.get("user"), user),
                        cb.equal(item.get("name"), API_KEY_ATTRIBUTE)
                )
        );

        Query apiAttributeQuery = this.entityManager.createQuery(query);
        List<UserAttributeEntity> apiAttributes = apiAttributeQuery.getResultList();
        if (apiAttributes == null || apiAttributes.isEmpty()) {
            throw new APIKeyNotConfiguredForUserException(userId);
        } else {
            this.entityManager.remove(apiAttributes.get(0));
        }
    }

    public Optional<UserModel> findUserFromKey(String apiKey) {

        RealmModel realm = this.session.getContext().getRealm();

        List<UserModel> users = this.session.userStorageManager().searchForUserByUserAttribute(API_KEY_ATTRIBUTE, apiKey, realm);

        if(users.isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(users.get(0));
    }
}
