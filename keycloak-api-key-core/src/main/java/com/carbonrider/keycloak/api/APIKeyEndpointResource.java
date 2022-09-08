package com.carbonrider.keycloak.api;

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
import com.carbonrider.keycloak.exception.ExceptionResponseHandler;
import com.carbonrider.keycloak.model.APIKey;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resources.Cors;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/*
 * REST endpoints for creating and deleting api key.
 *
 * @author Yogesh Jadhav
 */

public class APIKeyEndpointResource {

    private final KeycloakSession session;

    private final APIKeyDomain apiKeyDomain;

    public APIKeyEndpointResource(KeycloakSession session) {
        this.session = session;
        this.apiKeyDomain = new APIKeyDomain(session);
    }

    @OPTIONS
    @Path("{any:.*}")
    public Response preflight() {
        HttpRequest httpRequest = this.session.getContext().getContextObject(HttpRequest.class);
        return Cors.add(httpRequest, Response.ok()).auth().preflight().build();
    }

    @POST
    @Path("/api-key")
    @Produces({MediaType.APPLICATION_JSON})
    public Response generateAPIKeyForUser(@QueryParam("userid") String userId) {
        try {
            APIKey apiKey = this.apiKeyDomain.generateAPIKeyForUser(userId);
            return Response.ok().entity(apiKey).build();
        } catch (Exception e) {
            return ExceptionResponseHandler.handleException(e);
        }
    }

    @DELETE
    @Path("/api-key")
    @Produces({MediaType.APPLICATION_JSON})
    public Response deleteAPIKeyForUser(@QueryParam("userid") String userId) {
        try {
            this.apiKeyDomain.deleteAPIKeyFromUser(userId);
            return Response.ok().build();
        } catch (Exception e) {
            return ExceptionResponseHandler.handleException(e);
        }
    }
}
