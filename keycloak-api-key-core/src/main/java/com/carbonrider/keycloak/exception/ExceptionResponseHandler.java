package com.carbonrider.keycloak.exception;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.core.Response;

/*
 * @author Yogesh Jadhav
 */

public class ExceptionResponseHandler {

    private static final Logger logger = LoggerFactory.getLogger(ExceptionResponseHandler.class);

    private ExceptionResponseHandler() {
    }

    public static Response handleException(Exception e) {

        if (logger.isErrorEnabled()) {
            logger.error("Request couldn't be served.", e);
        }

        if (e instanceof APIKeyException) {
            APIKeyException apiKeyException = (APIKeyException) e;
            return Response.status(apiKeyException.getCode()).entity(apiKeyException.getFriendlyMessage()).build();
        }

        return Response.status(400).entity(new ErrorMessage("SERVER_ERROR", e.getMessage())).build();
    }
}
