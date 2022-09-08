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

/*
 * @author Yogesh Jadhav
 */

public class InvalidAPIKeyException extends APIKeyException {

    private static final int CODE = 400;

    private static final String INVALID_API_KEY = "Invalid api key {%s}";

    private final String apiKey;

    public InvalidAPIKeyException(String apiKey) {
        super(String.format(INVALID_API_KEY, apiKey));
        this.apiKey = apiKey;
    }

    public int getCode() {
        return CODE;
    }

    @Override
    public ErrorMessage getFriendlyMessage() {
        return new ErrorMessage("INVALID_API_KEY", this.toString());
    }

    @Override
    public String toString() {
        return String.format(INVALID_API_KEY, apiKey);
    }
}
