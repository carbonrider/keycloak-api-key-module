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

public class UserNotFoundException extends APIKeyException {

    private static final int CODE = 400;

    private static final String USER_NOT_FOUND = "User not found {%s}";

    private final String userKey;

    public UserNotFoundException(String userKey) {
        super(String.format(USER_NOT_FOUND, userKey));
        this.userKey = userKey;
    }

    public int getCode() {
        return CODE;
    }

    @Override
    public ErrorMessage getFriendlyMessage() {
        return new ErrorMessage("USER_NOT_FOUND", this.toString());
    }

    @Override
    public String toString() {
        return String.format(USER_NOT_FOUND, userKey);
    }
}
