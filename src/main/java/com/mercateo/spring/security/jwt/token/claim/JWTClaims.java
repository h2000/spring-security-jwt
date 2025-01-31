/*
 * Copyright © 2017 Mercateo AG (http://www.mercateo.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.mercateo.spring.security.jwt.token.claim;

import com.auth0.jwt.interfaces.DecodedJWT;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Singular;
import lombok.ToString;
import lombok.experimental.Accessors;

@AllArgsConstructor
@Builder(toBuilder = true, builderClassName = "JWTClaimsBuilder")
@ToString
@EqualsAndHashCode
@Getter
@Accessors(fluent = true)
public class JWTClaims {

  private final DecodedJWT token;
  @Singular private final Map<String, JWTClaim> claims;
  private final int verifiedCount;

  @SuppressWarnings({"unused", "FieldMayBeFinal"})
  public static class JWTClaimsBuilder {

    private int verifiedCount = 0;
  }
}
