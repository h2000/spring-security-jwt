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
package com.mercateo.spring.security.jwt.token.extractor;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import java.util.Optional;

class TokenProcessor {

  DecodedJWT decodeToken(String tokenString) {
    try {
      return JWT.decode(tokenString);
    } catch (JWTDecodeException e) {
      throw new InvalidTokenException("could not decode token", e);
    }
  }

  Optional<String> wrappedToken(DecodedJWT token, String claimName) {
    final Claim claim = token.getClaim(claimName);
    return Optional //
        .ofNullable(claim)
        .filter(c -> !c.isNull())
        .map(Claim::asString);
  }
}
