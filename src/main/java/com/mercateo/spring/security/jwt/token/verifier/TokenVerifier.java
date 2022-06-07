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
package com.mercateo.spring.security.jwt.token.verifier;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import java.util.Optional;
import lombok.AllArgsConstructor;

@AllArgsConstructor
public class TokenVerifier {

  private final Optional<JWTVerifier> verifier;

  public boolean verifyToken(DecodedJWT token) {

    return verifier
        .filter(ignore -> !"none".equals(token.getAlgorithm()))
        .map(x -> verify(token, x))
        .orElse(false);
  }

  private boolean verify(DecodedJWT token, JWTVerifier verifier) {
    try {
      verifier.verify(token.getToken());
      return true;
    } catch (RuntimeException e) {
      throw new InvalidTokenException("could not verify token", e);
    }
  }
}
