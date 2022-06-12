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

import static java.util.Objects.requireNonNull;

import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.support.Pair;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.verifier.TokenVerifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.stream.Collectors;

class HierarchicalClaimsExtractor {

  private final TokenProcessor tokenProcessor;

  private final TokenVerifier verifier;

  private final Set<String> claimNames;

  private final ClaimExtractor claimExtractor;

  private int depth;

  private int verifiedTokenCount;

  HierarchicalClaimsExtractor(
      TokenProcessor tokenProcessor,
      TokenVerifier verifier,
      Set<String> claimNames,
      ClaimExtractor claimExtractor) {
    this.tokenProcessor = tokenProcessor;
    this.verifier = verifier;
    this.claimNames = claimNames;
    this.claimExtractor = claimExtractor;

    depth = 0;
    verifiedTokenCount = 0;
  }

  List<JWTClaim> extractClaims(String tokenString) {
    final List<JWTClaim> claims = new ArrayList<>();

    // stack to collect unprocessed tokens
    final Stack<String> stack = new Stack<>();
    stack.push(tokenString);

    while (!stack.empty()) {
      final DecodedJWT token = tokenProcessor.decodeToken(stack.pop());
      // if token contains a "jwt" key
      tokenProcessor.wrappedToken(token)
        .ifPresent( stack::push);

      boolean verified = verifyToken(token);
      claims.addAll(extractClaims(token, verified));

      depth++;
    }

    return claims;
  }

  private List<JWTClaim> extractClaims(DecodedJWT token, boolean verified) {

    return claimNames.stream()
        // for all names: lookup claim value from token by name
        .map(claimName -> Pair.of(claimName, token.getClaim(claimName)))
        // ignore claims without value (so-called null claim)
        .filter(nameAndClaim -> !nameAndClaim.second().isNull())
        .map(
            nameAndClaim -> {
              final String claimName = nameAndClaim.first();
              final Claim claim = nameAndClaim.second();
              final String issuer =
                  requireNonNull(token.getIssuer(), "token issuer (iss) not found");
              final Object claimValue = claimExtractor.extract(claim);

              return JWTClaim.builder()
                  .name(claimName)
                  .value(claimValue)
                  .verified(verified)
                  .issuer(issuer)
                  .depth(depth)
                  .build();
            })
        .collect(Collectors.toList());
  }

  private boolean verifyToken(DecodedJWT token) {
    final boolean verified = verifier.verifyToken(token);

    if (verified) {
      verifiedTokenCount++;
    }
    return verified;
  }

  int getVerifiedTokenCount() {
    return verifiedTokenCount;
  }
}
