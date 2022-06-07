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
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifier;
import com.mercateo.spring.security.jwt.token.verifier.TokenVerifier;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ValidatingHierarchicalClaimsExtractor {

  public static final String WRAPPED_TOKEN_KEY = "jwt";

  public static final List<String> AUTHORIZATION_CLAIMS =
      Arrays.asList("scope", "authorization", "roles");

  private final TokenProcessor tokenProcessor;

  private final TokenVerifier verifier;

  private final InnerClaimsWrapper collector;

  private final RequiredClaimNamesValidator requiredClaimNamesValidator;

  private final Set<String> claims;

  private final Optional<JWTVerifier> jwtVerifier;

  public ValidatingHierarchicalClaimsExtractor(final JWTConfig config) {
    this.tokenProcessor = new TokenProcessor();
    this.jwtVerifier = config.jwtVerifier();
    this.verifier = new TokenVerifier(jwtVerifier);
    this.requiredClaimNamesValidator = new RequiredClaimNamesValidator(config.getRequiredClaims());
    this.collector = new InnerClaimsWrapper();

    final HashSet<String> claimNames = new HashSet<>();
    claimNames.addAll(config.getOptionalClaims());
    claimNames.addAll(AUTHORIZATION_CLAIMS);
    claimNames.addAll(config.getRequiredClaims());
    this.claims = Collections.unmodifiableSet(claimNames);

    config.jwtVerifier().ifPresent(v -> log.info("use JWT verifier {}", v));
  }

  public JWTClaims extractClaims(final String tokenString) {
    final ClaimExtractor claimExtractor = new ClaimExtractor();
    final HierarchicalClaimsExtractor extractor =
        new HierarchicalClaimsExtractor(tokenProcessor, verifier, claims, claimExtractor);

    final List<JWTClaim> claims = extractor.extractClaims(tokenString);

    if (jwtVerifier.isPresent()) {
      requiredClaimNamesValidator.ensureAtLeastOneVerifiedToken(extractor.getVerifiedTokenCount());
    }
    requiredClaimNamesValidator.ensurePresenceOfRequiredClaims(claims);

    return JWTClaims.builder()
        .claims(collector.wrapInnerClaims(claims))
        .verifiedCount(extractor.getVerifiedTokenCount())
        .token(JWT.decode(tokenString))
        .build();
  }

  public boolean hasJWTVerifier() {
    return jwtVerifier.isPresent();
  }
}
