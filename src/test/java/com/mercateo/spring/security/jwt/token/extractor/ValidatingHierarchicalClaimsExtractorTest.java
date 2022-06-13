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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.mercateo.spring.security.jwt.JWKProvider;
import com.mercateo.spring.security.jwt.support.Try;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.config.JWTConfigData;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.MissingClaimException;
import com.mercateo.spring.security.jwt.token.exception.MissingSignatureException;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import java.lang.reflect.Method;
import java.util.Date;
import java.util.HashMap;
import java.util.Optional;
import lombok.val;
import org.junit.Before;
import org.junit.Test;

public class ValidatingHierarchicalClaimsExtractorTest {

  private static final String KEY_ID = "0815";

  private ValidatingHierarchicalClaimsExtractor uut;

  private Algorithm algorithm;

  private Jwk jwk;

  private JWTKeyset jwks;

  public JWTConfig securityConfig() {
    return JWTConfigData.builder()
        // .addAnonymousPaths("/admin/app_health")
        .jwtKeyset(mock(JWTKeyset.class))
        .addRequiredClaims("foo")
        .addOptionalClaims("https://test.org/bar")
        .build();
  }

  @Before
  public void setUp() {
    final JWKProvider jwkProvider = new JWKProvider();
    jwk = jwkProvider.create(KEY_ID);
    algorithm = jwkProvider.getAlgorithm();

    val securityConfig = securityConfig();

    jwks =
        Optional.of(securityConfig)
            .flatMap(JWTConfig::jwtKeyset)
            .orElseThrow(() -> new IllegalStateException("could not fetch jwks mock"));
    when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

    uut = new ValidatingHierarchicalClaimsExtractor(securityConfig);
  }

  private JWTCreator.Builder unsignedJwtBuilder() {
    return JWT.create().withIssuer("<otherIssuer>");
  }

  private JWTCreator.Builder signedJwtBuilder() {
    return JWT.create().withIssuer("<issuer>").withKeyId(KEY_ID);
  }

  private JWTClaim getClaimByName(JWTClaims claims, String name) {
    return claims.claims().get(name);
  }

  private void assertClaimContent(JWTClaim claim, Object value, boolean verified, int depth) {
    assertThat(claim).extracting(JWTClaim::value).isEqualTo(value);
    assertThat(claim.verified()).isEqualTo(verified);
    assertThat(claim.depth()).isEqualTo(depth);
  }

  @Test
  public void extractsVerifiedClaims() {
    val tokenString =
        signedJwtBuilder()
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .withClaim("bar", "<bar>")
            .sign(algorithm);

    val claims = uut.extractClaims(tokenString);

    assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");
    assertClaimContent(getClaimByName(claims, "scope"), "test", true, 0);
    assertClaimContent(getClaimByName(claims, "foo"), "<foo>", true, 0);
  }

  @Test
  public void extractsClaimsOfDifferentType() throws Exception {
    val securityConfig =
        JWTConfigData.builder()
            .jwtKeyset(mock(JWTKeyset.class))
            .addRequiredClaims("string")
            .addRequiredClaims("float")
            .addRequiredClaims("int")
            .addRequiredClaims("object")
            .build();
    val uut = new ValidatingHierarchicalClaimsExtractor(securityConfig);

    final Method addClaim =
        JWTCreator.Builder.class.getDeclaredMethod("addClaim", String.class, Object.class);
    addClaim.setAccessible(true);

    final JWTCreator.Builder builder =
        signedJwtBuilder().withClaim("string", "test").withClaim("float", 1.1).withClaim("int", 12);
    final HashMap<String, Object> objectClaim = new HashMap<>();
    objectClaim.put("foo", 1.2);
    objectClaim.put("bar", "test");
    addClaim.invoke(builder, "object", objectClaim);

    val tokenString = builder.sign(algorithm);

    jwks =
        Optional.of(securityConfig)
            .flatMap(JWTConfig::jwtKeyset)
            .orElseThrow(() -> new IllegalStateException("could not fetch jwks mock"));
    when(jwks.getKeysetForId(KEY_ID)).thenReturn(Try.success(jwk));

    val claims = uut.extractClaims(tokenString);

    assertThat(claims.claims().keySet())
        .containsExactlyInAnyOrder("int", "string", "float", "object");
    assertClaimContent(getClaimByName(claims, "int"), 12, true, 0);
    assertClaimContent(getClaimByName(claims, "string"), "test", true, 0);
    assertClaimContent(getClaimByName(claims, "float"), 1.1, true, 0);
    assertClaimContent(getClaimByName(claims, "object"), objectClaim, true, 0);
  }

  @Test
  public void extractsNamespacedClaims() {
    val tokenString =
        signedJwtBuilder() //
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .withClaim("https://test.org/bar", "<bar>")
            .sign(algorithm);

    val claims = uut.extractClaims(tokenString);

    assertThat(claims.claims().keySet())
        .containsExactlyInAnyOrder("scope", "foo", "https://test.org/bar");
    assertClaimContent(getClaimByName(claims, "https://test.org/bar"), "<bar>", true, 0);
  }

  @Test
  public void mergesClaimsFromInnerAndOuterToken() {
    val wrappedTokenString =
        signedJwtBuilder() //
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .sign(algorithm);

    val tokenString =
        unsignedJwtBuilder()
            .withClaim("scope", "test test2")
            .withClaim("jwt", wrappedTokenString)
            .sign(Algorithm.none());

    val claims = uut.extractClaims(tokenString);

    assertThat(claims.claims().keySet()).containsExactlyInAnyOrder("scope", "foo");

    assertClaimContent(getClaimByName(claims, "scope"), "test test2", false, 0);
    assertClaimContent(getClaimByName(claims, "foo"), "<foo>", true, 1);
  }

  @Test
  public void keepsClaimsFromInnerTokenAsInnerClaims() {
    val wrappedTokenString =
        signedJwtBuilder() //
            .withClaim("scope", "test")
            .withClaim("foo", "<foo>")
            .sign(algorithm);

    val tokenString =
        unsignedJwtBuilder()
            .withClaim("scope", "test test2")
            .withClaim("jwt", wrappedTokenString)
            .sign(Algorithm.none());

    val claims = uut.extractClaims(tokenString);

    final JWTClaim scope = getClaimByName(claims, "scope");
    final JWTClaim innerScope =
        scope.innerClaim().orElseGet(() -> JWTClaim.builder().name("noInnerClaim").build());
    assertClaimContent(innerScope, "test", true, 1);
  }

  @Test
  public void throwsExceptionWithoutSignedToken() {
    final String tokenString = JWT.create().sign(Algorithm.none());

    assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
        .isInstanceOf(MissingSignatureException.class)
        .hasMessage("at least one part of the token should be signed");
  }

  @Test
  public void doesNotThrowsExceptionWithoutSignedTokenIfNoValidatorIsConfigured() {
    val uut = new ValidatingHierarchicalClaimsExtractor(JWTConfigData.builder().build());
    final String tokenString = JWT.create().sign(Algorithm.none());

    val result = uut.extractClaims(tokenString);

    assertThat(result).isNotNull();
  }

  @Test
  public void throwsExceptionWhenRequiredScopeIsMissing() {
    final String tokenString = signedJwtBuilder().withClaim("scope", "test").sign(algorithm);

    assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
        .isInstanceOf(MissingClaimException.class)
        .hasMessage("missing required claim(s): foo");
  }

  @Test
  public void rethrowsJWTException() {
    val tokenString = "<token>";

    assertThatThrownBy(() -> uut.extractClaims(tokenString)) //
        .isInstanceOf(InvalidTokenException.class)
        .hasMessage("could not decode token");
  }

  @Test
  public void throwsExceptionWhenTokenIsExpired() {
    final String tokenString =
        signedJwtBuilder()
            .withClaim("scope", "test")
            .withClaim("https://test.org/foo", "<foo>")
            .withExpiresAt(new Date(System.currentTimeMillis() - 10000))
            .sign(algorithm);

    assertThatThrownBy(() -> uut.extractClaims(tokenString))
        .isInstanceOf(InvalidTokenException.class)
        .hasMessage("could not verify token")
        .hasCauseInstanceOf(TokenExpiredException.class);
  }
}
