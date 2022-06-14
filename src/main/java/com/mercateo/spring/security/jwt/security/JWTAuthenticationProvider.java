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
package com.mercateo.spring.security.jwt.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.mercateo.spring.security.jwt.security.config.JWTAuthority;
import com.mercateo.spring.security.jwt.token.claim.JWTClaim;
import com.mercateo.spring.security.jwt.token.claim.JWTClaims;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.exception.TokenException;
import com.mercateo.spring.security.jwt.token.extractor.ValidatingHierarchicalClaimsExtractor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Slf4j
@AllArgsConstructor
public class JWTAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

  private final ValidatingHierarchicalClaimsExtractor hierarchicalJWTClaimsExtractor;

  @Override
  public boolean supports(Class<?> authentication) {
    return (JWTAuthenticationToken.class.isAssignableFrom(authentication));
  }

  @Override
  protected void additionalAuthenticationChecks(
      UserDetails userDetails, UsernamePasswordAuthenticationToken authentication)
      throws AuthenticationException {
    // intentionally left blank
  }

  @Override
  protected UserDetails retrieveUser(
      String username, UsernamePasswordAuthenticationToken authentication)
      throws AuthenticationException {
    final String tokenString = ((JWTAuthenticationToken) authentication).getToken();

    final JWTClaims claims;
    try {
      claims = hierarchicalJWTClaimsExtractor.extractClaims(tokenString);
    } catch (TokenException e) {
      final String message = searchMessageInException(e, "failed to extract token");
      throw new InvalidTokenException(message, e);
    }

    final DecodedJWT token = JWT.decode(tokenString);
    final String subject = token.getSubject();
    final int id = subject != null ? subject.hashCode() : 0;
    final List<? extends GrantedAuthority> authorities = retrieveAuthorities(claims);

    return new JWTPrincipal(id, subject, tokenString, authorities, claims.claims());
  }

  private static String searchMessageInException(RuntimeException e, String defaultErrorMsg) {
    if (e.getCause() != null && e.getCause().getMessage() != null) {
      return e.getCause().getMessage();
    } else if (e.getMessage() != null) {
      return e.getMessage();
    } else {
      return defaultErrorMsg;
    }
  }

  protected List<? extends GrantedAuthority> retrieveAuthorities(JWTClaims claims) {
    final List<String> scopes = extractScopes(claims);
    final List<String> roles = extractRoles(claims);
    final ArrayList<String> all = new ArrayList<>(scopes);
    all.addAll(roles);
    return all.stream()
        .map(value -> JWTAuthority.builder().authority(value).build())
        .collect(Collectors.toList());
  }

  private List<String> extractScopes(JWTClaims claims) {
    return Optional.ofNullable(claims.claims().get("scope"))
        .map(JWTClaim::value)
        .filter(Objects::nonNull)
        .map(value -> ((String) value).split("\\s+"))
        .map(Arrays::asList)
        .orElse(Collections.emptyList());
  }

  private List<String> extractRoles(JWTClaims claims) {
    return Optional.ofNullable(claims.claims().get("roles"))
        .map(JWTClaim::value)
        .filter(Objects::nonNull)
        .map(container -> (Object[]) container)
        .map(Arrays::asList)
        .map(
            list ->
                list //
                    .stream()
                    .map(element -> "ROLE_" + element)
                    .map(String::toUpperCase)
                    .collect(Collectors.toList()))
        .orElse(Collections.emptyList());
  }
}
