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

import com.google.common.annotations.VisibleForTesting;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import java.io.IOException;
import java.util.Collections;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.AntPathMatcher;

@Slf4j
public class JWTAuthenticationTokenFilter extends AbstractAuthenticationProcessingFilter {

  private static final String DEFAULT_FILTER_PROCESSES_URL = "/**";
  private static final String TOKEN_HEADER = "authorization";
  private static final String TOKEN_PREFIX_BEARER = "Bearer ";

  private final AntPathMatcher antPathMatcher = new AntPathMatcher();

  private final Set<String> unauthenticatedPaths;

  public JWTAuthenticationTokenFilter() {
    this(Collections.emptySet());
  }

  public JWTAuthenticationTokenFilter(Set<String> unauthenticatedPaths) {
    super(DEFAULT_FILTER_PROCESSES_URL);
    this.unauthenticatedPaths = Collections.unmodifiableSet(unauthenticatedPaths);
  }

  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    val request = (HttpServletRequest) req;
    val response = (HttpServletResponse) res;

    final String pathToCheck = pathFrom(request);
    final String tokenHeader = request.getHeader(TOKEN_HEADER);

    if (isInvalidTokenPrefixForBearer(tokenHeader)) {
      try {
        handleNoBearerToken(request, response, chain, tokenHeader, pathToCheck);
      } catch (InvalidTokenException e) {
        unsuccessfulAuthentication(request, response, e);
      }
    } else {
      continueAuthenticationChecks(request, response, chain);
    }
  }

  /**
   * Continue with default logic see {@link
   * AbstractAuthenticationProcessingFilter#doFilter(ServletRequest, ServletResponse, FilterChain)}
   * for Details.
   *
   * <p>This method is only needed to test the super.doFilter(..) call.
   */
  @VisibleForTesting
  void continueAuthenticationChecks(ServletRequest req, ServletResponse res, FilterChain chain)
      throws ServletException, IOException {
    super.doFilter(req, res, chain);
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) {
    final String tokenHeader = request.getHeader(TOKEN_HEADER);

    if (isInvalidTokenPrefixForBearer(tokenHeader)) {
      // signal super class to stop processing
      return null;
    }
    // existence of whitespace is ensured in isInvalidTokenPrefixForBearer
    final String authToken = tokenHeader.split("\\s+")[1];
    return getAuthenticationManager().authenticate(new JWTAuthenticationToken(authToken));
  }

  @Override
  protected void successfulAuthentication(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain,
      Authentication authResult)
      throws IOException, ServletException {
    super.successfulAuthentication(request, response, chain, authResult);

    chain.doFilter(request, response);
  }

  @VisibleForTesting
  void handleNoBearerToken(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain,
      String token,
      String pathToCheck)
      throws IOException, ServletException {

    log.debug("No {}token found: {} ({})", TOKEN_PREFIX_BEARER, pathToCheck, token);

    if (isUnauthenticatedPath(pathToCheck)) {
      chain.doFilter(request, response);
    } else {
      final String message = //
          "No " + TOKEN_PREFIX_BEARER + "token and no unauthenticated path [" + pathToCheck + "].";
      throw new InvalidTokenException(message);
    }
  }

  @VisibleForTesting
  boolean isInvalidTokenPrefixForBearer(final String tokenHeader) {
    return tokenHeader == null || !tokenHeader.startsWith(TOKEN_PREFIX_BEARER);
  }

  @VisibleForTesting
  boolean isUnauthenticatedPath(final String pathToCheck) {
    return unauthenticatedPaths.stream().anyMatch(path -> antPathMatcher.match(path, pathToCheck));
  }

  @VisibleForTesting
  String pathFrom(HttpServletRequest request) {
    final String pathInfo = String.valueOf(request.getPathInfo()).replace("null", "");
    final String servletPath = String.valueOf(request.getServletPath()).replace("null", "");

    // request URL depends on the default servlet or mounted location
    return servletPath + pathInfo;
  }
}
