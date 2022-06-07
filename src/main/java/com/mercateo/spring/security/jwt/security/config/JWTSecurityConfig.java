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
package com.mercateo.spring.security.jwt.security.config;

import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifier;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifierFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Immutable implementation of {@link JWTSecurityConfig}.
 *
 * <p>Use the builder to create immutable instances: {@code JWTSecurityConfig.builder()}.
 */
@SuppressWarnings({"all"})
public final class JWTSecurityConfig implements JWTConfig {
  private final int tokenLeeway;
  private final Set<String> tokenAudiences;
  private final Set<String> requiredClaims;
  private final Set<String> optionalClaims;
  private final JWTKeyset jwtKeyset;
  private final transient Optional<JWTVerifier> jwtVerifier;
  private final Set<String> anonymousPaths;
  private final Set<HttpMethod> anonymousMethods;
  private final AuthenticationFailureHandler authenticationFailureHandler;

  private JWTSecurityConfig(Builder builder) {
    this.tokenAudiences = createUnmodifiableSet(builder.tokenAudiences);
    this.requiredClaims = createUnmodifiableSet(builder.requiredClaims);
    this.optionalClaims = createUnmodifiableSet(builder.optionalClaims);
    this.jwtKeyset = builder.jwtKeyset;
    this.anonymousPaths = createUnmodifiableSet(builder.anonymousPaths);
    this.anonymousMethods = createUnmodifiableEnumSet(builder.anonymousMethods);
    this.authenticationFailureHandler = builder.authenticationFailureHandler;
    if (builder.tokenLeewayIsSet()) {
      initShim.tokenLeeway(builder.tokenLeeway);
    }
    this.tokenLeeway = initShim.getTokenLeeway();
    this.jwtVerifier = initShim.jwtVerifier();
    this.initShim = null;
  }

  private JWTSecurityConfig(
      int tokenLeeway,
      Set<String> tokenAudiences,
      Set<String> requiredClaims,
      Set<String> optionalClaims,
      JWTKeyset jwtKeyset,
      Set<String> anonymousPaths,
      Set<HttpMethod> anonymousMethods,
      AuthenticationFailureHandler authenticationFailureHandler) {
    initShim.tokenLeeway(tokenLeeway);
    this.tokenAudiences = tokenAudiences;
    this.requiredClaims = requiredClaims;
    this.optionalClaims = optionalClaims;
    this.jwtKeyset = jwtKeyset;
    this.anonymousPaths = anonymousPaths;
    this.anonymousMethods = anonymousMethods;
    this.authenticationFailureHandler = authenticationFailureHandler;
    this.tokenLeeway = initShim.getTokenLeeway();
    this.jwtVerifier = initShim.jwtVerifier();
    this.initShim = null;
  }

  private static final byte STAGE_INITIALIZING = -1;
  private static final byte STAGE_UNINITIALIZED = 0;
  private static final byte STAGE_INITIALIZED = 1;
  private transient volatile InitShim initShim = new InitShim();

  private final class InitShim {
    private byte tokenLeewayBuildStage = STAGE_UNINITIALIZED;
    private int tokenLeeway;

    int getTokenLeeway() {
      if (tokenLeewayBuildStage == STAGE_INITIALIZING)
        throw new IllegalStateException(formatInitCycleMessage());
      if (tokenLeewayBuildStage == STAGE_UNINITIALIZED) {
        tokenLeewayBuildStage = STAGE_INITIALIZING;
        this.tokenLeeway = getTokenLeewayInitialize();
        tokenLeewayBuildStage = STAGE_INITIALIZED;
      }
      return this.tokenLeeway;
    }

    void tokenLeeway(int tokenLeeway) {
      this.tokenLeeway = tokenLeeway;
      tokenLeewayBuildStage = STAGE_INITIALIZED;
    }

    private byte jwtVerifierBuildStage = STAGE_UNINITIALIZED;
    private Optional<JWTVerifier> jwtVerifier;

    Optional<JWTVerifier> jwtVerifier() {
      if (jwtVerifierBuildStage == STAGE_INITIALIZING)
        throw new IllegalStateException(formatInitCycleMessage());
      if (jwtVerifierBuildStage == STAGE_UNINITIALIZED) {
        jwtVerifierBuildStage = STAGE_INITIALIZING;
        this.jwtVerifier = Objects.requireNonNull(jwtVerifierInitialize(), "jwtVerifier");
        jwtVerifierBuildStage = STAGE_INITIALIZED;
      }
      return this.jwtVerifier;
    }

    private String formatInitCycleMessage() {
      List<String> attributes = new ArrayList<>();
      if (tokenLeewayBuildStage == STAGE_INITIALIZING) attributes.add("tokenLeeway");
      if (jwtVerifierBuildStage == STAGE_INITIALIZING) attributes.add("jwtVerifier");
      return "Cannot build JWTSecurityConfig, attribute initializers form cycle " + attributes;
    }
  }

  private int getTokenLeewayInitialize() {
    return 0;
  }

  private Optional<JWTVerifier> jwtVerifierInitialize() {
    return jwtKeyset()
        .map(jwks -> new JWTVerifierFactory(jwks, this))
        .map(JWTVerifierFactory::create);
  }

  /**
   * @return The default window in seconds in which the Not Before, Issued At and Expires At Claims
   *     will still be valid. Setting a specific leeway value on a given Claim will override this
   *     value for that Claim.
   */
  @Override
  public int getTokenLeeway() {
    InitShim shim = this.initShim;
    return shim != null ? shim.getTokenLeeway() : this.tokenLeeway;
  }

  /** @return required Audience ("aud") claims */
  @Override
  public Set<String> getTokenAudiences() {
    return tokenAudiences;
  }

  /** @return set of required claims */
  @Override
  public Set<String> getRequiredClaims() {
    return requiredClaims;
  }

  /** @return set of claims which should be processed if they exist */
  @Override
  public Set<String> getOptionalClaims() {
    return optionalClaims;
  }

  /** @return {@link JWTKeyset} to be used for token verification */
  @Override
  public Optional<JWTKeyset> jwtKeyset() {
    return Optional.ofNullable(jwtKeyset);
  }

  /** @return {@link JWTVerifier} for given {@link JWTKeyset} to be used for token verification */
  @Override
  public Optional<JWTVerifier> jwtVerifier() {
    InitShim shim = this.initShim;
    return shim != null ? shim.jwtVerifier() : this.jwtVerifier;
  }

  /** @return Paths with anonymous access */
  public Set<String> anonymousPaths() {
    return anonymousPaths;
  }

  /** @return {@link HttpMethod} with anynomous access */
  public Set<HttpMethod> anonymousMethods() {
    return anonymousMethods;
  }

  /** @return The value of the {@code authenticationFailureHandler} attribute */
  public Optional<AuthenticationFailureHandler> authenticationFailureHandler() {
    return Optional.ofNullable(authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link
   * JWTSecurityConfig#getTokenLeeway() tokenLeeway} attribute. A value equality check is used to
   * prevent copying of the same value by returning {@code this}.
   *
   * @param value A new value for tokenLeeway
   * @return A modified copy of the {@code this} object
   */
  public final JWTSecurityConfig withTokenLeeway(int value) {
    if (this.tokenLeeway == value) return this;
    return new JWTSecurityConfig(
        value,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getTokenAudiences() tokenAudiences}.
   *
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withTokenAudiences(String... elements) {
    Set<String> newValue =
        createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        newValue,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getTokenAudiences() tokenAudiences}. A shallow reference equality check is
   * used to prevent copying of the same value by returning {@code this}.
   *
   * @param elements An iterable of tokenAudiences elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withTokenAudiences(Iterable<String> elements) {
    if (this.tokenAudiences == elements) return this;
    Set<String> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        newValue,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getRequiredClaims() requiredClaims}.
   *
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withRequiredClaims(String... elements) {
    Set<String> newValue =
        createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        newValue,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getRequiredClaims() requiredClaims}. A shallow reference equality check is
   * used to prevent copying of the same value by returning {@code this}.
   *
   * @param elements An iterable of requiredClaims elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withRequiredClaims(Iterable<String> elements) {
    if (this.requiredClaims == elements) return this;
    Set<String> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        newValue,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getOptionalClaims() optionalClaims}.
   *
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withOptionalClaims(String... elements) {
    Set<String> newValue =
        createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        newValue,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#getOptionalClaims() optionalClaims}. A shallow reference equality check is
   * used to prevent copying of the same value by returning {@code this}.
   *
   * @param elements An iterable of optionalClaims elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withOptionalClaims(Iterable<String> elements) {
    if (this.optionalClaims == elements) return this;
    Set<String> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        newValue,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object by setting a <i>present</i> value for the optional {@link
   * JWTSecurityConfig#jwtKeyset() jwtKeyset} attribute.
   *
   * @param value The value for jwtKeyset
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withJwtKeyset(JWTKeyset value) {
    JWTKeyset newValue = Objects.requireNonNull(value, "jwtKeyset");
    if (this.jwtKeyset == newValue) return this;
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        newValue,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object by setting an optional value for the {@link
   * JWTSecurityConfig#jwtKeyset() jwtKeyset} attribute. A shallow reference equality check is used
   * on unboxed optional value to prevent copying of the same value by returning {@code this}.
   *
   * @param optional A value for jwtKeyset
   * @return A modified copy of {@code this} object
   */
  @SuppressWarnings("unchecked") // safe covariant cast
  public final JWTSecurityConfig withJwtKeyset(Optional<? extends JWTKeyset> optional) {
    JWTKeyset value = optional.orElse(null);
    if (this.jwtKeyset == value) return this;
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        value,
        this.anonymousPaths,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#anonymousPaths() anonymousPaths}.
   *
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withAnonymousPaths(String... elements) {
    Set<String> newValue =
        createUnmodifiableSet(createSafeList(Arrays.asList(elements), true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        newValue,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#anonymousPaths() anonymousPaths}. A shallow reference equality check is used
   * to prevent copying of the same value by returning {@code this}.
   *
   * @param elements An iterable of anonymousPaths elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withAnonymousPaths(Iterable<String> elements) {
    if (this.anonymousPaths == elements) return this;
    Set<String> newValue = createUnmodifiableSet(createSafeList(elements, true, false));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        newValue,
        this.anonymousMethods,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#anonymousMethods() anonymousMethods}.
   *
   * @param elements The elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withAnonymousMethods(HttpMethod... elements) {
    Set<HttpMethod> newValue = createUnmodifiableEnumSet(Arrays.asList(elements));
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        newValue,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object with elements that replace the content of {@link
   * JWTSecurityConfig#anonymousMethods() anonymousMethods}. A shallow reference equality check is
   * used to prevent copying of the same value by returning {@code this}.
   *
   * @param elements An iterable of anonymousMethods elements to set
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withAnonymousMethods(Iterable<HttpMethod> elements) {
    if (this.anonymousMethods == elements) return this;
    Set<HttpMethod> newValue = createUnmodifiableEnumSet(elements);
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        newValue,
        this.authenticationFailureHandler);
  }

  /**
   * Copy the current immutable object by setting a <i>present</i> value for the optional {@link
   * JWTSecurityConfig#authenticationFailureHandler() authenticationFailureHandler} attribute.
   *
   * @param value The value for authenticationFailureHandler
   * @return A modified copy of {@code this} object
   */
  public final JWTSecurityConfig withAuthenticationFailureHandler(
      AuthenticationFailureHandler value) {
    AuthenticationFailureHandler newValue =
        Objects.requireNonNull(value, "authenticationFailureHandler");
    if (this.authenticationFailureHandler == newValue) return this;
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        newValue);
  }

  /**
   * Copy the current immutable object by setting an optional value for the {@link
   * JWTSecurityConfig#authenticationFailureHandler() authenticationFailureHandler} attribute. A
   * shallow reference equality check is used on unboxed optional value to prevent copying of the
   * same value by returning {@code this}.
   *
   * @param optional A value for authenticationFailureHandler
   * @return A modified copy of {@code this} object
   */
  @SuppressWarnings("unchecked") // safe covariant cast
  public final JWTSecurityConfig withAuthenticationFailureHandler(
      Optional<? extends AuthenticationFailureHandler> optional) {
    AuthenticationFailureHandler value = optional.orElse(null);
    if (this.authenticationFailureHandler == value) return this;
    return new JWTSecurityConfig(
        this.tokenLeeway,
        this.tokenAudiences,
        this.requiredClaims,
        this.optionalClaims,
        this.jwtKeyset,
        this.anonymousPaths,
        this.anonymousMethods,
        value);
  }

  /**
   * This instance is equal to all instances of {@code JWTSecurityConfig} that have equal attribute
   * values.
   *
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof JWTSecurityConfig && equalTo((JWTSecurityConfig) another);
  }

  private boolean equalTo(JWTSecurityConfig another) {
    return tokenLeeway == another.tokenLeeway
        && tokenAudiences.equals(another.tokenAudiences)
        && requiredClaims.equals(another.requiredClaims)
        && optionalClaims.equals(another.optionalClaims)
        && Objects.equals(jwtKeyset, another.jwtKeyset)
        && jwtVerifier.equals(another.jwtVerifier)
        && anonymousPaths.equals(another.anonymousPaths)
        && anonymousMethods.equals(another.anonymousMethods)
        && Objects.equals(authenticationFailureHandler, another.authenticationFailureHandler);
  }

  /**
   * Computes a hash code from attributes: {@code tokenLeeway}, {@code tokenAudiences}, {@code
   * requiredClaims}, {@code optionalClaims}, {@code jwtKeyset}, {@code jwtVerifier}, {@code
   * anonymousPaths}, {@code anonymousMethods}, {@code authenticationFailureHandler}.
   *
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + tokenLeeway;
    h += (h << 5) + tokenAudiences.hashCode();
    h += (h << 5) + requiredClaims.hashCode();
    h += (h << 5) + optionalClaims.hashCode();
    h += (h << 5) + Objects.hashCode(jwtKeyset);
    h += (h << 5) + jwtVerifier.hashCode();
    h += (h << 5) + anonymousPaths.hashCode();
    h += (h << 5) + anonymousMethods.hashCode();
    h += (h << 5) + Objects.hashCode(authenticationFailureHandler);
    return h;
  }

  /**
   * Prints the immutable value {@code JWTSecurityConfig} with attribute values.
   *
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("JWTSecurityConfig{");
    builder.append("tokenLeeway=").append(tokenLeeway);
    builder.append(", ");
    builder.append("tokenAudiences=").append(tokenAudiences);
    builder.append(", ");
    builder.append("requiredClaims=").append(requiredClaims);
    builder.append(", ");
    builder.append("optionalClaims=").append(optionalClaims);
    if (jwtKeyset != null) {
      builder.append(", ");
      builder.append("jwtKeyset=").append(jwtKeyset);
    }
    builder.append(", ");
    builder.append("jwtVerifier=").append(jwtVerifier);
    builder.append(", ");
    builder.append("anonymousPaths=").append(anonymousPaths);
    builder.append(", ");
    builder.append("anonymousMethods=").append(anonymousMethods);
    if (authenticationFailureHandler != null) {
      builder.append(", ");
      builder.append("authenticationFailureHandler=").append(authenticationFailureHandler);
    }
    return builder.append("}").toString();
  }

  /**
   * Creates an immutable copy of a {@link JWTSecurityConfig} value. Uses accessors to get values to
   * initialize the new immutable instance. If an instance is already immutable, it is returned as
   * is.
   *
   * @param instance The instance to copy
   * @return A copied immutable JWTSecurityConfig instance
   */
  public static JWTSecurityConfig copyOf(JWTSecurityConfig instance) {
    if (instance instanceof JWTSecurityConfig) {
      return (JWTSecurityConfig) instance;
    }
    return JWTSecurityConfig.builder().from(instance).build();
  }

  /**
   * Creates a builder for {@link JWTSecurityConfig JWTSecurityConfig}.
   *
   * <pre>
   * JWTSecurityConfig.builder()
   *    .tokenLeeway(int) // optional {@link JWTSecurityConfig#getTokenLeeway() tokenLeeway}
   *    .addTokenAudiences|addAllTokenAudiences(String) // {@link JWTSecurityConfig#getTokenAudiences() tokenAudiences} elements
   *    .addRequiredClaims|addAllRequiredClaims(String) // {@link JWTSecurityConfig#getRequiredClaims() requiredClaims} elements
   *    .addOptionalClaims|addAllOptionalClaims(String) // {@link JWTSecurityConfig#getOptionalClaims() optionalClaims} elements
   *    .jwtKeyset(com.mercateo.spring.security.jwt.token.keyset.JWTKeyset) // optional {@link JWTSecurityConfig#jwtKeyset() jwtKeyset}
   *    .addAnonymousPaths|addAllAnonymousPaths(String) // {@link JWTSecurityConfig#anonymousPaths() anonymousPaths} elements
   *    .addAnonymousMethods|addAllAnonymousMethods(org.springframework.http.HttpMethod) // {@link JWTSecurityConfig#anonymousMethods() anonymousMethods} elements
   *    .authenticationFailureHandler(org.springframework.security.web.authentication.AuthenticationFailureHandler) // optional {@link JWTSecurityConfig#authenticationFailureHandler() authenticationFailureHandler}
   *    .build();
   * </pre>
   *
   * @return A new JWTSecurityConfig builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builds instances of type {@link JWTSecurityConfig JWTSecurityConfig}. Initialize attributes and
   * then invoke the {@link #build()} method to create an immutable instance.
   *
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or
   * collection, but instead used immediately to create instances.</em>
   */
  public static final class Builder {
    private static final long OPT_BIT_TOKEN_LEEWAY = 0x1L;
    private long optBits;

    private int tokenLeeway;
    private List<String> tokenAudiences = new ArrayList<String>();
    private List<String> requiredClaims = new ArrayList<String>();
    private List<String> optionalClaims = new ArrayList<String>();
    private JWTKeyset jwtKeyset;
    private List<String> anonymousPaths = new ArrayList<String>();
    private EnumSet<HttpMethod> anonymousMethods = EnumSet.noneOf(HttpMethod.class);
    private AuthenticationFailureHandler authenticationFailureHandler;

    private Builder() {}

    /**
     * Fill a builder with attribute values from the provided {@code
     * com.mercateo.spring.security.jwt.token.config.JWTConfig} instance.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(JWTConfig instance) {
      Objects.requireNonNull(instance, "instance");
      from((Object) instance);
      return this;
    }

    /**
     * Fill a builder with attribute values from the provided {@code
     * com.mercateo.spring.security.jwt.security.config._JWTSecurityConfig} instance.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(JWTSecurityConfig instance) {
      Objects.requireNonNull(instance, "instance");
      from((Object) instance);
      return this;
    }

    private void from(Object object) {
      if (object instanceof JWTConfig) {
        JWTConfig instance = (JWTConfig) object;
        Optional<JWTKeyset> jwtKeysetOptional = instance.jwtKeyset();
        if (jwtKeysetOptional.isPresent()) {
          jwtKeyset(jwtKeysetOptional);
        }
        tokenLeeway(instance.getTokenLeeway());
        addAllTokenAudiences(instance.getTokenAudiences());
        addAllRequiredClaims(instance.getRequiredClaims());
        addAllOptionalClaims(instance.getOptionalClaims());
      }
      if (object instanceof JWTSecurityConfig) {
        JWTSecurityConfig instance = (JWTSecurityConfig) object;
        addAllAnonymousPaths(instance.anonymousPaths());
        Optional<AuthenticationFailureHandler> authenticationFailureHandlerOptional =
            instance.authenticationFailureHandler();
        if (authenticationFailureHandlerOptional.isPresent()) {
          authenticationFailureHandler(authenticationFailureHandlerOptional);
        }
        addAllAnonymousMethods(instance.anonymousMethods());
      }
    }

    /**
     * Initializes the value for the {@link JWTSecurityConfig#getTokenLeeway() tokenLeeway}
     * attribute.
     *
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of
     * {@link JWTSecurityConfig#getTokenLeeway() tokenLeeway}.</em>
     *
     * @param tokenLeeway The value for tokenLeeway
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder tokenLeeway(int tokenLeeway) {
      this.tokenLeeway = tokenLeeway;
      optBits |= OPT_BIT_TOKEN_LEEWAY;
      return this;
    }

    /**
     * Adds one element to {@link JWTSecurityConfig#getTokenAudiences() tokenAudiences} set.
     *
     * @param element A tokenAudiences element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addTokenAudiences(String element) {
      this.tokenAudiences.add(Objects.requireNonNull(element, "tokenAudiences element"));
      return this;
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getTokenAudiences() tokenAudiences} set.
     *
     * @param elements An array of tokenAudiences elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addTokenAudiences(String... elements) {
      for (String element : elements) {
        this.tokenAudiences.add(Objects.requireNonNull(element, "tokenAudiences element"));
      }
      return this;
    }

    /**
     * Sets or replaces all elements for {@link JWTSecurityConfig#getTokenAudiences()
     * tokenAudiences} set.
     *
     * @param elements An iterable of tokenAudiences elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder tokenAudiences(Iterable<String> elements) {
      this.tokenAudiences.clear();
      return addAllTokenAudiences(elements);
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getTokenAudiences() tokenAudiences} set.
     *
     * @param elements An iterable of tokenAudiences elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllTokenAudiences(Iterable<String> elements) {
      for (String element : elements) {
        this.tokenAudiences.add(Objects.requireNonNull(element, "tokenAudiences element"));
      }
      return this;
    }

    /**
     * Adds one element to {@link JWTSecurityConfig#getRequiredClaims() requiredClaims} set.
     *
     * @param element A requiredClaims element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addRequiredClaims(String element) {
      this.requiredClaims.add(Objects.requireNonNull(element, "requiredClaims element"));
      return this;
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getRequiredClaims() requiredClaims} set.
     *
     * @param elements An array of requiredClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addRequiredClaims(String... elements) {
      for (String element : elements) {
        this.requiredClaims.add(Objects.requireNonNull(element, "requiredClaims element"));
      }
      return this;
    }

    /**
     * Sets or replaces all elements for {@link JWTSecurityConfig#getRequiredClaims()
     * requiredClaims} set.
     *
     * @param elements An iterable of requiredClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder requiredClaims(Iterable<String> elements) {
      this.requiredClaims.clear();
      return addAllRequiredClaims(elements);
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getRequiredClaims() requiredClaims} set.
     *
     * @param elements An iterable of requiredClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllRequiredClaims(Iterable<String> elements) {
      for (String element : elements) {
        this.requiredClaims.add(Objects.requireNonNull(element, "requiredClaims element"));
      }
      return this;
    }

    /**
     * Adds one element to {@link JWTSecurityConfig#getOptionalClaims() optionalClaims} set.
     *
     * @param element A optionalClaims element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addOptionalClaims(String element) {
      this.optionalClaims.add(Objects.requireNonNull(element, "optionalClaims element"));
      return this;
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getOptionalClaims() optionalClaims} set.
     *
     * @param elements An array of optionalClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addOptionalClaims(String... elements) {
      for (String element : elements) {
        this.optionalClaims.add(Objects.requireNonNull(element, "optionalClaims element"));
      }
      return this;
    }

    /**
     * Sets or replaces all elements for {@link JWTSecurityConfig#getOptionalClaims()
     * optionalClaims} set.
     *
     * @param elements An iterable of optionalClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder optionalClaims(Iterable<String> elements) {
      this.optionalClaims.clear();
      return addAllOptionalClaims(elements);
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#getOptionalClaims() optionalClaims} set.
     *
     * @param elements An iterable of optionalClaims elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllOptionalClaims(Iterable<String> elements) {
      for (String element : elements) {
        this.optionalClaims.add(Objects.requireNonNull(element, "optionalClaims element"));
      }
      return this;
    }

    /**
     * Initializes the optional value {@link JWTSecurityConfig#jwtKeyset() jwtKeyset} to jwtKeyset.
     *
     * @param jwtKeyset The value for jwtKeyset
     * @return {@code this} builder for chained invocation
     */
    public final Builder jwtKeyset(JWTKeyset jwtKeyset) {
      this.jwtKeyset = Objects.requireNonNull(jwtKeyset, "jwtKeyset");
      return this;
    }

    /**
     * Initializes the optional value {@link JWTSecurityConfig#jwtKeyset() jwtKeyset} to jwtKeyset.
     *
     * @param jwtKeyset The value for jwtKeyset
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder jwtKeyset(Optional<? extends JWTKeyset> jwtKeyset) {
      this.jwtKeyset = jwtKeyset.orElse(null);
      return this;
    }

    /**
     * Adds one element to {@link JWTSecurityConfig#anonymousPaths() anonymousPaths} set.
     *
     * @param element A anonymousPaths element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAnonymousPaths(String element) {
      this.anonymousPaths.add(Objects.requireNonNull(element, "anonymousPaths element"));
      return this;
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#anonymousPaths() anonymousPaths} set.
     *
     * @param elements An array of anonymousPaths elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAnonymousPaths(String... elements) {
      for (String element : elements) {
        this.anonymousPaths.add(Objects.requireNonNull(element, "anonymousPaths element"));
      }
      return this;
    }

    /**
     * Sets or replaces all elements for {@link JWTSecurityConfig#anonymousPaths() anonymousPaths}
     * set.
     *
     * @param elements An iterable of anonymousPaths elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder anonymousPaths(Iterable<String> elements) {
      this.anonymousPaths.clear();
      return addAllAnonymousPaths(elements);
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#anonymousPaths() anonymousPaths} set.
     *
     * @param elements An iterable of anonymousPaths elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllAnonymousPaths(Iterable<String> elements) {
      for (String element : elements) {
        this.anonymousPaths.add(Objects.requireNonNull(element, "anonymousPaths element"));
      }
      return this;
    }

    /**
     * Adds one element to {@link JWTSecurityConfig#anonymousMethods() anonymousMethods} set.
     *
     * @param element A anonymousMethods element
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAnonymousMethods(HttpMethod element) {
      this.anonymousMethods.add(Objects.requireNonNull(element, "anonymousMethods element"));
      return this;
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#anonymousMethods() anonymousMethods} set.
     *
     * @param elements An array of anonymousMethods elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAnonymousMethods(HttpMethod... elements) {
      for (HttpMethod element : elements) {
        this.anonymousMethods.add(Objects.requireNonNull(element, "anonymousMethods element"));
      }
      return this;
    }

    /**
     * Sets or replaces all elements for {@link JWTSecurityConfig#anonymousMethods()
     * anonymousMethods} set.
     *
     * @param elements An iterable of anonymousMethods elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder anonymousMethods(Iterable<HttpMethod> elements) {
      this.anonymousMethods.clear();
      return addAllAnonymousMethods(elements);
    }

    /**
     * Adds elements to {@link JWTSecurityConfig#anonymousMethods() anonymousMethods} set.
     *
     * @param elements An iterable of anonymousMethods elements
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder addAllAnonymousMethods(Iterable<HttpMethod> elements) {
      for (HttpMethod element : elements) {
        this.anonymousMethods.add(Objects.requireNonNull(element, "anonymousMethods element"));
      }
      return this;
    }

    /**
     * Initializes the optional value {@link JWTSecurityConfig#authenticationFailureHandler()
     * authenticationFailureHandler} to authenticationFailureHandler.
     *
     * @param authenticationFailureHandler The value for authenticationFailureHandler
     * @return {@code this} builder for chained invocation
     */
    public final Builder authenticationFailureHandler(
        AuthenticationFailureHandler authenticationFailureHandler) {
      this.authenticationFailureHandler =
          Objects.requireNonNull(authenticationFailureHandler, "authenticationFailureHandler");
      return this;
    }

    /**
     * Initializes the optional value {@link JWTSecurityConfig#authenticationFailureHandler()
     * authenticationFailureHandler} to authenticationFailureHandler.
     *
     * @param authenticationFailureHandler The value for authenticationFailureHandler
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder authenticationFailureHandler(
        Optional<? extends AuthenticationFailureHandler> authenticationFailureHandler) {
      this.authenticationFailureHandler = authenticationFailureHandler.orElse(null);
      return this;
    }

    /**
     * Builds a new {@link JWTSecurityConfig JWTSecurityConfig}.
     *
     * @return An immutable instance of JWTSecurityConfig
     * @throws IllegalStateException if any required attributes are missing
     */
    public JWTSecurityConfig build() {
      return new JWTSecurityConfig(this);
    }

    private boolean tokenLeewayIsSet() {
      return (optBits & OPT_BIT_TOKEN_LEEWAY) != 0;
    }
  }

  private static <T> List<T> createSafeList(
      Iterable<? extends T> iterable, boolean checkNulls, boolean skipNulls) {
    ArrayList<T> list;
    if (iterable instanceof Collection<?>) {
      int size = ((Collection<?>) iterable).size();
      if (size == 0) return Collections.emptyList();
      list = new ArrayList<>();
    } else {
      list = new ArrayList<>();
    }
    for (T element : iterable) {
      if (skipNulls && element == null) continue;
      if (checkNulls) Objects.requireNonNull(element, "element");
      list.add(element);
    }
    return list;
  }

  /** Unmodifiable set constructed from list to avoid rehashing. */
  private static <T> Set<T> createUnmodifiableSet(List<T> list) {
    switch (list.size()) {
      case 0:
        return Collections.emptySet();
      case 1:
        return Collections.singleton(list.get(0));
      default:
        Set<T> set = new LinkedHashSet<>(list.size());
        set.addAll(list);
        return Collections.unmodifiableSet(set);
    }
  }

  @SuppressWarnings("unchecked")
  private static <T extends Enum<T>> Set<T> createUnmodifiableEnumSet(Iterable<T> iterable) {
    if (iterable instanceof EnumSet<?>) {
      return Collections.unmodifiableSet(EnumSet.copyOf((EnumSet<T>) iterable));
    }
    List<T> list = createSafeList(iterable, true, false);
    switch (list.size()) {
      case 0:
        return Collections.emptySet();
      case 1:
        return Collections.singleton(list.get(0));
      default:
        return Collections.unmodifiableSet(EnumSet.copyOf(list));
    }
  }
}
