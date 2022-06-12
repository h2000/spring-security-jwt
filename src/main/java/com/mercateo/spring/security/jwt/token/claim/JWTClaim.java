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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable implementation of {@link JWTClaim}.
 *
 * <p>Use the builder to create immutable instances: {@code JWTClaim.builder()}.
 */
@SuppressWarnings({"all"})
public class JWTClaim {
  private final String name;
  private final Object value;
  private final String issuer;
  private final boolean verified;
  private final JWTClaim innerClaim;
  private final int depth;

  private JWTClaim(JWTClaim.Builder builder) {
    this.name = builder.name;
    this.value = builder.value;
    this.innerClaim = builder.innerClaim;
    if (builder.issuer != null) {
      initShim.issuer(builder.issuer);
    }
    if (builder.verifiedIsSet()) {
      initShim.verified(builder.verified);
    }
    if (builder.depthIsSet()) {
      initShim.depth(builder.depth);
    }
    this.issuer = initShim.issuer();
    this.verified = initShim.verified();
    this.depth = initShim.depth();
    this.initShim = null;
  }

  private JWTClaim(
      String name, Object value, String issuer, boolean verified, JWTClaim innerClaim, int depth) {
    this.name = name;
    this.value = value;
    this.issuer = issuer;
    this.verified = verified;
    this.innerClaim = innerClaim;
    this.depth = depth;
    this.initShim = null;
  }

  private static final byte STAGE_INITIALIZING = -1;
  private static final byte STAGE_UNINITIALIZED = 0;
  private static final byte STAGE_INITIALIZED = 1;
  private transient volatile InitShim initShim = new InitShim();

  private final class InitShim {
    private byte issuerBuildStage = STAGE_UNINITIALIZED;
    private String issuer;

    String issuer() {
      if (issuerBuildStage == STAGE_INITIALIZING)
        throw new IllegalStateException(formatInitCycleMessage());
      if (issuerBuildStage == STAGE_UNINITIALIZED) {
        issuerBuildStage = STAGE_INITIALIZING;
        this.issuer = Objects.requireNonNull(issuerInitialize(), "issuer");
        issuerBuildStage = STAGE_INITIALIZED;
      }
      return this.issuer;
    }

    void issuer(String issuer) {
      this.issuer = issuer;
      issuerBuildStage = STAGE_INITIALIZED;
    }

    private byte verifiedBuildStage = STAGE_UNINITIALIZED;
    private boolean verified;

    boolean verified() {
      if (verifiedBuildStage == STAGE_INITIALIZING)
        throw new IllegalStateException(formatInitCycleMessage());
      if (verifiedBuildStage == STAGE_UNINITIALIZED) {
        verifiedBuildStage = STAGE_INITIALIZING;
        this.verified = verifiedInitialize();
        verifiedBuildStage = STAGE_INITIALIZED;
      }
      return this.verified;
    }

    void verified(boolean verified) {
      this.verified = verified;
      verifiedBuildStage = STAGE_INITIALIZED;
    }

    private byte depthBuildStage = STAGE_UNINITIALIZED;
    private int depth;

    int depth() {
      if (depthBuildStage == STAGE_INITIALIZING)
        throw new IllegalStateException(formatInitCycleMessage());
      if (depthBuildStage == STAGE_UNINITIALIZED) {
        depthBuildStage = STAGE_INITIALIZING;
        this.depth = depthInitialize();
        depthBuildStage = STAGE_INITIALIZED;
      }
      return this.depth;
    }

    void depth(int depth) {
      this.depth = depth;
      depthBuildStage = STAGE_INITIALIZED;
    }

    private String formatInitCycleMessage() {
      List<String> attributes = new ArrayList<>();
      if (issuerBuildStage == STAGE_INITIALIZING) attributes.add("issuer");
      if (verifiedBuildStage == STAGE_INITIALIZING) attributes.add("verified");
      if (depthBuildStage == STAGE_INITIALIZING) attributes.add("depth");
      return "Cannot build JWTClaim, attribute initializers form cycle " + attributes;
    }
  }

  private String issuerInitialize() {
    return "";
  }

  private boolean verifiedInitialize() {
    return false;
  }

  private int depthInitialize() {
    return 0;
  }

  /** @return The value of the {@code name} attribute */
  public String name() {
    return name;
  }

  /** @return The value of the {@code value} attribute */
  public Object value() {
    return value;
  }

  /** @return The value of the {@code issuer} attribute */
  public String issuer() {
    InitShim shim = this.initShim;
    return shim != null ? shim.issuer() : this.issuer;
  }

  /** @return The value of the {@code verified} attribute */
  public boolean verified() {
    InitShim shim = this.initShim;
    return shim != null ? shim.verified() : this.verified;
  }

  /** @return The value of the {@code innerClaim} attribute */
  public Optional<JWTClaim> innerClaim() {
    return Optional.ofNullable(innerClaim);
  }

  /** @return The value of the {@code depth} attribute */
  public int depth() {
    InitShim shim = this.initShim;
    return shim != null ? shim.depth() : this.depth;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaim#name() name}
   * attribute. An equals check used to prevent copying of the same value by returning {@code this}.
   *
   * @param value A new value for name
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaim withName(String value) {
    String newValue = Objects.requireNonNull(value, "name");
    if (this.name.equals(newValue)) return this;
    return new JWTClaim(
        newValue, this.value, this.issuer, this.verified, this.innerClaim, this.depth);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaim#value() value}
   * attribute. A shallow reference equality check is used to prevent copying of the same value by
   * returning {@code this}.
   *
   * @param value A new value for value
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaim withValue(Object value) {
    if (this.value == value) return this;
    Object newValue = Objects.requireNonNull(value, "value");
    return new JWTClaim(
        this.name, newValue, this.issuer, this.verified, this.innerClaim, this.depth);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaim#issuer() issuer}
   * attribute. An equals check used to prevent copying of the same value by returning {@code this}.
   *
   * @param value A new value for issuer
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaim withIssuer(String value) {
    String newValue = Objects.requireNonNull(value, "issuer");
    if (this.issuer.equals(newValue)) return this;
    return new JWTClaim(
        this.name, this.value, newValue, this.verified, this.innerClaim, this.depth);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaim#verified()
   * verified} attribute. A value equality check is used to prevent copying of the same value by
   * returning {@code this}.
   *
   * @param value A new value for verified
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaim withVerified(boolean value) {
    if (this.verified == value) return this;
    return new JWTClaim(this.name, this.value, this.issuer, value, this.innerClaim, this.depth);
  }

  /**
   * Copy the current immutable object by setting a <i>present</i> value for the optional {@link
   * JWTClaim#innerClaim() innerClaim} attribute.
   *
   * @param value The value for innerClaim
   * @return A modified copy of {@code this} object
   */
  public final JWTClaim withInnerClaim(JWTClaim value) {
    JWTClaim newValue = Objects.requireNonNull(value, "innerClaim");
    if (this.innerClaim == newValue) return this;
    return new JWTClaim(this.name, this.value, this.issuer, this.verified, newValue, this.depth);
  }

  /**
   * Copy the current immutable object by setting an optional value for the {@link
   * JWTClaim#innerClaim() innerClaim} attribute. A shallow reference equality check is used on
   * unboxed optional value to prevent copying of the same value by returning {@code this}.
   *
   * @param optional A value for innerClaim
   * @return A modified copy of {@code this} object
   */
  @SuppressWarnings("unchecked") // safe covariant cast
  public final JWTClaim withInnerClaim(Optional<? extends JWTClaim> optional) {
    JWTClaim value = optional.orElse(null);
    if (this.innerClaim == value) return this;
    return new JWTClaim(this.name, this.value, this.issuer, this.verified, value, this.depth);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaim#depth() depth}
   * attribute. A value equality check is used to prevent copying of the same value by returning
   * {@code this}.
   *
   * @param value A new value for depth
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaim withDepth(int value) {
    if (this.depth == value) return this;
    return new JWTClaim(this.name, this.value, this.issuer, this.verified, this.innerClaim, value);
  }

  /**
   * This instance is equal to all instances of {@code JWTClaim} that have equal attribute values.
   *
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof JWTClaim && equalTo((JWTClaim) another);
  }

  private boolean equalTo(JWTClaim another) {
    return name.equals(another.name)
        && value.equals(another.value)
        && issuer.equals(another.issuer)
        && verified == another.verified
        && Objects.equals(innerClaim, another.innerClaim)
        && depth == another.depth;
  }

  /**
   * Computes a hash code from attributes: {@code name}, {@code value}, {@code issuer}, {@code
   * verified}, {@code innerClaim}, {@code depth}.
   *
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + name.hashCode();
    h += (h << 5) + value.hashCode();
    h += (h << 5) + issuer.hashCode();
    h += (h << 5) + Boolean.hashCode(verified);
    h += (h << 5) + Objects.hashCode(innerClaim);
    h += (h << 5) + depth;
    return h;
  }

  /**
   * Prints the immutable value {@code JWTClaim} with attribute values.
   *
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder("JWTClaim{");
    builder.append("name=").append(name);
    builder.append(", ");
    builder.append("value=").append(value);
    builder.append(", ");
    builder.append("issuer=").append(issuer);
    builder.append(", ");
    builder.append("verified=").append(verified);
    if (innerClaim != null) {
      builder.append(", ");
      builder.append("innerClaim=").append(innerClaim);
    }
    builder.append(", ");
    builder.append("depth=").append(depth);
    return builder.append("}").toString();
  }

  /**
   * Creates an immutable copy of a {@link JWTClaim} value. Uses accessors to get values to
   * initialize the new immutable instance. If an instance is already immutable, it is returned as
   * is.
   *
   * @param instance The instance to copy
   * @return A copied immutable JWTClaim instance
   */
  public static JWTClaim copyOf(JWTClaim instance) {
    if (instance instanceof JWTClaim) {
      return (JWTClaim) instance;
    }
    return JWTClaim.builder().from(instance).build();
  }

  /**
   * Creates a builder for {@link JWTClaim JWTClaim}.
   *
   * <pre>
   * JWTClaim.builder()
   *    .name(String) // required {@link JWTClaim#name() name}
   *    .value(Object) // required {@link JWTClaim#value() value}
   *    .issuer(String) // optional {@link JWTClaim#issuer() issuer}
   *    .verified(boolean) // optional {@link JWTClaim#verified() verified}
   *    .innerClaim(JWTClaim) // optional {@link JWTClaim#innerClaim() innerClaim}
   *    .depth(int) // optional {@link JWTClaim#depth() depth}
   *    .build();
   * </pre>
   *
   * @return A new JWTClaim builder
   */
  public static JWTClaim.Builder builder() {
    return new JWTClaim.Builder();
  }

  /**
   * Builds instances of type {@link JWTClaim JWTClaim}. Initialize attributes and then invoke the
   * {@link #build()} method to create an immutable instance.
   *
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or
   * collection, but instead used immediately to create instances.</em>
   */
  public static final class Builder {
    private static final long INIT_BIT_NAME = 0x1L;
    private static final long INIT_BIT_VALUE = 0x2L;
    private static final long OPT_BIT_VERIFIED = 0x1L;
    private static final long OPT_BIT_DEPTH = 0x2L;
    private long initBits = 0x3L;
    private long optBits;

    private String name;
    private Object value;
    private String issuer;
    private boolean verified;
    private JWTClaim innerClaim;
    private int depth;

    private Builder() {}

    /**
     * Fill a builder with attribute values from the provided {@code JWTClaim} instance. Regular
     * attribute values will be replaced with those from the given instance. Absent optional values
     * will not replace present values.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(JWTClaim instance) {
      Objects.requireNonNull(instance, "instance");
      name(instance.name());
      value(instance.value());
      issuer(instance.issuer());
      verified(instance.verified());
      Optional<JWTClaim> innerClaimOptional = instance.innerClaim();
      if (innerClaimOptional.isPresent()) {
        innerClaim(innerClaimOptional);
      }
      depth(instance.depth());
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaim#name() name} attribute.
     *
     * @param name The value for name
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder name(String name) {
      this.name = Objects.requireNonNull(name, "name");
      initBits &= ~INIT_BIT_NAME;
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaim#value() value} attribute.
     *
     * @param value The value for value
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder value(Object value) {
      this.value = Objects.requireNonNull(value, "value");
      initBits &= ~INIT_BIT_VALUE;
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaim#issuer() issuer} attribute.
     *
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of
     * {@link JWTClaim#issuer() issuer}.</em>
     *
     * @param issuer The value for issuer
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder issuer(String issuer) {
      this.issuer = Objects.requireNonNull(issuer, "issuer");
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaim#verified() verified} attribute.
     *
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of
     * {@link JWTClaim#verified() verified}.</em>
     *
     * @param verified The value for verified
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder verified(boolean verified) {
      this.verified = verified;
      optBits |= OPT_BIT_VERIFIED;
      return this;
    }

    /**
     * Initializes the optional value {@link JWTClaim#innerClaim() innerClaim} to innerClaim.
     *
     * @param innerClaim The value for innerClaim
     * @return {@code this} builder for chained invocation
     */
    public final Builder innerClaim(JWTClaim innerClaim) {
      this.innerClaim = Objects.requireNonNull(innerClaim, "innerClaim");
      return this;
    }

    /**
     * Initializes the optional value {@link JWTClaim#innerClaim() innerClaim} to innerClaim.
     *
     * @param innerClaim The value for innerClaim
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder innerClaim(Optional<? extends JWTClaim> innerClaim) {
      this.innerClaim = innerClaim.orElse(null);
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaim#depth() depth} attribute.
     *
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of
     * {@link JWTClaim#depth() depth}.</em>
     *
     * @param depth The value for depth
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder depth(int depth) {
      this.depth = depth;
      optBits |= OPT_BIT_DEPTH;
      return this;
    }

    /**
     * Builds a new {@link JWTClaim JWTClaim}.
     *
     * @return An immutable instance of JWTClaim
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public JWTClaim build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new JWTClaim(this);
    }

    private boolean verifiedIsSet() {
      return (optBits & OPT_BIT_VERIFIED) != 0;
    }

    private boolean depthIsSet() {
      return (optBits & OPT_BIT_DEPTH) != 0;
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_NAME) != 0) attributes.add("name");
      if ((initBits & INIT_BIT_VALUE) != 0) attributes.add("value");
      return "Cannot build JWTClaim, some of required attributes are not set " + attributes;
    }
  }
}
