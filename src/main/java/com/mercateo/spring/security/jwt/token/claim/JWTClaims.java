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
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable implementation of {@link JWTClaims}.
 *
 * <p>Use the builder to create immutable instances: {@code JWTClaims.builder()}.
 */
@SuppressWarnings({"all"})
public class JWTClaims {
  private final DecodedJWT token;
  private final Map<String, JWTClaim> claims;
  private final int verifiedCount;

  private JWTClaims(JWTClaims.Builder builder) {
    this.token = builder.token;
    this.claims = createUnmodifiableMap(false, false, builder.claims);
    this.verifiedCount = builder.verifiedCountIsSet() ? builder.verifiedCount : verifiedCount();
  }

  private JWTClaims(DecodedJWT token, Map<String, JWTClaim> claims, int verifiedCount) {
    this.token = token;
    this.claims = claims;
    this.verifiedCount = verifiedCount;
  }

  /** @return The value of the {@code token} attribute */
  public DecodedJWT token() {
    return token;
  }

  /** @return The value of the {@code claims} attribute */
  public Map<String, JWTClaim> claims() {
    return claims;
  }

  /** @return The value of the {@code verifiedCount} attribute */
  public int verifiedCount() {
    return verifiedCount;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaims#token() token}
   * attribute. A shallow reference equality check is used to prevent copying of the same value by
   * returning {@code this}.
   *
   * @param value A new value for token
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaims withToken(DecodedJWT value) {
    if (this.token == value) return this;
    DecodedJWT newValue = Objects.requireNonNull(value, "token");
    return new JWTClaims(newValue, this.claims, this.verifiedCount);
  }

  /**
   * Copy the current immutable object by replacing the {@link JWTClaims#claims() claims} map with
   * the specified map. Nulls are not permitted as keys or values. A shallow reference equality
   * check is used to prevent copying of the same value by returning {@code this}.
   *
   * @param entries The entries to be added to the claims map
   * @return A modified copy of {@code this} object
   */
  public final JWTClaims withClaims(Map<String, ? extends JWTClaim> entries) {
    if (this.claims == entries) return this;
    Map<String, JWTClaim> newValue = createUnmodifiableMap(true, false, entries);
    return new JWTClaims(this.token, newValue, this.verifiedCount);
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTClaims#verifiedCount()
   * verifiedCount} attribute. A value equality check is used to prevent copying of the same value
   * by returning {@code this}.
   *
   * @param value A new value for verifiedCount
   * @return A modified copy of the {@code this} object
   */
  public final JWTClaims withVerifiedCount(int value) {
    if (this.verifiedCount == value) return this;
    return new JWTClaims(this.token, this.claims, value);
  }

  /**
   * This instance is equal to all instances of {@code JWTClaims} that have equal attribute values.
   *
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof JWTClaims && equalTo((JWTClaims) another);
  }

  private boolean equalTo(JWTClaims another) {
    return token.equals(another.token)
        && claims.equals(another.claims)
        && verifiedCount == another.verifiedCount;
  }

  /**
   * Computes a hash code from attributes: {@code token}, {@code claims}, {@code verifiedCount}.
   *
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + token.hashCode();
    h += (h << 5) + claims.hashCode();
    h += (h << 5) + verifiedCount;
    return h;
  }

  /**
   * Prints the immutable value {@code JWTClaims} with attribute values.
   *
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "JWTClaims{"
        + "token="
        + token
        + ", claims="
        + claims
        + ", verifiedCount="
        + verifiedCount
        + "}";
  }

  /**
   * Creates an immutable copy of a {@link JWTClaims} value. Uses accessors to get values to
   * initialize the new immutable instance. If an instance is already immutable, it is returned as
   * is.
   *
   * @param instance The instance to copy
   * @return A copied immutable JWTClaims instance
   */
  public static JWTClaims copyOf(JWTClaims instance) {
    if (instance instanceof JWTClaims) {
      return (JWTClaims) instance;
    }
    return JWTClaims.builder().from(instance).build();
  }

  /**
   * Creates a builder for {@link JWTClaims JWTClaims}.
   *
   * <pre>
   * JWTClaims.builder()
   *    .token(com.auth0.jwt.interfaces.DecodedJWT) // required {@link JWTClaims#token() token}
   *    .putClaims|putAllClaims(String =&gt; JWTClaim) // {@link JWTClaims#claims() claims} mappings
   *    .verifiedCount(int) // optional {@link JWTClaims#verifiedCount() verifiedCount}
   *    .build();
   * </pre>
   *
   * @return A new JWTClaims builder
   */
  public static JWTClaims.Builder builder() {
    return new JWTClaims.Builder();
  }

  /**
   * Builds instances of type {@link JWTClaims JWTClaims}. Initialize attributes and then invoke the
   * {@link #build()} method to create an immutable instance.
   *
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or
   * collection, but instead used immediately to create instances.</em>
   */
  public static final class Builder {
    private static final long INIT_BIT_TOKEN = 0x1L;
    private static final long OPT_BIT_VERIFIED_COUNT = 0x1L;
    private long initBits = 0x1L;
    private long optBits;

    private DecodedJWT token;
    private Map<String, JWTClaim> claims = new LinkedHashMap<String, JWTClaim>();
    private int verifiedCount;

    private Builder() {}

    /**
     * Fill a builder with attribute values from the provided {@code _JWTClaims} instance. Regular
     * attribute values will be replaced with those from the given instance. Absent optional values
     * will not replace present values. Collection elements and entries will be added, not replaced.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(JWTClaims instance) {
      Objects.requireNonNull(instance, "instance");
      token(instance.token());
      putAllClaims(instance.claims());
      verifiedCount(instance.verifiedCount());
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaims#token() token} attribute.
     *
     * @param token The value for token
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder token(DecodedJWT token) {
      this.token = Objects.requireNonNull(token, "token");
      initBits &= ~INIT_BIT_TOKEN;
      return this;
    }

    /**
     * Put one entry to the {@link JWTClaims#claims() claims} map.
     *
     * @param key The key in the claims map
     * @param value The associated value in the claims map
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder putClaims(String key, JWTClaim value) {
      this.claims.put(
          Objects.requireNonNull(key, "claims key"), Objects.requireNonNull(value, "claims value"));
      return this;
    }

    /**
     * Put one entry to the {@link JWTClaims#claims() claims} map. Nulls are not permitted
     *
     * @param entry The key and value entry
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder putClaims(Map.Entry<String, ? extends JWTClaim> entry) {
      String k = entry.getKey();
      JWTClaim v = entry.getValue();
      this.claims.put(
          Objects.requireNonNull(k, "claims key"), Objects.requireNonNull(v, "claims value"));
      return this;
    }

    /**
     * Sets or replaces all mappings from the specified map as entries for the {@link
     * JWTClaims#claims() claims} map. Nulls are not permitted
     *
     * @param entries The entries that will be added to the claims map
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder claims(Map<String, ? extends JWTClaim> entries) {
      this.claims.clear();
      return putAllClaims(entries);
    }

    /**
     * Put all mappings from the specified map as entries to {@link JWTClaims#claims() claims} map.
     * Nulls are not permitted
     *
     * @param entries The entries that will be added to the claims map
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder putAllClaims(Map<String, ? extends JWTClaim> entries) {
      for (Map.Entry<String, ? extends JWTClaim> e : entries.entrySet()) {
        String k = e.getKey();
        JWTClaim v = e.getValue();
        this.claims.put(
            Objects.requireNonNull(k, "claims key"), Objects.requireNonNull(v, "claims value"));
      }
      return this;
    }

    /**
     * Initializes the value for the {@link JWTClaims#verifiedCount() verifiedCount} attribute.
     *
     * <p><em>If not set, this attribute will have a default value as returned by the initializer of
     * {@link JWTClaims#verifiedCount() verifiedCount}.</em>
     *
     * @param verifiedCount The value for verifiedCount
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder verifiedCount(int verifiedCount) {
      this.verifiedCount = verifiedCount;
      optBits |= OPT_BIT_VERIFIED_COUNT;
      return this;
    }

    /**
     * Builds a new {@link JWTClaims JWTClaims}.
     *
     * @return An immutable instance of JWTClaims
     * @throws java.lang.IllegalStateException if any required attributes are missing
     */
    public JWTClaims build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new JWTClaims(this);
    }

    private boolean verifiedCountIsSet() {
      return (optBits & OPT_BIT_VERIFIED_COUNT) != 0;
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_TOKEN) != 0) attributes.add("token");
      return "Cannot build JWTClaims, some of required attributes are not set " + attributes;
    }
  }

  private static <K, V> Map<K, V> createUnmodifiableMap(
      boolean checkNulls, boolean skipNulls, Map<? extends K, ? extends V> map) {
    switch (map.size()) {
      case 0:
        return Collections.emptyMap();
      case 1:
        {
          Map.Entry<? extends K, ? extends V> e = map.entrySet().iterator().next();
          K k = e.getKey();
          V v = e.getValue();
          if (checkNulls) {
            Objects.requireNonNull(k, "key");
            Objects.requireNonNull(v, "value");
          }
          if (skipNulls && (k == null || v == null)) {
            return Collections.emptyMap();
          }
          return Collections.singletonMap(k, v);
        }
      default:
        {
          Map<K, V> linkedMap = new LinkedHashMap<>(map.size());
          if (skipNulls || checkNulls) {
            for (Map.Entry<? extends K, ? extends V> e : map.entrySet()) {
              K k = e.getKey();
              V v = e.getValue();
              if (skipNulls) {
                if (k == null || v == null) continue;
              } else if (checkNulls) {
                Objects.requireNonNull(k, "key");
                Objects.requireNonNull(v, "value");
              }
              linkedMap.put(k, v);
            }
          } else {
            linkedMap.putAll(map);
          }
          return Collections.unmodifiableMap(linkedMap);
        }
    }
  }
}
