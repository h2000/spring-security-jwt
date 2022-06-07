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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.springframework.security.core.GrantedAuthority;

/**
 * Immutable implementation of {@link JWTAuthority}.
 *
 * <p>Use the builder to create immutable instances: {@code JWTAuthority.builder()}.
 */
@SuppressWarnings({"all"})
public final class JWTAuthority implements GrantedAuthority {
  private final String authority;

  private JWTAuthority(String authority) {
    this.authority = authority;
  }

  /** @return The value of the {@code authority} attribute */
  @Override
  public String getAuthority() {
    return authority;
  }

  /**
   * Copy the current immutable object by setting a value for the {@link JWTAuthority#getAuthority()
   * authority} attribute. An equals check used to prevent copying of the same value by returning
   * {@code this}.
   *
   * @param value A new value for authority
   * @return A modified copy of the {@code this} object
   */
  public final JWTAuthority withAuthority(String value) {
    String newValue = Objects.requireNonNull(value, "authority");
    if (this.authority.equals(newValue)) return this;
    return new JWTAuthority(newValue);
  }

  /**
   * This instance is equal to all instances of {@code JWTAuthority} that have equal attribute
   * values.
   *
   * @return {@code true} if {@code this} is equal to {@code another} instance
   */
  @Override
  public boolean equals(Object another) {
    if (this == another) return true;
    return another instanceof JWTAuthority && equalTo((JWTAuthority) another);
  }

  private boolean equalTo(JWTAuthority another) {
    return authority.equals(another.authority);
  }

  /**
   * Computes a hash code from attributes: {@code authority}.
   *
   * @return hashCode value
   */
  @Override
  public int hashCode() {
    int h = 5381;
    h += (h << 5) + authority.hashCode();
    return h;
  }

  /**
   * Prints the immutable value {@code JWTAuthority} with attribute values.
   *
   * @return A string representation of the value
   */
  @Override
  public String toString() {
    return "JWTAuthority{" + "authority=" + authority + "}";
  }

  /**
   * Creates an immutable copy of a {@link JWTAuthority} value. Uses accessors to get values to
   * initialize the new immutable instance. If an instance is already immutable, it is returned as
   * is.
   *
   * @param instance The instance to copy
   * @return A copied immutable JWTAuthority instance
   */
  public static JWTAuthority copyOf(JWTAuthority instance) {
    if (instance instanceof JWTAuthority) {
      return (JWTAuthority) instance;
    }
    return JWTAuthority.builder().from(instance).build();
  }

  /**
   * Creates a builder for {@link JWTAuthority JWTAuthority}.
   *
   * <pre>
   * JWTAuthority.builder().authority(String) // required {@link JWTAuthority#getAuthority() authority}
   *         .build();
   * </pre>
   *
   * @return A new JWTAuthority builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builds instances of type {@link JWTAuthority JWTAuthority}. Initialize attributes and then
   * invoke the {@link #build()} method to create an immutable instance.
   *
   * <p><em>{@code Builder} is not thread-safe and generally should not be stored in a field or
   * collection, but instead used immediately to create instances.</em>
   */
  public static final class Builder {
    private static final long INIT_BIT_AUTHORITY = 0x1L;
    private long initBits = 0x1L;

    private String authority;

    private Builder() {}

    /**
     * Fill a builder with attribute values from the provided {@code
     * org.springframework.security.core.GrantedAuthority} instance.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(GrantedAuthority instance) {
      Objects.requireNonNull(instance, "instance");
      from((Object) instance);
      return this;
    }

    /**
     * Fill a builder with attribute values from the provided {@code
     * com.mercateo.spring.security.jwt.security._JWTAuthority} instance.
     *
     * @param instance The instance from which to copy values
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder from(JWTAuthority instance) {
      Objects.requireNonNull(instance, "instance");
      from((Object) instance);
      return this;
    }

    private void from(Object object) {
      if (object instanceof GrantedAuthority) {
        GrantedAuthority instance = (GrantedAuthority) object;
        authority(instance.getAuthority());
      }
    }

    /**
     * Initializes the value for the {@link JWTAuthority#getAuthority() authority} attribute.
     *
     * @param authority The value for authority
     * @return {@code this} builder for use in a chained invocation
     */
    public final Builder authority(String authority) {
      this.authority = Objects.requireNonNull(authority, "authority");
      initBits &= ~INIT_BIT_AUTHORITY;
      return this;
    }

    /**
     * Builds a new {@link JWTAuthority JWTAuthority}.
     *
     * @return An immutable instance of JWTAuthority
     * @throws IllegalStateException if any required attributes are missing
     */
    public JWTAuthority build() {
      if (initBits != 0) {
        throw new IllegalStateException(formatRequiredAttributesMessage());
      }
      return new JWTAuthority(authority);
    }

    private String formatRequiredAttributesMessage() {
      List<String> attributes = new ArrayList<>();
      if ((initBits & INIT_BIT_AUTHORITY) != 0) attributes.add("authority");
      return "Cannot build JWTAuthority, some of required attributes are not set " + attributes;
    }
  }
}
