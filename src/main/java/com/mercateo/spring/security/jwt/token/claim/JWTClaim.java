package com.mercateo.spring.security.jwt.token.claim;

import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.experimental.Accessors;

@AllArgsConstructor
@Builder(toBuilder = true, builderClassName = "JWTClaimBuilder")
@ToString
@EqualsAndHashCode
@Getter
@Accessors(fluent = true)
public class JWTClaim {

  private final String name;
  private final Object value;
  private final String issuer;
  private final boolean verified;
  private final Optional<JWTClaim> innerClaim;
  private final int depth;

  @SuppressWarnings({"unused", "FieldMayBeFinal"})
  public static class JWTClaimBuilder {

    private String issuer = "";
    private boolean verified = false;
    private Optional<JWTClaim> innerClaim = Optional.empty();
    private int depth = 0;
  }
}
