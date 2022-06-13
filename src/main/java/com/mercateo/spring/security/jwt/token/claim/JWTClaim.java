package com.mercateo.spring.security.jwt.token.claim;

import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.Accessors;

@AllArgsConstructor
@Builder(toBuilder = true, builderClassName = "JWTClaimBuilder")
@ToString
@EqualsAndHashCode
@Getter
@Accessors(fluent = true)
public class JWTClaim {
  @NonNull private final String name;
  private final Object value;
  @NonNull private final String issuer;
  private final boolean verified;
  private final Optional<JWTClaim> innerClaim;
  /** Depth starting from zero, how deep was the claim inside a jwt hierarchy. */
  private final int depth;

  @SuppressWarnings({"unused", "FieldMayBeFinal"})
  public static class JWTClaimBuilder {

    private String issuer = "";
    private boolean verified = false;
    private Optional<JWTClaim> innerClaim = Optional.empty();
    private int depth = 0;
  }
}
