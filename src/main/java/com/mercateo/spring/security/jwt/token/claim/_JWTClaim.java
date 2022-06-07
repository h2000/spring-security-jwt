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

import com.mercateo.immutables.ValueStyle;
import java.util.Optional;
import org.immutables.value.Value;

@Value.Immutable
@ValueStyle
public interface _JWTClaim {
  String name();

  Object value();

  @Value.Default
  default String issuer() {
    return "";
  }

  @Value.Default
  default boolean verified() {
    return false;
  }

  Optional<JWTClaim> innerClaim();

  @Value.Default
  default int depth() {
    return 0;
  }
}
