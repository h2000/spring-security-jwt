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
package com.mercateo.spring.security.jwt.token.verifier;

import com.auth0.jwk.Jwk;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.mercateo.spring.security.jwt.token.config.JWTConfig;
import com.mercateo.spring.security.jwt.token.keyset.JWTKeyset;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifier.BaseVerification;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@AllArgsConstructor
@Slf4j
public class JWTVerifierFactory {
  private final JWTKeyset jwtKeyset;

  private final JWTConfig jwtConfig;

  private static IllegalStateException wrapInIllegateStateException(Throwable cause) {
    return new IllegalStateException(cause);
  }

  public JWTVerifier create() {
    final RSAKeyProvider rsaKeyProvider =
        new RSAKeyProvider() {
          @Override
          public RSAPublicKey getPublicKeyById(String keyId) {
            return jwtKeyset
                .getKeysetForId(keyId)
                .mapTry(Jwk::getPublicKey)
                .map(Key::getEncoded)
                .mapTry(JWTVerifierFactory::createKey)
                .onFailure(e -> log.error("Error getting public key for id " + keyId, e))
                .getOrElseThrow(JWTVerifierFactory::wrapInIllegateStateException);
          }

          @Override
          public RSAPrivateKey getPrivateKey() {
            return null;
          }

          @Override
          public String getPrivateKeyId() {
            return null;
          }
        };

    final BaseVerification verification = JWTVerifier.init(rsaKeyProvider);

    final int tokenLeeway = jwtConfig.getTokenLeeway();
    verification.acceptLeeway(tokenLeeway);

    Set<String> tokenAudiences = jwtConfig.getTokenAudiences();
    if (!tokenAudiences.isEmpty()) {
      verification.withAudience(tokenAudiences.stream().toArray(String[]::new));
    }

    return verification.build();
  }

  private static RSAPublicKey createKey(byte[] bytes)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    return (RSAPublicKey)
        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
  }
}
