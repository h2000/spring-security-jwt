package com.mercateo.spring.security.jwt.token.verifier;

import static org.assertj.core.api.Assertions.assertThat;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.mercateo.spring.security.jwt.support.CollectionUtils;
import com.mercateo.spring.security.jwt.support.Pair;
import com.mercateo.spring.security.jwt.token.exception.InvalidTokenException;
import com.mercateo.spring.security.jwt.token.verifier.JWTVerifier.ClockImpl;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Map;
import java.util.Optional;
import lombok.val;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class TokenVerifierTest {

  @Test
  public void verifyTokenForAlgoNoneIsAlwaysFalse() {
    // arrange
    final String tokenString =
        JWT //
            .create()
            .withClaim("Foo", "Bar")
            .sign(Algorithm.none());
    val token = JWT.decode(tokenString);
    val uut = new TokenVerifier(Optional.empty());

    // act
    val result = uut.verifyToken(token);

    // assert
    assertThat(result).isFalse();
  }

  @Test
  public void verifyTokenWithoutJwtVerifierIsAlwaysFalse() {
    // arrange
    final String tokenString =
        JWT //
            .create()
            .withClaim("Foo", "Bar")
            .sign(Algorithm.HMAC256("secret"));
    val token = JWT.decode(tokenString);
    val uut = new TokenVerifier(Optional.empty());

    // act
    val result = uut.verifyToken(token);

    // assert
    assertThat(result).isFalse();
  }

  @Test
  public void verifyTokenShouldWorkForCorrectToken()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    // arrange
    val keyProvider = createRsaKeyProvider();
    Map<String, Object> claims = CollectionUtils.mapOfTuples(Pair.of("Foo", "foo"));
    val clock = new ClockImpl();
    val jwtVerifier = new JWTVerifier(keyProvider, claims, clock);
    val uut = new TokenVerifier(Optional.of(jwtVerifier));

    val tokenString =
        JWT //
            .create()
            .withClaim("Foo", "foo")
            .sign(Algorithm.RSA256(keyProvider));
    val token = JWT.decode(tokenString);

    // act
    val result = uut.verifyToken(token);

    // assert
    assertThat(result).isTrue();
  }

  @Test(expected = InvalidTokenException.class)
  public void verifyTokenShouldBeFalseInCaseOfException()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
    // arrange
    val keyProvider = createRsaKeyProvider();
    Map<String, Object> claims = CollectionUtils.mapOfTuples(Pair.of("Foo", "foo"));
    val clock = new ClockImpl();
    val jwtVerifier = new JWTVerifier(keyProvider, claims, clock);
    val uut = new TokenVerifier(Optional.of(jwtVerifier));

    val tokenString =
        JWT //
            .create()
            .sign(Algorithm.RSA256(keyProvider));
    val token = JWT.decode(tokenString);

    // act
    val result = uut.verifyToken(token);

    // assert
    assertThat(result).isTrue();
  }

  static RSAKeyProvider createRsaKeyProvider()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    val keygen = KeyPairGenerator.getInstance("RSA");
    val spec = new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4);
    keygen.initialize(spec);
    val keypair = keygen.generateKeyPair();

    return new RSAKeyProvider() {
      @Override
      public RSAPrivateKey getPrivateKey() {
        return (RSAPrivateKey) keypair.getPrivate();
      }

      @Override
      public RSAPublicKey getPublicKeyById(String keyId) {
        return (RSAPublicKey) keypair.getPublic();
      }

      @Override
      public String getPrivateKeyId() {
        return "id";
      }
    };
  }
}
