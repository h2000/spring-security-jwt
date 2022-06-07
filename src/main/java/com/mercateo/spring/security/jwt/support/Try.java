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
package com.mercateo.spring.security.jwt.support;

import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Function;

@SuppressWarnings("unused")
public interface Try<T> {

  static <T> Try<T> of(CheckedSupplier<? extends T> supplier) {
    Objects.requireNonNull(supplier, "supplier is null");
    try {
      return new Success<>(supplier.apply());
    } catch (Throwable t) {
      return new Failure<>(t);
    }
  }

  static <T> Try<T> success(T value) {
    return new Success<>(value);
  }

  static <T> Try<T> failure(Throwable value) {
    return new Failure<>(value);
  }

  boolean isFailure();

  boolean isSuccess();

  <U> Try<U> mapTry(CheckedFunction<? super T, ? extends U> mapper);

  <U> Try<U> map(Function<? super T, ? extends U> mapper);

  Try<T> onFailure(Consumer<? super Throwable> action);

  <X extends Throwable> T getOrElseThrow(Function<? super Throwable, X> exceptionProvider) throws X;

  Throwable getCause();

  final class Success<T> implements Try<T> {

    private final T value;

    public Success(T value) {
      this.value = value;
    }

    public T get() {
      return value;
    }

    @Override
    public boolean isFailure() {
      return false;
    }

    @Override
    public boolean isSuccess() {
      return true;
    }

    public <U> Try<U> mapTry(CheckedFunction<? super T, ? extends U> mapper) {
      Objects.requireNonNull(mapper, "mapper is null");
      try {
        return new Success<>(mapper.apply(get()));
      } catch (Throwable t) {
        return new Failure<>(t);
      }
    }

    public <U> Try<U> map(Function<? super T, ? extends U> mapper) {
      Objects.requireNonNull(mapper, "mapper is null");
      try {
        return new Success<>(mapper.apply(get()));
      } catch (Throwable t) {
        return new Failure<>(t);
      }
    }

    public Try<T> onFailure(Consumer<? super Throwable> action) {
      return this;
    }

    public <X extends Throwable> T getOrElseThrow(
        Function<? super Throwable, X> exceptionProvider) {
      Objects.requireNonNull(exceptionProvider, "exceptionProvider is null");
      return get();
    }

    @Override
    public Throwable getCause() {
      return null;
    }
  }

  final class Failure<T> implements Try<T> {

    private final Throwable value;

    public Failure(Throwable value) {
      this.value = value;
    }

    public Throwable getCause() {
      return value;
    }

    @Override
    public boolean isFailure() {
      return true;
    }

    @Override
    public boolean isSuccess() {
      return false;
    }

    @SuppressWarnings("unchecked")
    public <U> Try<U> mapTry(CheckedFunction<? super T, ? extends U> mapper) {
      Objects.requireNonNull(mapper, "mapper is null");
      return (Failure<U>) this;
    }

    @SuppressWarnings("unchecked")
    public <U> Try<U> map(Function<? super T, ? extends U> mapper) {
      Objects.requireNonNull(mapper, "mapper is null");
      return (Failure<U>) this;
    }

    public Try<T> onFailure(Consumer<? super Throwable> action) {
      Objects.requireNonNull(action, "action is null");
      if (isFailure()) {
        action.accept(getCause());
      }
      return this;
    }

    public <X extends Throwable> T getOrElseThrow(Function<? super Throwable, X> exceptionProvider)
        throws X {
      Objects.requireNonNull(exceptionProvider, "exceptionProvider is null");
      throw exceptionProvider.apply(getCause());
    }
  }
}
