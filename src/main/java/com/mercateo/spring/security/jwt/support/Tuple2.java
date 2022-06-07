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

import java.util.AbstractMap;
import java.util.Comparator;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;

/**
 * A tuple of two elements which can be seen as cartesian product of two components.
 *
 * @param <T1> type of the 1st element
 * @param <T2> type of the 2nd element
 */
@SuppressWarnings("unused")
public final class Tuple2<T1, T2> {

  /** The 1st element of this tuple. */
  public final T1 _1;

  /** The 2nd element of this tuple. */
  public final T2 _2;

  /**
   * Constructs a tuple of two elements.
   *
   * @param t1 the 1st element
   * @param t2 the 2nd element
   */
  public Tuple2(T1 t1, T2 t2) {
    this._1 = t1;
    this._2 = t2;
  }

  public static <T1, T2> Comparator<Tuple2<T1, T2>> comparator(
      Comparator<? super T1> t1Comp, Comparator<? super T2> t2Comp) {
    return (Comparator<Tuple2<T1, T2>>)
        (t1, t2) -> {
          final int check1 = t1Comp.compare(t1._1, t2._1);
          if (check1 != 0) {
            return check1;
          }

          return t2Comp.compare(t1._2, t2._2);

          // all components are equal
        };
  }

  /**
   * Getter of the 1st element of this tuple.
   *
   * @return the 1st element of this Tuple.
   */
  public T1 _1() {
    return _1;
  }

  /**
   * Getter of the 2nd element of this tuple.
   *
   * @return the 2nd element of this Tuple.
   */
  public T2 _2() {
    return _2;
  }

  /**
   * Converts the tuple to java.util.Map.Entry {@code Tuple}.
   *
   * @return A java.util.Map.Entry where the first element is the key and the second element is the
   *     value.
   */
  public Map.Entry<T1, T2> toEntry() {
    return new AbstractMap.SimpleEntry<>(_1, _2);
  }

  /**
   * Maps the components of this tuple using a mapper function.
   *
   * @param mapper the mapper function
   * @param <U1> new type of the 1st component
   * @param <U2> new type of the 2nd component
   * @return A new Tuple of same arity.
   * @throws NullPointerException if {@code mapper} is null
   */
  public <U1, U2> Tuple2<U1, U2> map(BiFunction<? super T1, ? super T2, Tuple2<U1, U2>> mapper) {
    Objects.requireNonNull(mapper, "mapper is null");
    return mapper.apply(_1, _2);
  }

  /**
   * Maps the components of this tuple using a mapper function for each component.
   *
   * @param f1 the mapper function of the 1st component
   * @param f2 the mapper function of the 2nd component
   * @param <U1> new type of the 1st component
   * @param <U2> new type of the 2nd component
   * @return A new Tuple of same arity.
   * @throws NullPointerException if one of the arguments is null
   */
  public <U1, U2> Tuple2<U1, U2> map(
      Function<? super T1, ? extends U1> f1, Function<? super T2, ? extends U2> f2) {
    Objects.requireNonNull(f1, "f1 is null");
    Objects.requireNonNull(f2, "f2 is null");
    return Tuple2.of(f1.apply(_1), f2.apply(_2));
  }

  /**
   * Transforms this tuple to an object of type U.
   *
   * @param f Transformation which creates a new object of type U based on this tuple's contents.
   * @param <U> type of the transformation result
   * @return An object of type U
   * @throws NullPointerException if {@code f} is null
   */
  public <U> U apply(BiFunction<? super T1, ? super T2, ? extends U> f) {
    Objects.requireNonNull(f, "f is null");
    return f.apply(_1, _2);
  }

  // -- Object

  @Override
  public boolean equals(Object o) {
    if (o == this) {
      return true;
    } else if (!(o instanceof Tuple2)) {
      return false;
    } else {
      final Tuple2<?, ?> that = (Tuple2<?, ?>) o;
      return Objects.equals(this._1, that._1) && Objects.equals(this._2, that._2);
    }
  }

  @Override
  public int hashCode() {
    return Objects.hash(_1, _2);
  }

  @Override
  public String toString() {
    return "(" + _1 + ", " + _2 + ")";
  }

  public static <T1, T2> Tuple2<T1, T2> of(T1 t1, T2 t2) {
    return new Tuple2<>(t1, t2);
  }
}
