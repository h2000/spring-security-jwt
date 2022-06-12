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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public enum CollectionUtils {
  ;

  public static <T1, T2> Map<T1, T2> mapOfTuples(Iterable<Pair<T1, T2>> entries) {
    Map<T1, T2> map = new LinkedHashMap<>();
    entries.forEach(e -> map.put(e.first(), e.second()));
    return map;
  }

  @SafeVarargs
  public static <T1, T2> Map<T1, T2> mapOfTuples(Pair<T1, T2>... entries) {
    Map<T1, T2> map = new LinkedHashMap<>();
    Arrays.stream(entries).forEach(e -> map.put(e.first(), e.second()));
    return map;
  }

  public static <T> List<T> reverseList(List<T> list) {
    List<T> reverse = new ArrayList<>(list);
    Collections.reverse(reverse);
    return reverse;
  }
}
