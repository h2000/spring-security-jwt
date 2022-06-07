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
package com.mercateo.spring.security.jwt.token.extractor;

import com.auth0.jwt.interfaces.Claim;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.DoubleNode;
import com.fasterxml.jackson.databind.node.IntNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.mercateo.spring.security.jwt.support.CollectionUtils;
import com.mercateo.spring.security.jwt.support.Tuple2;
import java.lang.reflect.Field;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

class ClaimExtractor {

  private final Map<Class<?>, Function<Object, Object>> accessors =
      CollectionUtils.mapOfTuples( //
          Tuple2.of(TextNode.class, (node) -> ((TextNode) node).asText()), //
          Tuple2.of(IntNode.class, (node) -> ((IntNode) node).asInt()), //
          Tuple2.of(DoubleNode.class, (node) -> ((DoubleNode) node).asDouble()), //
          Tuple2.of(BooleanNode.class, (node) -> ((BooleanNode) node).asBoolean()), //
          Tuple2.of(ArrayNode.class, (node) -> extractArray((ArrayNode) node)), //
          Tuple2.of(ObjectNode.class, (node) -> extractObject((ObjectNode) node)));

  Object extract(Claim claim) {
    final Class<? extends Claim> claimClass = claim.getClass();
    if (claimClass.getSimpleName().equals("JsonNodeClaim")) {
      try {
        final Field data = claimClass.getDeclaredField("data");
        data.setAccessible(true);
        return extractNode(data.get(claim));
      } catch (IllegalAccessException | NoSuchFieldException e) {
        return null;
      }
    }
    return null;
  }

  private Object extractNode(Object rawClaim) {
    Function<Object, Object> accessorOption = accessors.get(rawClaim.getClass());
    if (accessorOption == null) {
      return null;
    }
    return accessorOption.apply(rawClaim);
  }

  private Object extractArray(ArrayNode node) {
    return asStream(node.elements()).map(this::extractNode).toArray();
  }

  private Object extractObject(ObjectNode node) {
    final Map<String, List<Entry<String, JsonNode>>> groupedByKey =
        asStream(node.fields()).collect(Collectors.groupingBy(Entry::getKey));

    return CollectionUtils.mapOfTuples(
        groupedByKey.entrySet().stream()
            .map(
                e -> {
                  final Entry<String, JsonNode> head = e.getValue().get(0);
                  final Object jsonNode = extractNode(head.getValue());
                  return Tuple2.of(e.getKey(), jsonNode);
                })
            .collect(Collectors.toList()));
  }

  public static <T> Stream<T> asStream(Iterator<T> sourceIterator) {
    final Iterable<T> iterable = () -> sourceIterator;
    return StreamSupport.stream(iterable.spliterator(), false);
  }
}
