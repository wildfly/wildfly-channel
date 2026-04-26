/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

public class Blocklist {

   public static final String SCHEMA_VERSION_1_0_0 = "1.0.0";
   private static final String SCHEMA_1_0_0_FILE = "org/wildfly/blocklist/v1.0.0/schema.json";
   private static final YAMLFactory YAML_FACTORY = new YAMLFactory()
      .configure(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR, true);
   private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(YAML_FACTORY)
      .configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
      .configure(ORDER_MAP_ENTRIES_BY_KEYS, true);
   private static final JsonSchemaFactory SCHEMA_FACTORY = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V201909)).jsonMapper(OBJECT_MAPPER).build();

   private static final Map<String, JsonSchema> SCHEMAS = new HashMap<>();

   static {
      SCHEMAS.put(SCHEMA_VERSION_1_0_0, SCHEMA_FACTORY.getSchema(ChannelMapper.class.getClassLoader().getResourceAsStream(SCHEMA_1_0_0_FILE)));
   }

   private final String schemaVersion;

   private Set<BlocklistEntry> entries;

   @JsonCreator
   public Blocklist(@JsonProperty(value = "schemaVersion", required = true) String schemaVersion,
                    @JsonProperty(value = "blocks") Set<BlocklistEntry> entries) {
      this.schemaVersion = schemaVersion;
      this.entries = entries;
   }

   public static Blocklist from(URL blocklistUrl) {
      requireNonNull(blocklistUrl);

      try {
         // QoL improvement
         if (blocklistUrl.toString().endsWith("/")) {
            blocklistUrl = blocklistUrl.toURI().resolve("blocklist.yaml").toURL();
         }

         List<String> messages = validate(blocklistUrl);
         if (!messages.isEmpty()) {
            throw new InvalidChannelMetadataException("Invalid blocklist", messages);
         }
         try (InputStream input = UrlContentLoader.openStream(blocklistUrl)) {
            return OBJECT_MAPPER.readValue(input, Blocklist.class);
         }
      } catch (IOException | URISyntaxException e) {
         throw wrapException(e);
      }
   }

   private static InvalidChannelMetadataException wrapException(Exception e) {
      InvalidChannelMetadataException ice = new InvalidChannelMetadataException("Invalid Channel", singletonList(e.getLocalizedMessage()));
      ice.initCause(e);
      return ice;
   }

   public Set<String> getVersionsFor(String groupId, String artifactId) {
      Objects.requireNonNull(groupId);
      Objects.requireNonNull(artifactId);

      if (entries == null) {
         return Collections.emptySet();
      }
      for (BlocklistEntry entry : entries) {
         if (entry.getGroupId().equals(groupId) && entry.getArtifactId().equals(artifactId)) {
            return entry.getVersions();
         }
      }
      for (BlocklistEntry entry : entries) {
         if (entry.getGroupId().equals(groupId) && entry.getArtifactId().equals("*")) {
            return entry.getVersions();
         }
      }
      return Collections.emptySet();
   }

   private static List<String> validate(URL url) throws IOException {
      try (InputStream input = UrlContentLoader.openStream(url)) {
         JsonNode node = OBJECT_MAPPER.readTree(input);
         JsonSchema schema = getSchema(node);
         schema.initializeValidators();
         Set<ValidationMessage> validationMessages = schema.validate(node);
         return validationMessages.stream().map(ValidationMessage::getMessage).collect(Collectors.toList());
      }
   }

   private static JsonSchema getSchema(JsonNode node) {
      JsonNode schemaVersion = node.path("schemaVersion");
      String version = schemaVersion.asText();
      if (version == null || version.isEmpty()) {
         throw new InvalidChannelMetadataException("Invalid Manifest", List.of("The manifest does not specify a schemaVersion."));
      }
      JsonSchema schema = SCHEMAS.get(version);
      if (schema == null) {
         throw new InvalidChannelMetadataException("Invalid Manifest", List.of("Unknown schema version " + schemaVersion));
      }
      return schema;
   }

   @Override
   public String toString() {
      return "Blocklist{" +
              "schemaVersion='" + schemaVersion + '\'' +
              ", entries=" + entries +
              '}';
   }
}
