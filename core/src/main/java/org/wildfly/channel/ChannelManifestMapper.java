/*
 * Copyright 2022 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wildfly.channel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.dataformat.yaml.YAMLGenerator;
import com.fasterxml.jackson.dataformat.yaml.YAMLParser;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import static com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES;
import static com.fasterxml.jackson.databind.SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS;
import static java.util.Collections.singletonList;
import static java.util.Objects.requireNonNull;

/**
 * Mapper class to transform YAML content (from URL or String) to Channel objects (and vice versa).
 *
 * YAML input is validated against a schema.
 */
public class ChannelManifestMapper {

    public static final String SCHEMA_VERSION_1_0_0 = "1.0.0";
    public static final String SCHEMA_VERSION_1_1_0 = "1.1.0";
    public static final String CURRENT_SCHEMA_VERSION = SCHEMA_VERSION_1_1_0;

    private static final String SCHEMA_1_0_0_FILE = "org/wildfly/manifest/v1.0.0/schema.json";
    private static final String SCHEMA_1_1_0_FILE = "org/wildfly/manifest/v1.1.0/schema.json";
    private static final YAMLFactory YAML_FACTORY = new YAMLFactory()
            .configure(YAMLGenerator.Feature.INDENT_ARRAYS_WITH_INDICATOR, true);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(YAML_FACTORY)
            .configure(FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(ORDER_MAP_ENTRIES_BY_KEYS, true);
    private static final JsonSchemaFactory SCHEMA_FACTORY = JsonSchemaFactory.builder(JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V201909)).jsonMapper(OBJECT_MAPPER).build();
    private static final Map<String, JsonSchema> SCHEMAS = new HashMap<>();

    static {
        SCHEMAS.put(SCHEMA_VERSION_1_0_0, SCHEMA_FACTORY.getSchema(ChannelManifestMapper.class.getClassLoader().getResourceAsStream(SCHEMA_1_0_0_FILE)));
        SCHEMAS.put(SCHEMA_VERSION_1_1_0, SCHEMA_FACTORY.getSchema(ChannelManifestMapper.class.getClassLoader().getResourceAsStream(SCHEMA_1_1_0_FILE)));
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

    public static String toYaml(ChannelManifest channelManifest) throws IOException {
        Objects.requireNonNull(channelManifest);
        StringWriter w = new StringWriter();
        OBJECT_MAPPER.writeValue(w, channelManifest);
        return w.toString();
    }

    public static ChannelManifest from(URL manifestURL) throws InvalidChannelMetadataException {
        requireNonNull(manifestURL);

        try {
            // QoL improvement
            if (manifestURL.toString().endsWith("/")) {
                manifestURL = manifestURL.toURI().resolve("channel.yaml").toURL();
            }

            List<String> messages = validate(manifestURL);
            if (!messages.isEmpty()) {
                throw new InvalidChannelMetadataException("Invalid manifest", messages);
            }
            try (InputStream input = UrlContentLoader.openStream(manifestURL)) {
                return OBJECT_MAPPER.readValue(input, ChannelManifest.class);
            }
        } catch (FileNotFoundException e) {
            final InvalidChannelMetadataException ice = new InvalidChannelMetadataException("Unable to resolve manifest.", List.of(manifestURL.toString()));
            ice.initCause(e);
            throw ice;
        } catch (IOException | URISyntaxException e) {
            throw wrapException(e);
        }
    }

    public static ChannelManifest fromString(String yamlContent) throws InvalidChannelMetadataException {
        requireNonNull(yamlContent);

        try {
            List<String> messages = validateString(yamlContent);
            if (!messages.isEmpty()) {
                throw new InvalidChannelMetadataException("Invalid manifest", messages);
            }

            YAMLParser parser = YAML_FACTORY.createParser(yamlContent);
            ChannelManifest channelManifest = OBJECT_MAPPER.readValue(parser, ChannelManifest.class);
            return channelManifest;
        } catch (IOException e) {
            throw wrapException(e);
        }
    }

    private static List<String> validate(URL url) throws IOException {
        try (InputStream input = UrlContentLoader.openStream(url)) {
            JsonNode node = OBJECT_MAPPER.readTree(input);
            JsonSchema schema = getSchema(node);
            Set<ValidationMessage> validationMessages = schema.validate(node);
            return validationMessages.stream().map(ValidationMessage::getMessage).collect(Collectors.toList());
        }
    }

    private static List<String> validateString(String yamlContent) throws IOException {
        JsonNode node = OBJECT_MAPPER.readTree(yamlContent);
        JsonSchema schema = getSchema(node);
        Set<ValidationMessage> validationMessages = schema.validate(node);
        return validationMessages.stream().map(ValidationMessage::getMessage).collect(Collectors.toList());
    }

    private static InvalidChannelMetadataException wrapException(Exception e) {
        InvalidChannelMetadataException ice = new InvalidChannelMetadataException("Invalid Manifest", singletonList(e.getLocalizedMessage()));
        ice.initCause(e);
        return ice;
    }
}
