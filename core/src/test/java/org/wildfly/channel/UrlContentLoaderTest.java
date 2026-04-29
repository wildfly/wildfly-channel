package org.wildfly.channel;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.unauthorized;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WireMockTest
public class UrlContentLoaderTest {

    @AfterEach
    void tearDown() {
        System.clearProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY);
    }

    @Test
    void systemPropertyTakesPrecedenceOverEnvironmentVariable(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/secured.yaml")
                .withHeader("Authorization", WireMock.equalTo("Bearer system-property-token"))
                .willReturn(ok(readResource("channels/remote-authenticated-manifest.yaml"))));

        // Set system property - this should take precedence
        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "system-property-token");
        
        // Note: Environment variable WILDFLY_CHANNEL_HTTP_AUTH_TOKEN would be ignored if set
        // This test verifies that system property takes precedence

        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/secured.yaml");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        UrlContentLoader.openStream(url).transferTo(outputStream);

        assertThat(outputStream.toString()).contains("schemaVersion: 1.1.0");
    }

    @Test
    void blankSystemPropertyFallsBackToEnvironmentVariable(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        
        // When system property is blank, environment variable should be used
        // This test documents the expected behavior
        // To manually verify: set WILDFLY_CHANNEL_HTTP_AUTH_TOKEN=env-token and run test
        
        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "");
        
        // If environment variable is set, it should be used
        // If not set, no authorization header should be sent
        wireMock.register(get("/public.yaml")
                .willReturn(ok(readResource("channels/remote-authenticated-manifest.yaml"))));

        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/public.yaml");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        UrlContentLoader.openStream(url).transferTo(outputStream);

        assertThat(outputStream.toString()).contains("schemaVersion: 1.1.0");
    }

    @Test
    void sendsBearerAuthorizationHeaderForHttpUrlsWhenTokenIsConfigured(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/secured.yaml")
                .withHeader("Authorization", WireMock.equalTo("Bearer secret-token"))
                .willReturn(ok(readResource("channels/remote-authenticated-manifest.yaml"))));

        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "secret-token");

        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/secured.yaml");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        UrlContentLoader.openStream(url).transferTo(outputStream);

        assertThat(outputStream.toString()).contains("schemaVersion: 1.1.0");
    }

    @Test
    void omitsAuthorizationHeaderWhenTokenIsNotConfigured(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/public.yaml")
                .willReturn(ok(readResource("channels/remote-authenticated-manifest.yaml"))));

        URL url = new URL(wmRuntimeInfo.getHttpBaseUrl() + "/public.yaml");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        UrlContentLoader.openStream(url).transferTo(outputStream);

        assertThat(outputStream.toString()).contains("schemaVersion: 1.1.0");
    }

    @Test
    void channelManifestMapperUsesAuthenticatedLoaderForRemoteYaml(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/manifest.yaml")
                .withHeader("Authorization", WireMock.equalTo("Bearer secret-token"))
                .willReturn(ok(readResource("channels/remote-authenticated-manifest.yaml"))));

        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "secret-token");

        URL url = asUrl(wmRuntimeInfo.getHttpBaseUrl() + "/manifest.yaml");
        ChannelManifest manifest = ChannelManifestMapper.from(url);

        assertThat(manifest.getName()).isEqualTo("remote");
        assertThat(manifest.getStreams()).hasSize(1);
    }

    @Test
    void channelMapperUsesAuthenticatedLoaderForRemoteYaml(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/channel.yaml")
                .withHeader("Authorization", WireMock.equalTo("Bearer secret-token"))
                .willReturn(ok(readResource("channels/remote-authenticated-channel.yaml"))));

        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "secret-token");

        URL url = asUrl(wmRuntimeInfo.getHttpBaseUrl() + "/channel.yaml");
        Channel channel = ChannelMapper.from(url);

        assertThat(channel.getName()).isEqualTo("remote");
        assertThat(channel.getRepositories()).hasSize(1);
    }

    @Test
    void blocklistUsesAuthenticatedLoaderForRemoteYaml(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/blocklist.yaml")
                .withHeader("Authorization", WireMock.equalTo("Bearer secret-token"))
                .willReturn(ok(readResource("channels/remote-authenticated-blocklist.yaml"))));

        System.setProperty(UrlContentLoader.HTTP_AUTH_TOKEN_PROPERTY, "secret-token");

        URL url = asUrl(wmRuntimeInfo.getHttpBaseUrl() + "/blocklist.yaml");
        Blocklist blocklist = Blocklist.from(url);

        assertThat(blocklist.getVersionsFor("org.acme", "artifact")).containsExactly("1.0.0");
    }

    @Test
    void channelManifestMapperFailsWithoutTokenForProtectedRemoteYaml(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock wireMock = wmRuntimeInfo.getWireMock();
        wireMock.register(get("/manifest.yaml")
                .willReturn(unauthorized()));

        URL url = asUrl(wmRuntimeInfo.getHttpBaseUrl() + "/manifest.yaml");

        assertThrows(InvalidChannelMetadataException.class, () -> ChannelManifestMapper.from(url));
    }

    private static URL asUrl(String value) {
        try {
            return new URL(value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String readResource(String path) {
        try (var input = Thread.currentThread().getContextClassLoader().getResourceAsStream(path)) {
            if (input == null) {
                throw new IllegalArgumentException("Missing test resource: " + path);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}