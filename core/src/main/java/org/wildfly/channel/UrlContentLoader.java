package org.wildfly.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

public final class UrlContentLoader {

    static final String HTTP_AUTH_TOKEN_PROPERTY = "org.wildfly.channel.http.auth.token";
    static final String HTTP_AUTH_TOKEN_ENV_VAR = "WILDFLY_CHANNEL_HTTP_AUTH_TOKEN";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private UrlContentLoader() {
    }

    /**
     * Retrieves the authentication token from system property or environment variable.
     * System property takes precedence over environment variable.
     *
     * @return the authentication token, or null if not configured
     */
    private static String getAuthToken() {
        // First try system property
        String token = System.getProperty(HTTP_AUTH_TOKEN_PROPERTY);
        
        // Fall back to environment variable if system property is not set or blank
        if (token == null || token.isBlank()) {
            token = System.getenv(HTTP_AUTH_TOKEN_ENV_VAR);
        }
        
        return token;
    }

    public static InputStream openStream(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        String protocol = url.getProtocol();
        if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol)) {
            String token = getAuthToken();
            if (token != null && !token.isBlank()) {
                connection.setRequestProperty(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
            }
        }
        return connection.getInputStream();
    }
}
