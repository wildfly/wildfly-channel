package org.wildfly.channel;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

final class UrlContentLoader {

    static final String HTTP_AUTH_TOKEN_PROPERTY = "org.wildfly.channel.http.auth.token";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private UrlContentLoader() {
    }

    static InputStream openStream(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        String protocol = url.getProtocol();
        if ("http".equalsIgnoreCase(protocol) || "https".equalsIgnoreCase(protocol)) {
            String token = System.getProperty(HTTP_AUTH_TOKEN_PROPERTY);
            if (token != null && !token.isBlank()) {
                connection.setRequestProperty(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
            }
        }
        return connection.getInputStream();
    }
}
