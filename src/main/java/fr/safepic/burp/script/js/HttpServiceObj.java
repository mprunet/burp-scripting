package fr.safepic.burp.script.js;

import burp.IHttpService;

public class HttpServiceObj implements IHttpService {
    private final String host;
    private final int port;
    private final boolean https;

    public HttpServiceObj(boolean https, String host, int port) {
        this.host = host;
        this.port = port;
        this.https = https;
    }

    @Override
    public String getHost() {
        return host;
    }

    @Override
    public int getPort() {
        return port;
    }

    @Override
    public String getProtocol() {
        return https ? "https" : "http";
    }
}
