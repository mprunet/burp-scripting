package fr.safepic.burp.script.js;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import fr.safepic.burp.script.LogCallback;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ResponseRWUtil extends AbstractRequestResponseUtil {
    protected IResponseInfo response;
    protected byte[] responseBytes;
    protected List<String> initialResponseHeader;
    protected List<String> responseHeaders;


    public ResponseRWUtil(LogCallback logCallback, IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        super(logCallback, helpers, requestResponse);
    }

    public byte[] responseBytes() {
        if (responseBytes == null) {
            responseBytes = requestResponse().getResponse();
        }
        return responseBytes;
    }

    public IResponseInfo response() {
        if (response == null) {
            response = helpers().analyzeResponse(responseBytes());
        }
        return response;
    }
    public List<String> initialResponseHeader() {
        if (initialResponseHeader == null) {
            initialResponseHeader = Collections.unmodifiableList(response().getHeaders());
        }
        return initialResponseHeader;
    }

    protected List<String> responseHeaders(boolean init) {
        List<String> responseHeaders = this.responseHeaders;
        if (responseHeaders == null) {
            if (init) {
                responseHeaders = new ArrayList<>(initialResponseHeader());
                this.responseHeaders = responseHeaders;
            } else {
                responseHeaders = initialResponseHeader();
            }

        }
        return responseHeaders;
    }


    public List<String> responseHeaders() {
        return responseHeaders(true);
    }

    public String responseHeader(String header) {
        List<String> responseHeaders = responseHeaders(false);
        return responseHeaders.stream().filter(header::equalsIgnoreCase).findFirst().orElse(null);
    }

    public List<String> responseHeaders(String header) {
        List<String> responseHeaders = responseHeaders(false);
        return responseHeaders.stream().filter(header::equalsIgnoreCase).collect(Collectors.toList());
    }

    public boolean hasResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(false);
        return hasHeaderWithValue(header, value, headers);
    }

    public void removeResponseHeader(String header) {
        List<String> headers = responseHeaders(true);
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                logCallback.trace("Response Header " + cur + " removed");
                headers.remove(i);
                i--;
            }
        }
    }

    public void setResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                headers.set(i, header+": "+value);
                logCallback.trace("Response Header " + cur + " replaced by" + header+": "+value);
            }
        }
    }

    public void addResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        headers.add(header+": "+value);
        logCallback.trace("Response Header " + header+": "+value + " added");
    }

    private boolean isModified() {
        return responseHeaders != null && !responseHeaders.equals(initialResponseHeader);
    }

    public void commit() {
        if (isModified()) {
            IResponseInfo ri = response();
            byte[] body = new byte[responseBytes.length - ri.getBodyOffset()];
            System.arraycopy(responseBytes, ri.getBodyOffset(), body, 0, body.length);
            requestResponse().setRequest(helpers().buildHttpMessage(responseHeaders, body));
            this.response = null;
            this.responseBytes = null;
            this.initialResponseHeader = null;
            this.responseHeaders = null;
            logCallback.trace("Response updated");
        }
    }

}
