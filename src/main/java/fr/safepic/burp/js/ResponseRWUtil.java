package fr.safepic.burp.js;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import fr.safepic.burp.AbstractMessageModifier;
import fr.safepic.burp.ui.ScriptPanel;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ResponseRWUtil extends AbstractRequestResponseUtil {
    protected IResponseInfo response;
    protected byte[] responseBytes;
    protected List<String> initialResponseHeader;
    protected List<String> responseHeaders;


    public ResponseRWUtil(ScriptPanel panel, AbstractMessageModifier modifier, IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        super(panel, modifier, helpers, requestResponse);
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
        return responseHeaders.stream().filter(h->header.equalsIgnoreCase(h)).findFirst().orElse(null);
    }

    public List<String> responseHeaders(String header) {
        List<String> responseHeaders = responseHeaders(false);
        return responseHeaders.stream().filter(h->header.equalsIgnoreCase(h)).collect(Collectors.toList());
    }

    public boolean hasResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(false);
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                return value == null || value.equals(cur.substring(sep+1).trim());
            }
        }
        return false;
    }

    public void removeResponseHeader(String header) {
        List<String> headers = responseHeaders(true);
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                debug("Response Header " + cur + " removed");
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
                debug("Response Header " + cur + " replaced by" + header+": "+value);
            }
        }
    }

    public void addResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        headers.add(header+": "+value);
        debug("Response Header " + header+": "+value + " added");
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
            debug("Response updated");
        }
    }

}
