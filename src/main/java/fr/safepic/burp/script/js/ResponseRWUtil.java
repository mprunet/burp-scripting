package fr.safepic.burp.script.js;

import burp.*;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.NativeJSON;
import org.mozilla.javascript.json.JsonParser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class ResponseRWUtil extends AbstractRequestResponseUtil {
    protected IResponseInfo response;
    protected byte[] responseBytes;
    protected List<String> initialResponseHeader;
    protected List<String> responseHeaders;
    protected byte[] responseBody;
    private boolean responseBodyModified = false;


    public ResponseRWUtil(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, JavascriptContext context) {
        super(callbacks, requestResponse, context);
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


    public List<String> getAllResponseHeaders() {
        return responseHeaders(false);
    }

    public String getResponseHeader(String header) {
        List<String> responseHeaders = responseHeaders(false);
        return filterHeaderGetValue(responseHeaders, header).findFirst().orElse(null);
    }

    public List<String> getResponseHeaders(String header) {
        List<String> responseHeaders = responseHeaders(false);
        return filterHeaderGetValue(responseHeaders, header).collect(Collectors.toList());
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
                logCallback.verbose("Response Header " + cur + " removed");
                headers.remove(i);
                i--;
            }
        }
    }

    public void setStatusMessage(String s) {
        List<String> headers = responseHeaders(true);
        String oldStatus = headers.get(0);
        headers.set(0, "HTTP/1.1 "+s);
        logCallback.verbose("Status Header " + oldStatus + " replaced by" +  headers.get(0));
    }

    public void setResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        boolean set = false;
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                headers.set(i, header+": "+value);
                logCallback.verbose("Response Header " + cur + " replaced by" + header+": "+value);
                set = true;
                break;
            }
        }
        if (!set) {
            addResponseHeader(header, value);
        }
    }

    public void updateResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        String cur;
        for (int i = 1; i<headers.size(); i++) {
            cur = headers.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                headers.set(i, header+": "+value);
                logCallback.verbose("Response Header " + cur + " replaced by" + header+": "+value);
            }
        }
    }

    public void addResponseHeader(String header, String value) {
        List<String> headers = responseHeaders(true);
        headers.add(header+": "+value);
        logCallback.verbose("Response Header " + header+": "+value + " added");
    }

    public byte[] getResponseBody() {
        if (responseBody == null) {
            byte[] responseBytes = responseBytes();
            IResponseInfo ri = response();
            responseBody = new byte[responseBytes.length - ri.getBodyOffset()];
            System.arraycopy(responseBytes, ri.getBodyOffset(), responseBody, 0, responseBody.length);
        }
        return responseBody;
    }

    public String getResponseBodyAsString(String encoding) {
        return decodeBody(getResponseBody(), encoding, ()->getResponseHeader("Content-Type"));
    }

    public Object getResponseBodyAsJson(String encoding) throws JsonParser.ParseException {
        String value = getResponseBodyAsString(encoding);
        JsonParser jsonParser = new JsonParser(context.getCx(), context.getScope());
        return jsonParser.parseValue(value);
    }

    public void setResponseBody(byte[] responseBody) {
        this.responseBody = responseBody;
        responseBodyModified = true;
    }

    public void setResponseBodyAsString(String body) {
        setResponseBody(body.getBytes());
    }

    public void setResponseBodyAsJson(Object json) {
        Object jsonStringify = NativeJSON.stringify(context.getCx(), context.getScope(), json, null, null);
        setResponseBodyAsString((String)Context.jsToJava(jsonStringify,String.class));
    }

    public void setResponseAsFile(String fileName) throws IOException {
        commit();
        byte[] content = Files.readAllBytes(Paths.get(fileName));
        requestResponse().setResponse(content);
    }


    private boolean isModified() {
        return responseBodyModified || (responseHeaders != null && !responseHeaders.equals(initialResponseHeader));
    }


    public void commit() {
        super.commit();
        if (isModified()) {
            requestResponse().setResponse(helpers().buildHttpMessage(responseHeaders(false), getResponseBody()));
            this.response = null;
            this.responseBytes = null;
            this.initialResponseHeader = null;
            this.responseHeaders = null;
            this.responseBody = null;
            this.responseBodyModified = false;
            logCallback.verbose("Response updated");
        }
    }

}
