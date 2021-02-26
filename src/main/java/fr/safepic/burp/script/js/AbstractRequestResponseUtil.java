package fr.safepic.burp.script.js;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import fr.safepic.burp.script.LogCallback;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public abstract class AbstractRequestResponseUtil {
    protected final LogCallback logCallback;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse requestResponse;
    private IRequestInfo request;
    private byte[] requestBytes;
    private List<String> initialRequestHeader;


    public AbstractRequestResponseUtil(LogCallback logCallback, IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        this.logCallback = logCallback;
        this.helpers = helpers;
        this.requestResponse = requestResponse;
    }

    protected IExtensionHelpers helpers() {
        return helpers;
    }
    protected IHttpRequestResponse requestResponse() {
        return requestResponse;
    }


    public byte[] requestBytes() {
        if (requestBytes == null) {
            requestBytes = requestResponse.getRequest();
        }
        return requestBytes;
    }

    public IRequestInfo request() {
        if (request == null) {
            request = helpers.analyzeRequest(requestResponse.getHttpService(), requestBytes());
        }
        return request;
    }
    public List<String> initialRequestHeader() {
        if (initialRequestHeader == null) {
            initialRequestHeader = Collections.unmodifiableList(request().getHeaders());
        }
        return initialRequestHeader;
    }

    protected List<String> requestHeaders(boolean init) {
        return initialRequestHeader();
    }


    public List<String> requestHeaders() {
        return requestHeaders(true);
    }

    public String requestHeader(String header) {
        List<String> requestHeader = requestHeaders(false);
        return requestHeader.stream().filter(header::equalsIgnoreCase).findFirst().orElse(null);
    }

    public List<String> requestHeaders(String header) {
        List<String> requestHeader = requestHeaders(false);
        return requestHeader.stream().filter(header::equalsIgnoreCase).collect(Collectors.toList());
    }

    public boolean hasRequestHeader(String header, String value) {
        List<String> headers = requestHeaders(false);
        return hasHeaderWithValue(header, value, headers);
    }

    static protected boolean hasHeaderWithValue(String header, String value, List<String> headers) {
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



    public String url() {
        List<String> headers = requestHeaders(false);
        String url = headers.get(0).trim();
        int begin = url.indexOf(' ');
        int end = url.lastIndexOf(' ');
        if (begin != -1 && end != -1 && (url.substring(end + 1).equalsIgnoreCase("HTTP/1.1")
                || url.substring(end + 1).equalsIgnoreCase("HTTP/1.0"))) {
            return url.substring(begin + 1, end);
        } else {
            return null;
        }
    }

    public String href() {
        String url = url();
        int idxHRef = url.indexOf("#");
        if (idxHRef != -1) {
            return url.substring(idxHRef+1);
        }
        return "";
    }


    protected void resetCache() {
        this.request = null;
        this.requestBytes = null;
        this.initialRequestHeader = null;
    }

    abstract public void commit();

}
