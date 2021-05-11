package fr.safepic.burp.script.js;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import fr.safepic.burp.script.LogCallback;
import org.mozilla.javascript.json.JsonParser;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public abstract class AbstractRequestResponseUtil {

    protected LogCallback logCallback;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private final IHttpRequestResponse requestResponse;
    private IRequestInfo request;
    private byte[] requestBytes;
    protected byte[] requestBody;
    private List<String> initialRequestHeader;
    private List<IssueObj> issues = new ArrayList<>();
    protected final JavascriptContext context;


    public AbstractRequestResponseUtil(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse, JavascriptContext context) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.requestResponse = requestResponse;
        this.context = context;
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


    public List<String> getAllRequestHeaders() {
        return requestHeaders(true);
    }

    protected Stream<String> filterHeaderGetValue(List<String> headers, String header) {
        return headers.stream()
                .filter(cur->{
                    int sep = cur.indexOf(':');
                    return (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header))
                            && (header == null || header.equals(cur.substring(sep+1).trim()));
                })
                .map(cur->cur.substring(cur.indexOf(':')+1).trim());
    }


    public String getRequestHeader(String header) {
        List<String> requestHeader = requestHeaders(false);
        return filterHeaderGetValue(requestHeader, header).findFirst().orElse(null);

    }

    public List<String> getRequestHeaders(String header) {
        List<String> requestHeader = requestHeaders(false);
        return filterHeaderGetValue(requestHeader, header).collect(Collectors.toList());
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



    public String getUrl() {
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

    public String getHref() {
        String url = getUrl();
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

    public void setLogCallback(LogCallback logCallback) {
        this.logCallback = logCallback;
    }

    public IssueObj addIssue(String name) {

        IssueObj issueObj = new IssueObj(
                request().getUrl(),
                name,
                new IHttpRequestResponse[]{requestResponse},
                requestResponse.getHttpService()
        );
        issues.add(issueObj);
        return issueObj;
    }
    protected String decodeBody(byte[] body, String encoding, Supplier<String> contentType) {
        if ("undefined".equals(encoding)) {
            String type = contentType.get();
            if (type == null) {
                logCallback.error("Encoding not specified use ISO-8859-1");
                encoding = "ISO-8859-1";
            } else {
                int idxCharset = type.indexOf("charset");
                if (idxCharset != -1) {
                    encoding = type.substring(idxCharset + 8).split(" ;")[0];
                } else {
                    logCallback.error("Encoding not specified use ISO-8859-1");
                    encoding = "ISO-8859-1";
                }
            }
        }
        try {
            return new String(body, encoding);
        } catch (UnsupportedEncodingException e) {
            logCallback.error("Encoding not supported "+ encoding + " fallback to ISO-8859-1");
            return new String(requestBytes(), StandardCharsets.ISO_8859_1);
        }

    }

    public byte[] getRequestBody() {
        if (requestBody == null) {
            IRequestInfo ri = request();
            requestBody = new byte[requestBytes().length - ri.getBodyOffset()];
            System.arraycopy(requestBytes(), ri.getBodyOffset(), requestBody, 0, requestBody.length);
        }
        return requestBody;
    }

    public String getRequestBodyAsString(String encoding) {
        return decodeBody(getRequestBody(), encoding, ()->getRequestHeader("Content-Type"));
    }

    public Object getRequestBodyAsJson(String encoding) throws JsonParser.ParseException {
        String value = getRequestBodyAsString(encoding);
        JsonParser jsonParser = new JsonParser(context.getCx(), context.getScope());
        return jsonParser.parseValue(value);
    }

    public void commit() {
        for (IssueObj issueObj : issues) {
            callbacks.addScanIssue(issueObj);
        }
    }

}
