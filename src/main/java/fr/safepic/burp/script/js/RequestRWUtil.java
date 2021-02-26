package fr.safepic.burp.script.js;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import fr.safepic.burp.script.LogCallback;

import java.util.ArrayList;
import java.util.List;

public class RequestRWUtil extends AbstractRequestResponseUtil {
    private List<String> requestHeader;


    public RequestRWUtil(LogCallback logCallback, IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        super(logCallback, helpers, requestResponse);
    }

    @Override
    protected List<String> requestHeaders(boolean init) {
        List<String> requestHeader = this.requestHeader;
        if (requestHeader == null) {
            if (init) {
                requestHeader = new ArrayList<>(initialRequestHeader());
                this.requestHeader = requestHeader;
            } else {
                requestHeader = initialRequestHeader();
            }

        }
        return requestHeader;
    }


    public void removeRequestHeader(String header) {
        requestHeaders(true);
        String cur;
        for (int i = 1; i<requestHeader.size(); i++) {
            cur = requestHeader.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                logCallback.trace("Request Header " + cur + " removed");
                requestHeader.remove(i);
                i--;
            }
        }
    }

    public void setRequestHeader(String header, String value) {
        requestHeaders(true);
        String cur;
        for (int i = 1; i<requestHeader.size(); i++) {
            cur = requestHeader.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                requestHeader.set(i, header+": "+value);
                logCallback.trace("Request Header " + cur + " replaced by" + header+": "+value);
            }
        }
    }

    public void addRequestHeader(String header, String value) {
        requestHeaders(true);
        requestHeader.add(header+": "+value);
        logCallback.trace("Request Header " + header+": "+value + " added");
    }
    public void url(String url) {
        List<String> headers  = requestHeaders();
        String oldUrl = headers.get(0);
        int begin = oldUrl.indexOf(' ');
        int end = oldUrl.lastIndexOf(' ');
        headers.set(0, oldUrl.substring(0, begin+1) + url + oldUrl.substring(end));
    }

    public void href(String href) {
        String oldUrl = url();
        int idxHRef = oldUrl.indexOf("#");
        String url;
        if (idxHRef != -1) {
            url = oldUrl.substring(0, idxHRef - 1) + href;
        } else {
            url = oldUrl += "#" + href;
        }
        url(url);
        logCallback.trace("Request Url " + oldUrl + " replaced by " + url);
    }

    private boolean isModified() {
        return requestHeader != null && !requestHeader.equals(initialRequestHeader());
    }

    public void commit() {
        if (isModified()) {
            IRequestInfo ri = request();
            byte[] body = new byte[requestBytes().length - ri.getBodyOffset()];
            System.arraycopy(requestBytes(), ri.getBodyOffset(), body, 0, body.length);
            requestResponse().setRequest(helpers().buildHttpMessage(requestHeader, body));
            resetCache();
            this.requestHeader = null;
            logCallback.trace("Request updated");
        }
    }

}
