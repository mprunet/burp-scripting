package fr.safepic.burp.script.js;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.List;

public class RequestRWUtil extends AbstractRequestResponseUtil {
    private List<String> requestHeader;


    public RequestRWUtil(IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        super(helpers, requestResponse);
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


    /**
     * Remove all requests header having the provided name
     * @param header: name of the header
     */
    public void removeRequestHeader(String header) {
        requestHeaders(true);
        String cur;
        for (int i = 1; i<requestHeader.size(); i++) {
            cur = requestHeader.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                logCallback.verbose("Request Header " + cur + " removed");
                requestHeader.remove(i);
                i--;
            }
        }
    }

    /**
     * Set the value of the first request header if exists
     * If the header does not exists add a new one
     * @param header: the header's name
     * @param value: the header's value
     */
    public void setRequestHeader(String header, String value) {
        requestHeaders(true);
        String cur;
        boolean set = false;
        for (int i = 1; i<requestHeader.size(); i++) {
            cur = requestHeader.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                requestHeader.set(i, header+": "+value);
                logCallback.verbose("Request Header " + cur + " replaced by" + header+": "+value);
                set = true;
                break;
            }
        }
        if (!set) {
            addRequestHeader(header, value);
        }
    }


        /**
         * Set the value of all requests header having the provided name
         * If the header does not exists does nothing
         * @param header: the header's name
         * @param value: the header's value
         */
    public void updateRequestHeader(String header, String value) {
        requestHeaders(true);
        String cur;
        for (int i = 1; i<requestHeader.size(); i++) {
            cur = requestHeader.get(i);
            int sep = cur.indexOf(':');
            if (sep != -1 && cur.substring(0, sep).trim().equalsIgnoreCase(header)) {
                requestHeader.set(i, header+": "+value);
                logCallback.verbose("Request Header " + cur + " replaced by" + header+": "+value);
            }
        }
    }

    /**
     * Add a request header with the provided name
     * If the header does not exists does nothing
     * @param header: the header's name
     * @param value: the header's value
     */
    public void addRequestHeader(String header, String value) {
        requestHeaders(true);
        requestHeader.add(header+": "+value);
        logCallback.verbose("Request Header " + header+": "+value + " added");
    }
    /**
     * Set the URL of the request (first line)
     * @param url: the url value
     */
    public void setUrl(String url) {
        List<String> headers  = requestHeaders(true);
        String oldUrl = headers.get(0);
        int begin = oldUrl.indexOf(' ');
        int end = oldUrl.lastIndexOf(' ');
        headers.set(0, oldUrl.substring(0, begin+1) + url + oldUrl.substring(end));
    }

    /**
     * Set a href in the URL
     * @param href: the href value
     */
    public void setHref(String href) {
        String oldUrl = getUrl();
        int idxHRef = oldUrl.indexOf("#");
        String url;
        if (idxHRef != -1) {
            url = oldUrl.substring(0, idxHRef - 1) + href;
        } else {
            url = oldUrl += "#" + href;
        }
        setUrl(url);
        logCallback.verbose("Request Url " + oldUrl + " replaced by " + url);
    }

    private boolean isModified() {
        return requestHeader != null && !requestHeader.equals(initialRequestHeader());
    }

    /**
     * Save the request, usefull in case of mixing Burp native method and helper method.
     */
    public void commit() {
        if (isModified()) {
            IRequestInfo ri = request();
            byte[] body = new byte[requestBytes().length - ri.getBodyOffset()];
            System.arraycopy(requestBytes(), ri.getBodyOffset(), body, 0, body.length);
            requestResponse().setRequest(helpers().buildHttpMessage(requestHeader, body));
            resetCache();
            this.requestHeader = null;
            logCallback.verbose("Request updated");
        }
    }

}
