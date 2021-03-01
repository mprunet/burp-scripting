package fr.safepic.burp.script.js;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

import java.net.URL;

public class IssueObj implements IScanIssue {
    private URL url;
    private String issueName;
    private int issueType = 0x08000000;
    private String severity = "Information";
    private String confidence = "Tentative";
    private String issueBackground;
    private String issueDetail;
    private String remediationBackground;
    private String remediationDetail;
    private IHttpRequestResponse[] httpMessages;
    private IHttpService httpService;

    public IssueObj(URL url, String name, IHttpRequestResponse[] httpMessages, IHttpService httpService) {
        this.url = url;
        this.issueName = name;
        this.httpMessages = httpMessages;
        this.httpService = httpService;
    }

    public IssueObj certain() {
        confidence = "Certain";
        return this;
    }

    public IssueObj firm() {
        confidence = "Firm";
        return this;
    }

    public IssueObj tentative() {
        confidence = "Tentative";
        return this;
    }

    public IssueObj high() {
        severity = "High";
        return this;
    }

    public IssueObj medium() {
        severity = "Medium";
        return this;
    }

    public IssueObj low() {
        severity = "Low";
        return this;
    }

    public IssueObj information() {
        severity = "Information";
        return this;
    }

    public IssueObj falsePositive() {
        severity = "False positive";
        return this;
    }

    public IssueObj issue(String detail, String background) {
        if (!"undefined".equals(detail)) {
            this.issueDetail = detail;
        }
        if (!"undefined".equals(background)) {
            this.issueBackground = background;
        }
        return this;
    }

    public IssueObj remediation(String detail, String background) {
        if (!"undefined".equals(detail)) {
            this.remediationDetail = detail;
        }
        if (!"undefined".equals(background)) {
            this.remediationDetail = background;
        }
        return this;
    }

    @Override
    public URL getUrl() {
        return url;
    }

    @Override
    public String getIssueName() {
        return issueName;
    }

    @Override
    public int getIssueType() {
        return issueType;
    }

    @Override
    public String getSeverity() {
        return severity;
    }

    @Override
    public String getConfidence() {
        return confidence;
    }

    @Override
    public String getIssueBackground() {
        return null;
    }

    @Override
    public String getRemediationBackground() {
        return null;
    }

    @Override
    public String getIssueDetail() {
        return null;
    }

    @Override
    public String getRemediationDetail() {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages() {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService() {
        return httpService;
    }
}
