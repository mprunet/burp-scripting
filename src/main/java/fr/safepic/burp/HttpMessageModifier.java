package fr.safepic.burp;


import burp.*;
import fr.safepic.burp.ui.MainPanel;

import java.util.ArrayList;
import java.util.List;

import static burp.IBurpExtenderCallbacks.*;

public class HttpMessageModifier implements IHttpListener, IProxyListener {
    List<AbstractMessageModifier> modifiers = new ArrayList<>();
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public HttpMessageModifier(IBurpExtenderCallbacks callbacks, MainPanel panel) {
        this.helpers = callbacks.getHelpers();
        modifiers.add(new ScriptModifier(callbacks, panel.getScriptPanel()));
    }

    @Override
    public void processProxyMessage(boolean request, IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (request) {
            for (AbstractMessageModifier modifier : this.modifiers) {
                if (modifier.isEnabled(TOOL_PROXY, iInterceptedProxyMessage.getMessageInfo())) {
                    modifier.modifyRequest(iInterceptedProxyMessage.getMessageInfo());
                }
            }
        } else {
            for (AbstractMessageModifier modifier : this.modifiers) {
                if (modifier.isEnabled(TOOL_PROXY, iInterceptedProxyMessage.getMessageInfo())) {
                    modifier.modifyResponse(iInterceptedProxyMessage.getMessageInfo());
                }
            }
        }
    }


    @Override
    public void processHttpMessage(int tools, boolean request, IHttpRequestResponse requestResponse) {
        if (tools == TOOL_PROXY) {
            return;
        }
        if (request) {
            for (AbstractMessageModifier modifier : this.modifiers) {
                if (modifier.isEnabled(tools, requestResponse)) {
                    modifier.modifyRequest(requestResponse);
                }
            }
        } else {
            for (AbstractMessageModifier modifier : this.modifiers) {
                if (modifier.isEnabled(tools, requestResponse)) {
                    modifier.modifyResponse(requestResponse);
                }
            }
        }
    }

}
