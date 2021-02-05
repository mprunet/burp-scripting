package fr.safepic.burp;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

import java.io.PrintWriter;
import java.util.function.Supplier;

import static burp.IBurpExtenderCallbacks.*;

public abstract class AbstractMessageModifier {

    private final PrintWriter pwOut;
    protected IBurpExtenderCallbacks callbacks;


    public AbstractMessageModifier(IBurpExtenderCallbacks callbacks) {
        this.pwOut = new PrintWriter(callbacks.getStdout(), true);
        this.callbacks = callbacks;
    }

    public void debug(Object s) {
        if (isDebug()) {
            pwOut.println("DEBUG :" + s);
        }
    }

    public void error(Object s) {
        pwOut.println("ERROR :" + s);
    }

    public void error(Exception e) {
        e.printStackTrace(pwOut);
    }


    public abstract void modifyRequest(IHttpRequestResponse requestResponse);

    public abstract void modifyResponse(IHttpRequestResponse requestResponse);

    public abstract boolean isEnabled(int extension, IHttpRequestResponse message);
/*        int allowedExtension = TOOL_SUITE |
                TOOL_TARGET |
                TOOL_PROXY |
                TOOL_SPIDER |
                TOOL_SCANNER |
                TOOL_INTRUDER |
                TOOL_REPEATER |
                TOOL_SEQUENCER |
                TOOL_DECODER |
                TOOL_COMPARER |
                TOOL_EXTENDER;
    }*/

    protected boolean isInScope(IHttpRequestResponse message) {
        return callbacks.isInScope(callbacks.getHelpers().analyzeRequest(message).getUrl());
    }

    protected boolean isEnabled(int extension, IHttpRequestResponse message, Supplier<Boolean> isEnabled, Supplier<Boolean> isInScopeOnlySupplier, Supplier<Boolean> isProxyOnlySupplier) {
        boolean isInScopeOnly = isInScopeOnlySupplier.get();
        boolean isProxyOnly = isProxyOnlySupplier.get();

        return isEnabled.get()
                && (!isInScopeOnly || (isInScopeOnly && isInScope(message)))
                && (!isProxyOnly || (isProxyOnly && extension == TOOL_PROXY));
    }



    public abstract boolean isDebug();

}
