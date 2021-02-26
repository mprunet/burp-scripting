package fr.safepic.burp;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import fr.safepic.burp.js.AbstractRequestResponseUtil;
import fr.safepic.burp.js.RequestRWUtil;
import fr.safepic.burp.js.ResponseRWUtil;
import fr.safepic.burp.ui.ScriptPanel;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

import java.lang.reflect.Method;

public class ScriptModifier extends AbstractMessageModifier{
    private ScriptPanel panel;

    public ScriptModifier(IBurpExtenderCallbacks callbacks, ScriptPanel scriptPanel) {
        super(callbacks);
        this.panel = scriptPanel;
    }


    private void callScript(boolean request, IHttpRequestResponse requestResponse) {
        // Create and enter a Context. A Context stores information about the execution environment of a script.
        Context cx = Context.enter();
        try {
            AbstractRequestResponseUtil tools;
            if (request) {
              tools = new RequestRWUtil(this.panel, this, callbacks.getHelpers(), requestResponse);
            } else {
              tools = new ResponseRWUtil(this.panel, this, callbacks.getHelpers(), requestResponse);
            }
            Scriptable scope = cx.initStandardObjects();
            // Pass the Stock Java object to the JavaScript context
            Object wrappedRequestResponse = Context.javaToJS(requestResponse, scope);
            Object wrappedLog = Context.javaToJS(this, scope);
            Object wrappedTools = Context.javaToJS(tools, scope);

            ScriptableObject.putProperty(scope, "helper", Context.javaToJS(callbacks.getHelpers(), scope));
            ScriptableObject.putProperty(scope, "requestResponse", wrappedRequestResponse);
            ScriptableObject.putProperty(scope, "burpcustomextension", wrappedTools);
            StringBuilder sb = new StringBuilder();
            for (Method m : tools.getClass().getMethods()) {
                if (m.getDeclaringClass() != Object.class) {
                    sb.append("function ").append(m.getName()).append("(");
                    String sep = "";
                    for (int i = 0; i< m.getParameterCount();i++) {
                        sb.append(sep).append("p").append(i);
                        sep = ",";
                    }
                    sb.append(") {\n");
                    sb.append("   ");
                    if (m.getReturnType() != Void.TYPE) {
                        sb.append("return ");
                    }
                    sb.append("burpcustomextension.").append(m.getName()).append("(");
                    sep = "";
                    for (int i = 0; i< m.getParameterCount();i++) {
                        sb.append(sep).append("p").append(i);
                        sep = ",";
                    }
                    sb.append(");\n}\n");
                }
            }
            sb.append(request ? panel.getRequestScript() : panel.getResponseScript());
            String fullScript = sb.toString();
            // Execute the script
            cx.evaluateString(scope, fullScript, "EvaluationScript", 1, null);
            tools.commit();
        } catch (Exception e) {
            this.panel.printException(e);
        } finally {
            // Exit the Context. This removes the association between the Context and the current thread and is an
            // essential cleanup action. There should be a call to exit for every call to enter.
            Context.exit();
        }

    }

    @Override
    public void modifyRequest(IHttpRequestResponse requestResponse) {
        callScript(true, requestResponse);
    }

    @Override
    public void modifyResponse(IHttpRequestResponse requestResponse) {
        callScript(false, requestResponse);
    }

    @Override
    public boolean isEnabled(int extension, IHttpRequestResponse request) {
        boolean enabled = super.isEnabled(extension, request, ()-> panel.isEnabled(), ()-> panel.isInScopeOnly(), () -> panel.isProxyOnly());
        return enabled;
    }


    @Override
    public boolean isDebug() {
        return this.panel.isDebug();
    }

}
