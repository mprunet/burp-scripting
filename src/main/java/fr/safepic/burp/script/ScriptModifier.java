package fr.safepic.burp.script;

import burp.*;
import fr.safepic.burp.script.js.AbstractRequestResponseUtil;
import fr.safepic.burp.script.js.RequestRWUtil;
import fr.safepic.burp.script.js.ResponseRWUtil;
import fr.safepic.burp.script.ui.panel.ScriptTablePanel;
import fr.safepic.burp.script.ui.model.ScriptRef;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.function.Supplier;

import static burp.IBurpExtenderCallbacks.TOOL_PROXY;

public class ScriptModifier implements IHttpListener, IProxyListener {
    private final ScriptTablePanel panel;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    private String requestMethodCache;
    private String responseMethodCache;


    public ScriptModifier(IBurpExtenderCallbacks callbacks, ScriptTablePanel scriptPanel) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.panel = scriptPanel;
    }
    @Override
    public void processProxyMessage(boolean request, IInterceptedProxyMessage iInterceptedProxyMessage) {
        callScript(TOOL_PROXY, request, iInterceptedProxyMessage::getMessageInfo);
    }


    @Override
    public void processHttpMessage(int tools, boolean request, IHttpRequestResponse requestResponse) {
        if (tools == TOOL_PROXY) {
            return;
        }
        callScript(tools, request, ()->requestResponse);
    }


    private void classToJavascript(StringBuilder sb, Class<?> clazz, String jsObjectName) {
        for (Method m : clazz.getMethods()) {
            if (m.getDeclaringClass() != Object.class && (m.getModifiers() & Modifier.PUBLIC) != 0) {
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
                sb.append(jsObjectName).append(".").append(m.getName()).append("(");
                sep = "";
                for (int i = 0; i< m.getParameterCount();i++) {
                    sb.append(sep).append("p").append(i);
                    sep = ",";
                }
                sb.append(");\n}\n");
            }
        }

    }

    private StringBuilder newRequestScript() {
        StringBuilder sb = new StringBuilder();
        if (requestMethodCache == null) {
            classToJavascript(sb, RequestRWUtil.class, "burpscriptingextension");
            classToJavascript(sb, LogCallback.class, "log");
            requestMethodCache = sb.toString();
        } else {
            sb.append(requestMethodCache);
        }
        return sb;
    }

    private StringBuilder newResponseScript() {
        StringBuilder sb = new StringBuilder();
        if (responseMethodCache == null) {
            classToJavascript(sb, ResponseRWUtil.class, "burpscriptingextension");
            classToJavascript(sb, LogCallback.class, "log");
            responseMethodCache = sb.toString();
        } else {
            sb.append(responseMethodCache);
        }
        return sb;
    }

    private void callScript(int burpTools, boolean request, Supplier<IHttpRequestResponse> supplierRequestResponse) {
        IHttpRequestResponse requestResponse = null;
        AbstractRequestResponseUtil tools = null;
        for (ScriptRef scriptRef : panel.getActiveScriptRef()) {
            if (requestResponse == null) {
                requestResponse = supplierRequestResponse.get();
                if (request) {
                    tools = new RequestRWUtil(helpers, requestResponse);
                } else {
                    tools = new ResponseRWUtil(helpers, requestResponse);
                }
            }
            if ((scriptRef.getTools() & burpTools) == 0
               || scriptRef.isScriptError()
               || scriptRef.isInScope() && !callbacks.isInScope(tools.request().getUrl())) {
                continue;
            }


            // Create and enter a Context. A Context stores information about the execution environment of a script.
            LogCallback logCallback = new LogCallback(scriptRef.getPanel(), stdout, stderr);
            tools.setLogCallback(logCallback);
            Context cx = Context.enter();
            try {
                String scriptContent = request ? scriptRef.getScriptRequest() : scriptRef.getScriptResponse();
                if (scriptContent.trim().length() == 0) {
                    continue;
                }
                StringBuilder script = request ? newRequestScript() : newResponseScript();

                Scriptable scope = cx.initStandardObjects();
                // Pass the Stock Java object to the JavaScript context
                Object wrappedRequestResponse = Context.javaToJS(requestResponse, scope);
                Object wrappedTools = Context.javaToJS(tools, scope);
                Object wrappedLog = Context.javaToJS(logCallback, scope);

                ScriptableObject.putProperty(scope, "helper", Context.javaToJS(callbacks.getHelpers(), scope));
                ScriptableObject.putProperty(scope, "requestResponse", wrappedRequestResponse);
                ScriptableObject.putProperty(scope, "burpscriptingextension", wrappedTools);
                ScriptableObject.putProperty(scope, "log", wrappedLog);
                script.append(scriptContent);
                // Execute the script
                cx.evaluateString(scope, script.toString(), "EvaluationScript", 1, null);
                tools.commit();
            } catch (Throwable e) {
                scriptRef.setScriptError(true);
                logCallback.exception(e);
                callbacks.issueAlert("Compilation error in script " + scriptRef.getName() + ", script disabled, fix it to reactivate execution");
                logCallback.error("Compilation error, script disabled, you must fix the error");
                panel.notifyScriptDisabled(scriptRef);
            } finally {
                logCallback.flush();
                // Exit the Context. This removes the association between the Context and the current thread and is an
                // essential cleanup action. There should be a call to exit for every call to enter.
                Context.exit();
            }
        }

    }
}
