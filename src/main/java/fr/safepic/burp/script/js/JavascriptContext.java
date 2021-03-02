package fr.safepic.burp.script.js;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.Scriptable;

public class JavascriptContext {
    private Context cx;
    private Scriptable scope;

    public void setCx(Context cx) {
        this.cx = cx;
    }

    public void setScope(Scriptable scope) {
        this.scope = scope;
    }

    public Context getCx() {
        return cx;
    }

    public Scriptable getScope() {
        return scope;
    }
}
