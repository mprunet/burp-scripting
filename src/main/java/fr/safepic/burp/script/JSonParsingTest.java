package fr.safepic.burp.script;

import org.mozilla.javascript.Context;
import org.mozilla.javascript.NativeJSON;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;
import org.mozilla.javascript.json.JsonParser;

public class JSonParsingTest {
    public static void main(String[] args) {
        Context cx = Context.enter();
      try {

            Scriptable scope = cx.initStandardObjects();
            // Pass the Stock Java object to the JavaScript context

            JsonParser jsonParser = new JsonParser(cx, scope);
            Object json = jsonParser.parseValue("{\"titi\":\"toto\"}");
            ScriptableObject.putProperty(scope, "json", json);
            ScriptableObject.putProperty(scope, "out",  Context.javaToJS(System.out, scope));
            // Execute the script
            cx.evaluateString(scope, "out.println(json.titi);json.titi='Modified value'", "EvaluationScript", 1, null);
            System.out.println(NativeJSON.stringify(cx, scope, json, null, null));
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            Context.exit();
        }

    }
}
