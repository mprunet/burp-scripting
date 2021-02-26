package fr.safepic.burp.script.ui.model;

import burp.IBurpExtenderCallbacks;
import fr.safepic.burp.script.ui.panel.ScriptPanel;

import java.util.Objects;
import java.util.UUID;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

public class ScriptRef {
    private String uid = UUID.randomUUID().toString();
    private boolean enabled;
    private boolean inScope = true;
    private int tools = IBurpExtenderCallbacks.TOOL_PROXY;
    private transient ScriptPanel panel;
    private String name;
    private String description;
    private String scriptRequest;
    private String scriptResponse;
    private transient ScriptRef backup;
    private boolean savedGlobally;

    public ScriptRef() {

    }

    public ScriptRef getBackup() {
        return backup;
    }

    public ScriptRef backup() {
        backup = new ScriptRef();
        backup.enabled = enabled;
        backup.name = name;
        backup.description = description;
        backup.inScope = inScope;
        backup.tools = tools;
        backup.scriptRequest = scriptRequest;
        backup.scriptResponse = scriptResponse;
        return backup;
    }

    public void restore() {
        enabled = backup.enabled;
        name = backup.name;
        description = backup.description;
        inScope = backup.inScope;
        tools = backup.tools;
        scriptRequest = backup.scriptRequest;
        scriptResponse = backup.scriptResponse;
        backup = null;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public ScriptPanel getPanel() {
        return panel;
    }

    public void setPanel(ScriptPanel panel) {
        this.panel = panel;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getScriptRequest() {
        return scriptRequest;
    }

    public void setScriptRequest(String scriptRequest) {
        this.scriptRequest = scriptRequest;
    }

    public String getScriptResponse() {
        return scriptResponse;
    }

    public void setScriptResponse(String scriptResponse) {
        this.scriptResponse = scriptResponse;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isInScope() {
        return inScope;
    }

    public void setInScope(boolean inScope) {
        this.inScope = inScope;
    }

    public int getTools() {
        return tools;
    }

    public void setTools(int tools) {
        this.tools = tools;
    }

    public boolean needsSave() {
        if (backup == null) {
            return false;
        }
        if (backup.isInScope() != isInScope()) return true;
        if (backup.getTools() != getTools()) return true;
        if (!Objects.equals(backup.getName(), getName())) return true;
        if (!Objects.equals(backup.getDescription(), getDescription())) return true;
        if (!Objects.equals(backup.getScriptRequest(), getScriptRequest())) return true;
        return !Objects.equals(backup.getScriptResponse(), getScriptResponse());
    }



    public void saveData(Preferences pref) throws BackingStoreException {
        Preferences node = pref.node(uid);
        node.putInt("version", 1);
        node.putBoolean("enabled", enabled);
        node.putInt("tools", tools);
        node.put("name", name);
        node.put("description", description);
        node.put("scriptRequest", scriptRequest);
        node.put("scriptResponse", scriptResponse);
        savedGlobally = true;
        node.flush();
    }

    public static ScriptRef restoreData(Preferences node) {
        ScriptRef ref = new ScriptRef();
        ref.uid = node.name();
        ref.enabled = node.getBoolean("enabled", false);
        ref.tools = node.getInt("tools", 0);
        ref.name = node.get("name", node.name());
        ref.description = node.get("description", "");
        ref.scriptRequest = node.get("scriptRequest", "");
        ref.scriptResponse = node.get("scriptResponse", "");
        ref.savedGlobally = true;
        return ref;
    }

    public String getUid() {
        return uid;
    }

    public boolean isSavedGlobally() {
        return savedGlobally;
    }


/*
        private boolean local;
    private boolean enabled;
    private boolean inScope = true;
    private int tools = IBurpExtenderCallbacks.TOOL_PROXY;
    private transient Script2Panel panel;
    private String name;
    private String description;
    private String scriptRequest;
    private String scriptResponse;
    private transient ScriptRef backup;

     */
}
