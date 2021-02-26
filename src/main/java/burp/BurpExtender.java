package burp;

import fr.safepic.burp.script.ScriptModifier;
import fr.safepic.burp.script.ui.panel.TabbedPanel;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        SwingUtilities.invokeLater(() -> {
            TabbedPanel panel = new TabbedPanel();
            callbacks.setExtensionName("ScriptingExtension");
            callbacks.registerExtensionStateListener(panel::unload);
            ScriptModifier modifier = new ScriptModifier(callbacks, panel.getScriptListPanel());
            callbacks.registerHttpListener(modifier);
            callbacks.registerProxyListener(modifier);
            callbacks.addSuiteTab(new ITab() {
                @Override
                public String getTabCaption() {
                    return "Scripting";
                }

                @Override
                public Component getUiComponent() {
                    return panel;
                }
            });
        });
    }
}
