package burp;

import fr.safepic.burp.HttpMessageModifier;
import fr.safepic.burp.ui.MainPanel;

import javax.swing.*;
import java.awt.*;

public class BurpExtender implements IBurpExtender {
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        SwingUtilities.invokeLater(() -> {
            MainPanel panel = new MainPanel(callbacks);
            callbacks.setExtensionName("ScriptingExtension");
            callbacks.registerExtensionStateListener(new IExtensionStateListener() {
                @Override
                public void extensionUnloaded() {
                    panel.unload();
                }
            });
            HttpMessageModifier modifier = new HttpMessageModifier(callbacks, panel);
            callbacks.registerHttpListener(modifier);
            callbacks.registerProxyListener(modifier);
            callbacks.addSuiteTab(new ITab() {
                @Override
                public String getTabCaption() {
                    return "ScriptingExtension";
                }

                @Override
                public Component getUiComponent() {
                    return panel;
                }
            });
        });
    }
}
