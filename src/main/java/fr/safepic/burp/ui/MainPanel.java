package fr.safepic.burp.ui;

import burp.IBurpExtenderCallbacks;
import fr.safepic.burp.ui.common.CloseableTabbedPane;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JPanel {
    IBurpExtenderCallbacks callbacks;
    ScriptPanel scriptPanel;
    ScriptListPanel refPanel;

    public MainPanel(IBurpExtenderCallbacks callbacks) {
        setLayout(new BorderLayout());
        refPanel = new ScriptListPanel();
        add(refPanel.getTabbedPane(), BorderLayout.CENTER);
        //scriptPanel = new ScriptPanel(callbacks, "Script", tabbedPane);
    }

    public void unload() {
        scriptPanel.unload();
    }


    public ScriptPanel getScriptPanel() {
        return scriptPanel;
    }
}
