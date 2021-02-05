package fr.safepic.burp.ui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;
import java.awt.*;

public class MainPanel extends JPanel {
    JTabbedPane tabbedPane = new JTabbedPane();
    IBurpExtenderCallbacks callbacks;
    ScriptPanel scriptPanel;

    public MainPanel(IBurpExtenderCallbacks callbacks) {
        setLayout(new BorderLayout());
        add(tabbedPane, BorderLayout.CENTER);
        scriptPanel = new ScriptPanel(callbacks, "Script", tabbedPane);
    }

    public void unload() {
        scriptPanel.unload();
    }


    public ScriptPanel getScriptPanel() {
        return scriptPanel;
    }
}
