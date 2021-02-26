package fr.safepic.burp.script.ui.panel;

import javax.swing.*;
import java.awt.*;

public class TabbedPanel extends JPanel {
    final ScriptTablePanel refPanel;

    public TabbedPanel() {
        setLayout(new BorderLayout());
        refPanel = new ScriptTablePanel();
        add(refPanel.getTabbedPane(), BorderLayout.CENTER);
    }

    public void unload() {

    }


    public ScriptTablePanel getScriptListPanel() {
        return refPanel;
    }
}
