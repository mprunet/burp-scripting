package fr.safepic.burp.ui.common;

import fr.safepic.burp.ui.MainPanel;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

import static java.awt.GridBagConstraints.LINE_START;
import static java.awt.GridBagConstraints.NONE;

public class PluginPanel extends JPanel implements PreferenceFriendly, Scrollable{
    protected JTabbedPane tabbedPane;
    protected int lastLine = 0;
    protected JPanel upPanel = new JPanel();
    protected JCheckBox enablePlugin = new JCheckBox("Enable plugin");
    protected JCheckBox debug = new JCheckBox("Debug");
    protected JCheckBox proxyOnly = new JCheckBox("Proxy only", true);
    protected JCheckBox inScopeOnly = new JCheckBox("In scope only", true);
    JComboBox<String> comboBox = new JComboBox<>();
    JButton load = new JButton("Load");
    JButton save = new JButton("Save");
    JButton clearList = new JButton("Delete");
    JPanel savePanel = new JPanel();

    public PluginPanel(String name, JTabbedPane tabbedPane) {
        this.tabbedPane = tabbedPane;
        setName(name);
        tabbedPane.addTab(name, new JScrollPane(this, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER));
        setLayout(new BorderLayout());
        super.add(upPanel, BorderLayout.NORTH);
//        setLayout(new GridBagLayout());
        upPanel.setLayout(new GridBagLayout());
        comboBox.setEditable(true);
        savePanel.setLayout(new FlowLayout());
        savePanel.add(comboBox);
        savePanel.add(load);
        savePanel.add(save);
        savePanel.add(clearList);

        /*add(enabledCB, new GridBagConstraints(0, generalGridY, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));*/
        add(enablePlugin, new GridBagConstraints(0, lastLine, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(debug, new GridBagConstraints(2, lastLine, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(savePanel, new GridBagConstraints(4, lastLine, 3, 1, 1.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));

        add(proxyOnly, new GridBagConstraints(0, lastLine+1, 2, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(inScopeOnly, new GridBagConstraints(2, lastLine, 2, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        load.addActionListener(l->{
            load((String)comboBox.getEditor().getItem());
        });
        save.addActionListener(l->{
            save((String)comboBox.getEditor().getItem());
        });
        clearList.addActionListener(l->{
            String item = (String)comboBox.getEditor().getItem();
            if (JOptionPane.YES_OPTION == JOptionPane.showConfirmDialog(PluginPanel.this,
                    "Do you really want to delete the preference for " + item,
                    "Delete",
                    JOptionPane.YES_NO_OPTION)) {
                Preferences prefs = Preferences.userNodeForPackage(MainPanel.class);
                prefs = prefs.node("Safepic");
                prefs = prefs.node(getName());
                try {
                    for(String child : prefs.childrenNames()) {
                        if (item.equals(child))
                            prefs.node(child).removeNode();
                    }
                    comboBox.removeItem(item);
                } catch (BackingStoreException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public void add(Component comp, Object constraints) {
        if (constraints instanceof GridBagConstraints) {
            lastLine=Math.max(lastLine, ((GridBagConstraints) constraints).gridy);
        }
        upPanel.add(comp, constraints);
    }



    private int lastLine() {
        return lastLine;
    }


    public void postConstruct() {
        toggleEnable();
        enablePlugin.addItemListener(e->{
            toggleEnable();
        });
        save("default");
    }

    static private Color green = new Color(0,190,0);
    public void toggleEnable() {
        boolean enabled = enablePlugin.isSelected();
        enableOrDisableContainer(upPanel, enabled);
        for (int i = 0; i<tabbedPane.getTabCount();i++) {
            if (tabbedPane.getComponentAt(i) == this) {
                tabbedPane.setForegroundAt(i, enabled ? green : Color.BLACK);
            }
        }
        /*proxyOnly.setEnabled(enabled);
        inScopeOnly.setEnabled(enabled);
        siuPanel.setEnabled(enabled);
        gassiPanel.setEnabled(enabled);
        debug.setEnabled(enabled);
        hrefURL.setEnabled(enabled);
        prefixUrl.setEnabled(enabled);
        symfonyCVE.setEnabled(enabled);
        exploitOFT.setEnabled(enabled);
        lowercaseHeader.setEnabled(enabled);*/
    }

    private void enableOrDisableContainer(Container panel, boolean enabled) {
        for (int i = 0; i<panel.getComponentCount();i++) {
            Component c = panel.getComponent(i);
            if (c != enablePlugin) {
                c.setEnabled(enabled);
            }
            if (!excludeInSave(c) && (c instanceof Container)) {
                enableOrDisableContainer((Container) c, enabled);
            }
        }
    }

    public boolean isEnabled() {
        return enablePlugin.isSelected();
    }

    public void setEnabled(boolean b) {
        enablePlugin.setSelected(b);
    }

    public boolean isDebug() {
        return debug.isSelected();
    }

    public boolean isInScopeOnly() {
        return inScopeOnly.isSelected();
    }

    public boolean isProxyOnly() {
        return proxyOnly.isSelected();
    }

    public void load(String prefName) {
        Preferences prefs = Preferences.userNodeForPackage(MainPanel.class);
        prefs = prefs.node("Safepic");
        prefs = prefs.node(getName());
        prefs = prefs.node(prefName);

        load(prefs, upPanel);
        enablePlugin.setSelected(true);
        toggleEnable();
    }



    public void save(String prefName) {
        Preferences prefs = Preferences.userNodeForPackage(MainPanel.class);
        prefs = prefs.node("Safepic");
        final Preferences panelPrefs = prefs.node(getName());
        save(panelPrefs.node(prefName), upPanel);

        SwingUtilities.invokeLater(()->{
            comboBox.removeAllItems();
            try {
                Arrays.stream(panelPrefs.childrenNames())
                        .forEach(comboBox::addItem);
            } catch (BackingStoreException e) {
                e.printStackTrace();
            }
            comboBox.setSelectedItem(prefName);
        });

    }

    public boolean excludeInSave(Component c) {
        return c == savePanel;
    }

    @Override
    public Dimension getPreferredScrollableViewportSize() {
        return super.getPreferredSize();
    }


    @Override
    public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return 16;
    }

    @Override
    public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return 16;
    }

    @Override
    public boolean getScrollableTracksViewportWidth() {
        return true;
    }

    @Override
    public boolean getScrollableTracksViewportHeight() {
        return false;
    }
}
