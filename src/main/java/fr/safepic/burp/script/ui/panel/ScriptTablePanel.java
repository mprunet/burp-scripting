package fr.safepic.burp.script.ui.panel;

import fr.safepic.burp.script.PreferenceClass;
import fr.safepic.burp.script.ui.component.CloseTabIcon;
import fr.safepic.burp.script.ui.component.CloseableTabbedPane;
import fr.safepic.burp.script.ui.model.ScriptRef;
import fr.safepic.burp.script.ui.model.ScriptTableModel;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;
import java.util.stream.Collectors;

public class ScriptTablePanel extends JPanel {
    private JTable table;
    private ScriptTableModel tm;
    private final List<ScriptRef> data = new ArrayList<>();
    private final CloseableTabbedPane tabbedPane = new CloseableTabbedPane("Scripts", this, this::addTab);
    private final Timer timer;


    public ScriptTablePanel() {
        setName("Scripts");
        init();
        //tabbedPane.addChangeListener(this::tabChange);
        timer = new Timer(1000, e -> {
            oldSelectedIndex = tabbedPane.getSelectedIndex();
            Component c = tabbedPane.getComponentAt(oldSelectedIndex);
            if (c instanceof JScrollPane) {
                c = ((JScrollPane)c).getViewport().getView();
                if (c instanceof ScriptPanel) {
                    ((ScriptPanel) c).refreshLog();
                }
            }
        });
        timer.setInitialDelay(5000);
        timer.start();
    }

    public Void addTab() {
        ScriptRef sr = fakeData("New script " + data.size());
        data.add(sr);
        SwingUtilities.invokeLater(()-> tm.fireTableDataChanged());
        addTab(sr);
        return null;
    }

    public CloseableTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    private ScriptRef fakeData(String name) {

        ScriptRef scriptRef = new ScriptRef();
        scriptRef.setName(name);
        scriptRef.setDescription("");
        scriptRef.setScriptRequest("/* Variables exposed :\n" +
                "helper : instance of burp.IExtensionHelpers\n" +
                "requestResponse : instance of burp.IHttpRequestResponse\n" +
                "Right click to see code sample\n"+
                "*/\n");
        scriptRef.setScriptResponse("/* Variables exposed :\n" +
                        "helper : instance of burp.IExtensionHelpers\n" +
                        "requestResponse : instance of burp.IHttpRequestResponse\n" +
                        "Right click to see code sample\n"+
                "*/\n");
        return scriptRef;
    }

    public void init() {
        setLayout(new BorderLayout());
        loadData();

        tm = new ScriptTableModel(data);
        table = new JTable(tm);
        for (int i = 0; i<tm.getColumnCount();i++) {
            if (tm.getColumnClass(i) == String.class) {
                table.getColumnModel().getColumn(i).setCellRenderer(tm);
            }
        }
        add(new JScrollPane(table), BorderLayout.CENTER);
        table.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent me) {
                Point p = me.getPoint();
                int row = table.rowAtPoint(p);
                int column = table.columnAtPoint(p);
                if (!tm.isCellEditable(row, column) && me.getClickCount() == 2) {
                    ScriptRef sr = tm.getValueAt(row);
                    addTab(sr);
                }
            }
        });
    }

    private int oldSelectedIndex = 0;

    /*public void tabChange(ChangeEvent event) {
        Component c = tabbedPane.getComponentAt(oldSelectedIndex);
        if (c instanceof JScrollPane) {
            c = ((JScrollPane)c).getViewport().getView();
            if (c instanceof ScriptPanel) {
                ((ScriptPanel) c).componentHidden(null);
            }
        }
        oldSelectedIndex = tabbedPane.getSelectedIndex();
        c = tabbedPane.getComponentAt(oldSelectedIndex);
        if (c instanceof JScrollPane) {
            c = ((JScrollPane)c).getViewport().getView();
            if (c instanceof ScriptPanel) {
                ((ScriptPanel) c).componentShown(null);
            }
        }
    }*/

    private void addTab(ScriptRef sr) {
        SwingUtilities.invokeLater(()-> {
            if (sr.getPanel() == null) {
                if (!sr.needsSave()) {
                    sr.backup();
                }
                ScriptPanel scriptPanel = new ScriptPanel(sr, ScriptTablePanel.this::onChange);
                sr.setPanel(scriptPanel);
                tabbedPane.addTab(sr.getName(), new CloseTabIcon(), scriptPanel.getScrollPane(), null, () -> {
                    SwingUtilities.invokeLater(() -> {
                        int idx = tabbedPane.indexOfComponent(scriptPanel.getScrollPane());
                        sr.setPanel(null);
                        tabbedPane.removeTabAt(idx);
                        tabbedPane.setSelectedIndex(0);
                    });
                    return null;
                });
                scriptPanel.buildUi();
            }
            tabbedPane.setSelectedIndex(tabbedPane.indexOfComponent(sr.getPanel().getScrollPane()));
        });
    }

    public void loadData() {
        try {
            Preferences nodes = getNode();
            for (String child : getNode().childrenNames()) {
                data.add(ScriptRef.restoreData(nodes.node(child)));
            }
        } catch (BackingStoreException ignore) {
        }
    }

    public void onChange(ScriptRef ref, ScriptPanel.Action action) {
        if (action == ScriptPanel.Action.UPDATE) {
            SwingUtilities.invokeLater(()-> {
                tm.fireDataChanged(ref);
                JPanel panel = ref.getPanel();
                if (panel != null) {
                    int idx = tabbedPane.indexOfComponent(ref.getPanel().getScrollPane());
                    tabbedPane.setTitleAt(idx, ref.getName());
                }
            });
        } else if (action == ScriptPanel.Action.SAVE) {
            try {
                ref.saveData(getNode());
                ref.backup();
                SwingUtilities.invokeLater(()-> tm.fireDataChanged(ref));
            } catch (BackingStoreException ignore) {
            }
        } else if (action == ScriptPanel.Action.DELETE) {
            Preferences node = getNode();
            try {
                if (node.nodeExists(ref.getUid())) {
                    node.node(ref.getUid()).removeNode();
                }
                node.flush();
            } catch (BackingStoreException ignore) {
            }
            if (data.contains(ref)) {
                data.remove(ref);
                SwingUtilities.invokeLater(()-> tm.fireTableDataChanged());
            }
        }
    }

    private Preferences getNode() {
        return Preferences.userNodeForPackage(PreferenceClass.class);
    }

    public List<ScriptRef> getActiveScriptRef() {
        return data.stream().filter(ScriptRef::isEnabled).collect(Collectors.toList());
    }

    public void notifyScriptDisabled(ScriptRef ref) {
        SwingUtilities.invokeLater(()-> tm.fireDataChanged(ref));
    }
}
