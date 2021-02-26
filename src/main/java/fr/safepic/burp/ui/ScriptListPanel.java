package fr.safepic.burp.ui;

import fr.safepic.burp.ui.common.CloseTabIcon;
import fr.safepic.burp.ui.common.CloseableTabbedPane;
import fr.safepic.burp.ui.common.NewTabIcon;
import fr.safepic.burp.ui.scripts.ScriptRef;
import fr.safepic.burp.ui.scripts.ScriptTableModel;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

public class ScriptListPanel extends JPanel {
    private JTable table;
    private ScriptTableModel tm;
    List<ScriptRef> data = new ArrayList<>();
    private CloseableTabbedPane tabbedPane = new CloseableTabbedPane("Scripts", this, this::addTab);


    public ScriptListPanel() {
        setName("Scripts");
        this.tabbedPane = tabbedPane;
        init();
    }

    public Void addTab() {
        ScriptRef sr = fakeData("New script","");
        data.add(sr);
        SwingUtilities.invokeLater(()->{
            tm.fireTableDataChanged();
        });
        addTab(sr);
        return null;
    }

    public CloseableTabbedPane getTabbedPane() {
        return tabbedPane;
    }

    private ScriptRef fakeData(String name, String description) {

        ScriptRef scriptRef = new ScriptRef();
        scriptRef.setName(name);
        scriptRef.setDescription(description);
        scriptRef.setScriptRequest("/* Variables exposed \n" +
                "helper : instance of burp.IExtensionHelpers\n" +
                "requestResponse : instance of burp.IHttpRequestResponse\n" +
                "log : a logger helper\n" +
                "log.debug('Bonjour');\n" +
                "//log.error('Bonjour');\n" +
                "tools : see help\n" +
                "tools.removeRequestHeader('Connection');\n" +
                "tools.setRequestHeader('User-Agent', 'xxx');\n" +
                "tools.addRequestHeader('Connection', 'Close'\n" +
                "tools.url('/auth/login#favicon.ico');\n" +
                "tools.url()\n" +
                "*/\n");
        scriptRef.setScriptResponse("/* Variables exposed \n" +
                "helper : instance of burp.IExtensionHelpers\n" +
                "requestResponse : instance of burp.IHttpRequestResponse\n" +
                "log : a logger helper\n" +
                "log.debug('Bonjour');\n" +
                "//log.error('Bonjour');\n" +
                "tools : see help\n" +
                "tools.removeResponseHeader('Cache');\n" +
                "tools.setRequestHeader('User-Agent', 'xxx');\n" +
                "tools.addRequestHeader('Connection', 'Close'\n" +
                "tools.url('/auth/login#favicon.ico');\n" +
                "tools.url()\n" +
                "*/\n");
        return scriptRef;
    }

    public void init() {
        setLayout(new BorderLayout());
        loadData();
/*
        data.add(fakeData("avoid cache", "Remove cache"));
        data.add(fakeData("useragent", "Change useragent value"));*/

        tm = new ScriptTableModel(data);
        table = new JTable(tm);
        for (int i = 0; i<tm.getColumnCount();i++) {
            if (tm.getColumnClass(i) == String.class) {
                table.getColumnModel().getColumn(i).setCellRenderer(tm);
            }
        }
        add(new JScrollPane(table), BorderLayout.CENTER);
        /*ListSelectionModel listModel = table.getSelectionModel();
        listModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        listModel.addListSelectionListener(this);*/
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

    private void addTab(ScriptRef sr) {
        SwingUtilities.invokeLater(()-> {
            if (sr.getPanel() == null) {
                if (!sr.needsSave()) {
                    sr.backup();
                }
                Script2Panel scriptPanel = new Script2Panel(sr, ScriptListPanel.this::onChange);
                sr.setPanel(scriptPanel);
                tabbedPane.addTab(sr.getName(), new CloseTabIcon(), scriptPanel.getScrollPane(), null, () -> {
                    SwingUtilities.invokeLater(() -> {
                        boolean close = true;
/*                        if (sr.needsSave()) {
                            close = JOptionPane.showConfirmDialog(scriptPanel, "Do you want to close the tab without saving the changes ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
                        }*/
                        if (close) {
                            int idx = tabbedPane.indexOfComponent(scriptPanel.getScrollPane());
                            sr.setPanel(null);
                            tabbedPane.removeTabAt(idx);
                            tabbedPane.setSelectedIndex(0);
                        }
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

    public void onChange(ScriptRef ref, Script2Panel.Action action) {
        if (action == Script2Panel.Action.UPDATE) {
            SwingUtilities.invokeLater(()-> {
                tm.fireDataChanged(ref);
                JPanel panel = ref.getPanel();
                if (panel != null) {
                    int idx = tabbedPane.indexOfComponent(ref.getPanel().getScrollPane());
                    tabbedPane.setTitleAt(idx, ref.getName());
                }
            });
        } else if (action == Script2Panel.Action.SAVE) {
            try {
                ref.saveData(getNode());
                ref.backup();
                SwingUtilities.invokeLater(()->{
                    tm.fireDataChanged(ref);
                });
            } catch (BackingStoreException ignore) {
            }
        } else if (action == Script2Panel.Action.DELETE) {
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
                SwingUtilities.invokeLater(()->{
                    tm.fireTableDataChanged();
                });
            }
        }
    }

    private Preferences getNode() {
        return Preferences.userNodeForPackage(ScriptListPanel.class).node(ScriptListPanel.class.getName());
    }
/*
    public void valueChanged(ListSelectionEvent e) {
        int[] sel;
        Object value;
        if (!e.getValueIsAdjusting())
        {
            sel = table.getSelectedRows();
            if (sel.length > 0) {
                System.out.println("Value selected " + tm.getValueAt(sel[0]).getName());
            }
        }
    }}*/
}
