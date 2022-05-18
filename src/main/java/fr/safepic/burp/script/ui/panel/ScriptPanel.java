package fr.safepic.burp.script.ui.panel;

import burp.IBurpExtenderCallbacks;
import fr.safepic.burp.script.ui.component.MyTextArea;
import fr.safepic.burp.script.ui.model.ScriptRef;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.util.LinkedList;
import java.util.function.BiConsumer;

import static java.awt.GridBagConstraints.*;


public class ScriptPanel extends JPanel implements Scrollable, ComponentListener {
    private final JCheckBox enabled = new JCheckBox("Enabled");
    private final JCheckBox cbScope = new JCheckBox("In Scope Only");
    private final JLabel labIntercept = new JLabel("Intercept from : ");
    private final JCheckBox cbProxy = new JCheckBox("Proxy");
    private final JCheckBox cbSpider = new JCheckBox("Spider");
    private final JCheckBox cbScanner = new JCheckBox("Scanner");
    private final JCheckBox cbIntruder = new JCheckBox("Intruder");
    private final JCheckBox cbRepeater = new JCheckBox("Repeater");
    private final JCheckBox cbSequencer = new JCheckBox("Sequencer");
    private final JCheckBox cbExtension = new JCheckBox("Extension");
    private final JLabel labelName = new JLabel("Name: ");
    private final JTextField tfName = new JTextField(20);
/*    private final JLabel labelDesc = new JLabel("Description: ");
    private final JTextField tfDesc = new JTextField(20);*/
    private final JCheckBox cbSessionHandling = new JCheckBox("Session Handling Script");

    private final JCheckBox color = new JCheckBox("Disable syntax coloration (bugfix when plugin is reloaded)");
    private final MyTextArea requestScript = new MyTextArea("request");
    private final MyTextArea responseScript = new MyTextArea("response");
    private final JTextPane errorPane = new JTextPane();
    private final JSplitPane hSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScript, responseScript);
    private final JSplitPane vSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, hSplitPane, new JScrollPane(errorPane));
    private final LinkedList<CharSequence> contentQueue = new LinkedList<>();
    private boolean contentQueueModified = false;
    private final ScriptDocumentListener documentListener = new ScriptDocumentListener();
    private boolean updateObject=true;
    private final ScriptRef scriptRef;

    private final JScrollPane scrollPane;
    private final BiConsumer<ScriptRef, Action> scriptRefChangeConsumer;
    private final JButton btnRevert = new JButton("Revert");
    private final JButton btnDelete = new JButton("Delete");
    private final JButton btnSave = new JButton("Save");
    private final JComboBox<String> logLevel = new JComboBox<>(new String[]{"NONE", "ERROR","INFO", "DEBUG", "VERBOSE"});

    public enum Action {
        UPDATE,
        SAVE,
        DELETE
    }

    public ScriptPanel(ScriptRef scriptRef, BiConsumer<ScriptRef, Action> scriptRefChangeConsumer) {
        setName(scriptRef.getName());
        scrollPane = new JScrollPane(this, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        this.scriptRef = scriptRef;
        this.scriptRefChangeConsumer = scriptRefChangeConsumer;
        this.logLevel.setSelectedIndex(1);
        this.logLevel.setToolTipText("Log level");
    }

    private void setValues() {
        try {
            updateObject=false;
            enabled.setSelected(scriptRef.isEnabled());
            tfName.setText(scriptRef.getName());
//            tfDesc.setText(scriptRef.getDescription());

            requestScript.setText(scriptRef.getScriptRequest());
            responseScript.setText(scriptRef.getScriptResponse());
            cbScope.setSelected(scriptRef.isInScope());
            cbProxy.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_PROXY) != 0);
            cbSpider.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SPIDER) != 0);
            cbScanner.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SCANNER) != 0);
            cbIntruder.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_INTRUDER) != 0);
            cbRepeater.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_REPEATER) != 0);
            cbSequencer.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SEQUENCER) != 0);
            cbExtension.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_EXTENDER) != 0);
            cbSessionHandling.setSelected(scriptRef.isSessionHandling());
            cbIntruder.setEnabled(!scriptRef.isSessionHandling());
            cbProxy.setEnabled(!scriptRef.isSessionHandling());
            cbRepeater.setEnabled(!scriptRef.isSessionHandling());
            cbScanner.setEnabled(!scriptRef.isSessionHandling());
            cbSequencer.setEnabled(!scriptRef.isSessionHandling());
            cbExtension.setEnabled(!scriptRef.isSessionHandling());
            cbSpider.setEnabled(!scriptRef.isSessionHandling());
        } finally {
            updateObject=true;
        }
    }

    public void refresh() {
        SwingUtilities.invokeLater(this::setValues);
    }

    public JScrollPane getScrollPane() {
        return scrollPane;
    }

    @Override
    public void componentShown(ComponentEvent e) {
    }

    @Override
    public void componentHidden(ComponentEvent e) {
    }

    @Override
    public void componentMoved(ComponentEvent e) {

    }

    @Override
    public void componentResized(ComponentEvent e) {
        Dimension parentSize = getParent().getSize();
        Dimension d;
        int width = (int)parentSize.getWidth();
        int height = (int)parentSize.getHeight();
        d = new Dimension(width - 10, height - vSplitPane.getY() - 10);
        SwingUtilities.invokeLater(()-> ScriptPanel.this.vSplitPane.setPreferredSize(d));
    }

    /*private class ScriptComponentListener implements ComponentListener {
    }*/

    private class ScriptDocumentListener implements DocumentListener {
        @Override
        public void insertUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            update();
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            update();
        }

        public void update() {
            if (updateObject) {
                scriptRef.setName(tfName.getText());
//                scriptRef.setDescription(tfDesc.getText());
                scriptRef.setScriptError(false);
                scriptRef.setScriptResponse(responseScript.getText());
                scriptRef.setScriptRequest(requestScript.getText());
                scriptRef.setSessionHandling(cbSessionHandling.isSelected());
                scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
            }
        }
    }

    private void changeTools(int tools, boolean enabled) {
        if (enabled) {
            tools = scriptRef.getTools() | tools;
        } else {
            tools = scriptRef.getTools() & (tools ^ 0xFFFFFFFF);
        }
        scriptRef.setTools(tools);
        SwingUtilities.invokeLater(()-> scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE));
    }

    public void buildUi() {
        int maxColumn = 9;
        int line = 0;
        setLayout(new GridBagLayout());
        add(enabled, new GridBagConstraints(0, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbScope, new GridBagConstraints(1, line, 2, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(logLevel, new GridBagConstraints(3, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));

        JPanel savePanel = new JPanel();
        savePanel.setLayout(new FlowLayout());
        savePanel.add(btnRevert);
        savePanel.add(btnDelete);
        savePanel.add(btnSave);
        add(savePanel, new GridBagConstraints(4, line, maxColumn - 5, 1, 0.0, 0.0
                , LINE_END, NONE, new Insets(2, 2, 2, 2), 5, 5));

        add(labIntercept, new GridBagConstraints(0, ++line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        addComponent(line, 1, cbProxy, cbSpider, cbScanner, cbIntruder, cbRepeater, cbSequencer, cbExtension);
        line = addTextFieldWithLabel(maxColumn, line, labelName, tfName);
        add(cbSessionHandling, new GridBagConstraints(0, ++line, maxColumn, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
//        line = addTextFieldWithLabel(maxColumn, line, labelDesc, tfDesc);
        add(color, new GridBagConstraints(0, ++line, maxColumn, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        requestScript.setBorder(BorderFactory.createTitledBorder("Request script"));
        responseScript.setBorder(BorderFactory.createTitledBorder("Response script"));
        errorPane.setContentType("text/html");
        hSplitPane.setResizeWeight( 0.5 );
        vSplitPane.setResizeWeight(0.8);

        add(vSplitPane, new GridBagConstraints(0, ++line, maxColumn, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(2, 2, 2, 2), 5, 5));
        setValues();
        enabled.addItemListener(e->{
            scriptRef.setEnabled(enabled.isSelected());
            scriptRef.setScriptError(false);
            scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
        });
        cbScope.addItemListener(e-> {
            scriptRef.setInScope(cbScope.isSelected());
            scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
        });
        cbSessionHandling.addItemListener(e-> {
            scriptRef.setSessionHandling(cbSessionHandling.isSelected());
            SwingUtilities.invokeLater(()->{
                responseScript.setVisible(!cbSessionHandling.isSelected());
                if (!cbSessionHandling.isSelected()) {
                    hSplitPane.setResizeWeight(0.5);
                    hSplitPane.resetToPreferredSizes();
                    cbIntruder.setEnabled(true);
                    cbProxy.setEnabled(true);
                    cbRepeater.setEnabled(true);
                    cbScanner.setEnabled(true);
                    cbSequencer.setEnabled(true);
                    cbExtension.setEnabled(true);
                    cbSpider.setEnabled(true);
                } else {
                    cbIntruder.setEnabled(false);
                    cbProxy.setEnabled(false);
                    cbRepeater.setEnabled(false);
                    cbScanner.setEnabled(false);
                    cbSequencer.setEnabled(false);
                    cbExtension.setEnabled(false);
                    cbSpider.setEnabled(false);
                }

            });
            scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
        });

        cbProxy.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_PROXY, cbProxy.isSelected()));
        cbSpider.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SPIDER, cbSpider.isSelected()));
        cbScanner.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SCANNER, cbScanner.isSelected()));
        cbIntruder.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_INTRUDER, cbIntruder.isSelected()));
        cbRepeater.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_REPEATER, cbRepeater.isSelected()));
        cbSequencer.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SEQUENCER, cbSequencer.isSelected()));
        cbExtension.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_EXTENDER, cbExtension.isSelected()));

        tfName.getDocument().addDocumentListener(documentListener);
//        tfDesc.getDocument().addDocumentListener(documentListener);
        requestScript.addDocumentListener(documentListener);
        responseScript.addDocumentListener(documentListener);

        color.addItemListener(e-> SwingUtilities.invokeLater(()-> {
            requestScript.setColored(!color.isSelected());
            responseScript.setColored(!color.isSelected());
        }));

        addComponentListener(this);
        getParent().addComponentListener(this);
        btnRevert.addActionListener(l-> SwingUtilities.invokeLater(()->{
            boolean revert = JOptionPane.showConfirmDialog(this, "Are you sure you want to revert your changes ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
            if (revert) {
                scriptRef.restore();
                scriptRef.backup();
                setValues();
                scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
            }
        }));
        btnSave.addActionListener(l-> SwingUtilities.invokeLater(()->{
            boolean save = JOptionPane.showConfirmDialog(this, "Are you sure you want to save your changes ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
            if (save) {
                scriptRefChangeConsumer.accept(scriptRef, Action.SAVE);
            }
        }));
        btnDelete.addActionListener(l-> SwingUtilities.invokeLater(()->{
            boolean delete = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this script ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
            if (delete) {
                scriptRefChangeConsumer.accept(scriptRef, Action.DELETE);
            }
        }));
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem clear = new JMenuItem(new AbstractAction("Clear content") {
            @Override
            public void actionPerformed(ActionEvent e) {
                synchronized (contentQueue) {
                    contentQueue.clear();
                    contentQueueModified = true;
                }
                refreshLog();
            }
        });
        popupMenu.add(clear);
        errorPane.setComponentPopupMenu(popupMenu);
    }

    private int addTextFieldWithLabel(int maxColumn, int line, JLabel labelName, JTextField tfName) {
        add(labelName, new GridBagConstraints(0, ++line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(tfName, new GridBagConstraints(1, line, maxColumn-2, 1, 1.0, 0.0
                , LINE_START, BOTH, new Insets(2, 2, 2, 2), 5, 5));
        return line;
    }

    private void addComponent(int line, int column, Component ...components) {
        for (Component c: components) {
            add(c, new GridBagConstraints(column++, line, 1, 1, 0.0, 0.0
                    , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        }
    }

    public int getLogLevel() {
        return logLevel.getSelectedIndex();
    }

    public void refreshLog() {
        if (contentQueueModified) {
            SwingUtilities.invokeLater(()->{
                StringBuilder sb = new StringBuilder();
                sb.append("<html><body>");
                synchronized (contentQueue) {
                    contentQueue.forEach(sb::append);
                    contentQueueModified = false;
                }
                sb.append("</body></html>");
                this.errorPane.setText(sb.toString());
            });
        }
    }
    public void addLog(CharSequence content) {
        synchronized (contentQueue) {
            while (contentQueue.size()>1000) {
                contentQueue.removeFirst();
            }
            contentQueue.addLast(content);
            contentQueueModified = true;
        }
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
