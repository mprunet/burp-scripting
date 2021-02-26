package fr.safepic.burp.ui;

import burp.IBurpExtenderCallbacks;
import fr.safepic.burp.ui.common.MyTextArea;
import fr.safepic.burp.ui.scripts.ScriptRef;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Style;
import java.awt.*;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedList;
import java.util.Objects;
import java.util.function.BiConsumer;

import static java.awt.GridBagConstraints.*;


public class Script2Panel extends JPanel implements Scrollable {
    private boolean displayed;
    private JCheckBox enabled = new JCheckBox("Enabled");
    private JCheckBox cbScope = new JCheckBox("In Scope Only");
    private JLabel labIntercept = new JLabel("Intercept from : ");
    private JCheckBox cbProxy = new JCheckBox("Proxy");
    private JCheckBox cbSpider = new JCheckBox("Spider");
    private JCheckBox cbScanner = new JCheckBox("Scanner");
    private JCheckBox cbIntruder = new JCheckBox("Intruder");
    private JCheckBox cbRepeater = new JCheckBox("Repeater");
    private JCheckBox cbSequencer = new JCheckBox("Sequencer");
    //private JCheckBox cbSaveInProject = new JCheckBox("Store in project");
    private JLabel labelName = new JLabel("Name: ");
    private JTextField tfName = new JTextField(20);
    private JLabel labelDesc = new JLabel("Description: ");
    private JTextField tfDesc = new JTextField(20);
    private JCheckBox color = new JCheckBox("Disable syntax coloration (bugfix when plugin is reloaded)");
    private MyTextArea requestScript = new MyTextArea("request");
    private MyTextArea responseScript = new MyTextArea("response");
    private JTextPane errorPane = new JTextPane();
    private JSplitPane hSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScript, responseScript);
    private JSplitPane vsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, hSplitPane, new JScrollPane(errorPane));
    private LinkedList<CharSequence> contentQueue = new LinkedList<>();
    private ScriptComponentListener listener = new ScriptComponentListener();
    private ScriptDocumentListener documentListener = new ScriptDocumentListener();
    private boolean updateObject=true;
    private Style styleRouge;
    private ScriptRef scriptRef;

    private JScrollPane scrollPane;
    private BiConsumer<ScriptRef, Action> scriptRefChangeConsumer;
    private JButton btnRevert = new JButton("Revert");
    private JButton btnDelete = new JButton("Delete");
    private JButton btnSave = new JButton("Save");

    public enum Action {
        UPDATE,
        SAVE,
        DELETE
    }

    public Script2Panel(ScriptRef scriptRef, BiConsumer<ScriptRef, Action> scriptRefChangeConsumer) {
        setName(scriptRef.getName());
        scrollPane = new JScrollPane(this, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        this.scriptRef = scriptRef;
        this.scriptRefChangeConsumer = scriptRefChangeConsumer;
    }

    private void setValues() {
        try {
            updateObject=false;
            enabled.setSelected(scriptRef.isEnabled());
            tfName.setText(scriptRef.getName());
            tfDesc.setText(scriptRef.getDescription());
            requestScript.setText(scriptRef.getScriptRequest());
            responseScript.setText(scriptRef.getScriptResponse());
            cbScope.setSelected(scriptRef.isInScope());
            cbProxy.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_PROXY) != 0);
            cbSpider.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SPIDER) != 0);
            cbScanner.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SCANNER) != 0);
            cbIntruder.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_INTRUDER) != 0);
            cbRepeater.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_REPEATER) != 0);
            cbSequencer.setSelected((scriptRef.getTools() & IBurpExtenderCallbacks.TOOL_SEQUENCER) != 0);
        } finally {
            updateObject=true;
        }
    }

    public void refresh() {
        SwingUtilities.invokeLater(()-> {
            setValues();
        });
    }

    public JScrollPane getScrollPane() {
        return scrollPane;
    }
    private class ScriptComponentListener implements ComponentListener {
        @Override
        public void componentShown(ComponentEvent e) {
            displayed=true;
            synchronized (contentQueue) {
                displayLog();
            }
            componentResized(e);
        }

        @Override
        public void componentHidden(ComponentEvent e) {
            displayed=false;
        }

        @Override
        public void componentMoved(ComponentEvent e) {

        }

        @Override
        public void componentResized(ComponentEvent e) {
            Dimension parentSize = getParent().getSize();
            System.out.println("Conteneur "  + parentSize);
            Dimension d;
            int width = (int)parentSize.getWidth();
            int height = (int)parentSize.getHeight();
            d = new Dimension(width - 10, height - vsplitPane.getY() - 10);
            System.out.println(d);
            SwingUtilities.invokeLater(()->{
                Script2Panel.this.vsplitPane.setPreferredSize(d);
            });
        }
    }

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
                scriptRef.setDescription(tfDesc.getText());
                scriptRef.setScriptResponse(responseScript.getText());
                scriptRef.setScriptRequest(requestScript.getText());
                scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
            }
        }
    }

    private void changeTools(int tools, boolean enabled) {
        if (enabled) {
            tools = scriptRef.getTools() | tools;
        } else {
            tools = scriptRef.getTools() & (0xFFFFFFFF & tools);
        }
        scriptRef.setTools(tools);
        SwingUtilities.invokeLater(()->{
            scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
        });
    }

    public void buildUi() {
        int maxColumn = 9;
        int line = 0;
        setLayout(new GridBagLayout());
        add(enabled, new GridBagConstraints(0, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbScope, new GridBagConstraints(1, line, 2, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));

        JPanel savePanel = new JPanel();
        savePanel.setLayout(new FlowLayout());
        //savePanel.add(cbSaveInProject);
        savePanel.add(btnRevert);
        savePanel.add(btnDelete);
        savePanel.add(btnSave);
        add(savePanel, new GridBagConstraints(2, line, maxColumn - 2, 1, 0.0, 0.0
                , LINE_END, NONE, new Insets(2, 2, 2, 2), 5, 5));

        int column = 0;
        add(labIntercept, new GridBagConstraints(column, ++line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbProxy, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbSpider, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbScanner, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbIntruder, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbRepeater, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(cbSequencer, new GridBagConstraints(++column, line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(labelName, new GridBagConstraints(0, ++line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(tfName, new GridBagConstraints(1, line, maxColumn-1, 1, 1.0, 0.0
                , LINE_START, BOTH, new Insets(2, 2, 2, 2), 5, 5));
        add(labelDesc, new GridBagConstraints(0, ++line, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        add(tfDesc, new GridBagConstraints(1, line, maxColumn-1, 1, 1.0, 0.0
                , LINE_START, BOTH, new Insets(2, 2, 2, 2), 5, 5));
        add(color, new GridBagConstraints(0, ++line, maxColumn, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        requestScript.setBorder(BorderFactory.createTitledBorder("Request script"));
        responseScript.setBorder(BorderFactory.createTitledBorder("Response script"));
        /*JPanel requestResponsePanel = new JPanel();
        requestResponsePanel.setLayout(new WrapLayout());
        requestResponsePanel.add(requestScript);
        requestResponsePanel.add(responseScript);*/
        errorPane.setContentType("text/html");
        hSplitPane.setResizeWeight( 0.5 );
        vsplitPane.setResizeWeight(0.8);

        /*        add(requestScript, new GridBagConstraints(0, lastLine+1, 8, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(30, 2, 2, 2), 5, 5));
        add(responseScript, new GridBagConstraints(8, lastLine, 1, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(30, 2, 2, 2), 5, 5));*/
        add(vsplitPane, new GridBagConstraints(0, ++line, maxColumn, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(2, 2, 2, 2), 5, 5));
        setValues();
        enabled.addItemListener(e->{
            scriptRef.setEnabled(enabled.isSelected());
            SwingUtilities.invokeLater(()->{
                scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
            });
        });
        cbScope.addItemListener(e->{
            scriptRef.setInScope(cbScope.isSelected());
        });
        cbProxy.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_PROXY, cbProxy.isSelected()));
        cbSpider.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SPIDER, cbSpider.isSelected()));
        cbScanner.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SCANNER, cbScanner.isSelected()));
        cbIntruder.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_INTRUDER, cbIntruder.isSelected()));
        cbRepeater.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_REPEATER, cbRepeater.isSelected()));
        cbSequencer.addItemListener(e->changeTools(IBurpExtenderCallbacks.TOOL_SEQUENCER, cbSequencer.isSelected()));

        tfName.getDocument().addDocumentListener(documentListener);
        tfDesc.getDocument().addDocumentListener(documentListener);
        requestScript.addDocumentListener(documentListener);
        responseScript.addDocumentListener(documentListener);

        color.addItemListener(e->{
            SwingUtilities.invokeLater(()-> {
                requestScript.setColored(!color.isSelected());
                responseScript.setColored(!color.isSelected());
            });
        });

        addComponentListener(listener);
        getParent().addComponentListener(listener);
        btnRevert.addActionListener(l->{
            SwingUtilities.invokeLater(()->{
                boolean revert = JOptionPane.showConfirmDialog(this, "Are you sure you want to revert your changes ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
                if (revert) {
                    scriptRef.restore();
                    scriptRef.backup();
                    setValues();
                    scriptRefChangeConsumer.accept(scriptRef, Action.UPDATE);
                }
            });

        });
        btnSave.addActionListener(l->{
            SwingUtilities.invokeLater(()->{
                boolean save = JOptionPane.showConfirmDialog(this, "Are you sure you want to save your changes ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
                if (save) {
                    scriptRefChangeConsumer.accept(scriptRef, Action.SAVE);
                }
            });

        });
        btnDelete.addActionListener(l->{
            SwingUtilities.invokeLater(()->{
                boolean delete = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this script ?", "Confirmation", JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION;
                if (delete) {
                    scriptRefChangeConsumer.accept(scriptRef, Action.DELETE);
                }
            });

        });
    }

    public void printException(Exception ex) {
        StringWriter sw = new StringWriter();
        try (PrintWriter pw = new PrintWriter(sw)) {
            ex.printStackTrace(pw);
            pw.flush();
        }
        addLog("<span style=\"color:red\">ERROR : <br>","</span>",sw.toString());
    }
    private StringBuilder htmlEncode(String content, StringBuilder sb) {
        if (sb == null) {
            sb = new StringBuilder();
        }
        char c;
        for (int i = 0; i<content.length();i++) {
            c = content.charAt(i);
            switch (c) {
                case '&':
                    sb.append("&amp;");
                    break;
                case '"':
                    sb.append("&quot;");
                    break;
                case '\'':
                    sb.append("&#39;");
                    break;
                case '>':
                    sb.append("&gt;");
                    break;
                case '<':
                    sb.append("&lt;");
                    break;
                case '\n':
                    sb.append("<br>");
                    break;
                default:
                    sb.append(c);
            }
        }
        sb.append("<br>");
        return sb;

    }

    public void printLn(String content) {
        addLog("", "", content);
    }

    private void displayLog() {
        SwingUtilities.invokeLater(()->{
            StringBuilder sb = new StringBuilder();
            sb.append("<html><body>");
            synchronized (contentQueue) {
                contentQueue.forEach(sb::append);
            }
            sb.append("</body></html>");
            this.errorPane.setText(sb.toString());
        });
    }

    public void addLog(String prefix, String suffix, String content) {
        synchronized (contentQueue) {
            while (contentQueue.size()>1000) {
                contentQueue.removeFirst();
            }
            contentQueue.addLast(htmlEncode(content, null).toString());
        }
        if (displayed) {
            displayLog();
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
