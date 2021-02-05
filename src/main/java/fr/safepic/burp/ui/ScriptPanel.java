package fr.safepic.burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditorController;
import fr.safepic.burp.ui.common.MyTextArea;
import fr.safepic.burp.ui.common.PluginPanel;

import javax.swing.*;
import javax.swing.text.Style;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.LinkedList;

import static java.awt.GridBagConstraints.*;


public class ScriptPanel extends PluginPanel implements IMessageEditorController {
    private IBurpExtenderCallbacks callbacks;
    private JTabbedPane tabbedPane = new JTabbedPane();
    private JCheckBox color = new JCheckBox("Disable syntax coloration (bugfix when plugin is reloaded)");
    private MyTextArea requestScript = new MyTextArea("request");
    private MyTextArea responseScript = new MyTextArea("response");
    private JTextPane errorPane = new JTextPane();
    private LinkedList<CharSequence> contentQueue = new LinkedList<>();

    private Style styleRouge;
    public ScriptPanel(IBurpExtenderCallbacks callbacks, String name, JTabbedPane tabbedPane) {
        super(name, tabbedPane);
        this.callbacks = callbacks;
        buildUi();
    }


    public void buildUi() {
        add(color, new GridBagConstraints(0, lastLine+1, 7, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));


        color.addItemListener(e->{
            requestScript.setColored(!color.isSelected());
            responseScript.setColored(!color.isSelected());
        });
        requestScript.setBorder(BorderFactory.createTitledBorder("Request script"));
        responseScript.setBorder(BorderFactory.createTitledBorder("Response script"));
        /*JPanel requestResponsePanel = new JPanel();
        requestResponsePanel.setLayout(new WrapLayout());
        requestResponsePanel.add(requestScript);
        requestResponsePanel.add(responseScript);*/
        errorPane = new JTextPane();
        errorPane.setContentType("text/html");


        JSplitPane hSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScript, responseScript);
        hSplitPane.setResizeWeight( 0.5 );
        JSplitPane vsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, hSplitPane, new JScrollPane(errorPane));
        vsplitPane.setResizeWeight(0.8);



        getParent().addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                componentResized(e);
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
                    vsplitPane.setPreferredSize(d);
                });
            }
        });

        /*        add(requestScript, new GridBagConstraints(0, lastLine+1, 8, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(30, 2, 2, 2), 5, 5));
        add(responseScript, new GridBagConstraints(8, lastLine, 1, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(30, 2, 2, 2), 5, 5));*/
        add(vsplitPane, new GridBagConstraints(0, lastLine+1, 8, 1, 1.0, 1.0
                , CENTER, BOTH, new Insets(30, 2, 2, 2), 5, 5));
        requestScript.setText("/* Variables exposed \n" +
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
        responseScript.setText("/* Variables exposed \n" +
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

        postConstruct();
    }

    public boolean excludeInSave(Component c) {
        return super.excludeInSave(c) || c == errorPane;
    }
    public void unload() {
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


    public void addLog(String prefix, String suffix, String content) {
        SwingUtilities.invokeLater(()->{
            while (contentQueue.size()>1000) {
                contentQueue.removeFirst();
            }
            contentQueue.addLast(htmlEncode(content, null).toString());
            StringBuilder sb = new StringBuilder();
            sb.append("<html><body>");
            contentQueue.forEach(sb::append);
            sb.append("</body></html>");
            this.errorPane.setText(sb.toString());
        });
    }


    private void addTab(String title, Component content) {
        JPanel arroundPanel = new JPanel();
        arroundPanel.setLayout(new BorderLayout());
        arroundPanel.add(content, BorderLayout.CENTER);
        tabbedPane.addTab(title, arroundPanel);
    }

    public String getRequestScript() {
        return requestScript.getText();
    }

    public String getResponseScript() {
        return responseScript.getText();
    }


    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }
}
