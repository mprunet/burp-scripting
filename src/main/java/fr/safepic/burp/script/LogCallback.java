package fr.safepic.burp.script;

import fr.safepic.burp.script.ui.panel.ScriptPanel;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;

public class LogCallback {
    private final ScriptPanel panel;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private final List<Message> messageList = new ArrayList<>();
    private final int level;

    private static class Message {
        boolean error;
        String message;
        Throwable exception;

        public Message(Throwable exception) {
            this.error = true;
            this.exception = exception;
        }
        public Message(boolean error, String message) {
            this.error = error;
            this.message = message;
        }
    }

    public LogCallback(ScriptPanel panel, PrintWriter stdout, PrintWriter stderr) {
        this.panel = panel;
        this.stdout = stdout;
        this.stderr = stderr;
        this.level = panel == null ? 1 : panel.getLogLevel();
    }

    public void flush() {
        for (Message msg : messageList) {
            if (msg.error) {
                if (panel == null) {
                    if (msg.message != null) {
                        stderr.println(msg.message);
                    } else {
                        msg.exception.printStackTrace(stderr);
                    }
                } else {
                    if (msg.message != null) {
                        panel.addLog(htmlEncode("<span style=\"color:red\">", msg.message, "</span><br>"));
                    } else {
                        StringWriter sw = new StringWriter();
                        try (PrintWriter pw = new PrintWriter(sw)) {
                            msg.exception.printStackTrace(pw);
                            pw.flush();
                        }
                        panel.addLog(htmlEncode("<span style=\"color:red\">Exception : ", sw.toString(), "</span><br>"));
                    }
                }
            } else {
                if (panel == null) {
                    stdout.println(msg.message);
                } else {
                    panel.addLog(htmlEncode("", msg.message, "<br>"));
                }
            }
        }
    }

    private CharSequence htmlEncode(String prefix, String content, String suffix) {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);
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
        sb.append(suffix);
        return sb;

    }



    public void exception(Throwable ex) {
        if (level>=1) {
            messageList.add(new Message(ex));
        }
    }


    public void trace(String s) {
        if (level>=4) {
            messageList.add(new Message(false, "TRACE : " + s));
        }
    }

    public void debug(String s) {
        if (level>=3) {
            messageList.add(new Message(false, "DEBUG : " + s));
        }
    }

    public void info(String s) {
        if (level>=2) {
            messageList.add(new Message(false, "INFO : " + s));
        }
    }

    public void error(String s) {
        if (level>=1) {
            messageList.add(new Message(true, "ERROR : " + s));
        }
    }

}
