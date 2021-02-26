package fr.safepic.burp.script.ui.component;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;

public class MyTextArea extends JPanel {
    private final RSyntaxTextArea coloredArea = new FSRTextArea(15, 80);
    private final JTextArea  normalArea = new FSJTextArea(15, 80);
    private final CardLayout layout = new CardLayout();
    private boolean colored = true;



    public MyTextArea(String name) {
        setName(name);
        setLayout(layout);
        coloredArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        RTextScrollPane coloredAreaSP = new RTextScrollPane(coloredArea);
        add(coloredAreaSP, "colored");
        JScrollPane normalAreaSP = new JScrollPane(normalArea);
        add(normalAreaSP, "normal");
        layout.show(this, "colored");

        normalArea.getDocument().addDocumentListener(new ScriptDocumentListener(false));
        coloredArea.getDocument().addDocumentListener(new ScriptDocumentListener(true));
    }
    public void addDocumentListener(DocumentListener listener) {
        listenerList.add(DocumentListener.class, listener);
    }


    private class ScriptDocumentListener implements DocumentListener {
        private final boolean fireWhenColored;
        ScriptDocumentListener(boolean fireWhenColored){
            this.fireWhenColored = fireWhenColored;
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.insertUpdate(e);
                }
            }
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.removeUpdate(e);
                }
            }
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.changedUpdate(e);
                }
            }
        }
    }

    public void setColored(boolean b) {
        String currentValue = getText();
        colored = b;
        layout.show(this, b ? "colored" : "normal");
        setText(currentValue);
    }


    public String getText() {
        return colored ? coloredArea.getText() : normalArea.getText();
   }

    public void setText(String txt) {
        if (colored) {
            coloredArea.setText(txt);
        } else {
            normalArea.setText(txt);
        }
    }

}
