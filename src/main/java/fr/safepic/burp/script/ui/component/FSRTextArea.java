package fr.safepic.burp.script.ui.component;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import java.awt.*;

public class FSRTextArea extends RSyntaxTextArea {
    public FSRTextArea() {
    }
    public FSRTextArea(int rows, int cols) {
        super(rows, cols);
    }
    public void setFont(Font font) {
        super.setFont(new Font("monospaced", Font.PLAIN, 16));
    }
}
