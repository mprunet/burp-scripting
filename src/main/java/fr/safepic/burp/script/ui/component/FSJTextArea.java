package fr.safepic.burp.script.ui.component;

import javax.swing.*;
import java.awt.*;

public class FSJTextArea extends JTextArea {
    public FSJTextArea() {
    }
    public FSJTextArea(int rows, int columns) {
        super(rows, columns);
    }

    public void setFont(Font font) {
        super.setFont(new Font("monospaced", Font.PLAIN, 16));
    }
}
