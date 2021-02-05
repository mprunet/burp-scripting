package fr.safepic.burp.ui.common;

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
/*        if (font.getSize() != 16f) {
            font = font.deriveFont(16f);
        }
        super.setFont(font);*/

    }
}
