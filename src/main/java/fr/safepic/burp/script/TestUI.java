package fr.safepic.burp.script;

import fr.safepic.burp.script.ui.panel.TabbedPanel;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestUI {
    public static void main(String[] args) throws IOException {
/*        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in))) {
            while(true){*/
                JFrame frame = new JFrame();
                frame.setContentPane(new TabbedPanel());
                frame.setSize(800, 800);
                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                frame.setVisible(true);
/*                br.readLine();
            }
        }*/

    }
}
