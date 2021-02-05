package fr.safepic.burp.ui.common;


import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.ArrayList;
import java.util.HashMap;

import static java.awt.GridBagConstraints.LINE_START;
import static java.awt.GridBagConstraints.NONE;

public class CheckBoxesPanel extends JPanel {
    protected boolean enabled = true;
    protected ArrayList<CheckBoxValue> checkBoxes = new ArrayList<>();
    protected JCheckBox enableCB;
    protected int lastLine;

    public CheckBoxesPanel(String label) {
        enableCB = new JCheckBox("Enable "+label);
        setName(label);
//        setBorder(BorderFactory.createTitledBorder(label));
        setLayout(new GridBagLayout());
        add(enableCB, new GridBagConstraints(0, 0, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        enableCB.addItemListener(e->{
            if (e.getStateChange() == ItemEvent.SELECTED) {
                checkBoxes.forEach(cbv->cbv.enable(enableCB));
            } else {
                checkBoxes.forEach(cbv->cbv.disable(enableCB));
            }
        });


    }
    public void add(Component comp, Object constraints) {
        if (constraints instanceof GridBagConstraints) {
            lastLine=Math.max(lastLine, ((GridBagConstraints) constraints).gridy);
        }
        super.add(comp, constraints);
    }

    public void updateFieldName(boolean lowercaseHeader, boolean exploitOFT) {
        checkBoxes.forEach(cb->cb.computeFieldName(lowercaseHeader, exploitOFT));
    }


    public CheckBoxValue add(int x, int y, String fieldName, String defaultValue, boolean selected) {
        CheckBoxValue cbv = new CheckBoxValue(fieldName, selected, defaultValue);
        cbv.add(this,x, y);
        checkBoxes.add(cbv);
        cbv.disable(null);
        lastLine = Math.max(y, lastLine);
        return cbv;
    }

    public void fillHeader(HashMap<String, String> headers) {
        if (enabled && enableCB.isSelected()) {
            checkBoxes.forEach(cb->cb.addIfActive(headers));
        }

    }
    public void setEnabled(boolean enabled) {
        this.enabled=enabled;
        computeEnabled();

    }
    public void computeEnabled()  {
        if (enabled) {
            enableCB.setEnabled(true);
            checkBoxes.forEach(cb->cb.enable(CheckBoxesPanel.this));
        } else {
            enableCB.setEnabled(false);
            checkBoxes.forEach(cb->cb.disable(CheckBoxesPanel.this));
        }
        if (enableCB.isSelected()) {
            checkBoxes.forEach(cb->cb.enable(enableCB));
        } else {
            checkBoxes.forEach(cb->cb.disable(enableCB));
        }



    }

}
