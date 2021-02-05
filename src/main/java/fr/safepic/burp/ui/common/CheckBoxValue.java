package fr.safepic.burp.ui.common;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.awt.GridBagConstraints.HORIZONTAL;
import static java.awt.GridBagConstraints.LINE_START;
import static java.awt.GridBagConstraints.NONE;

public class CheckBoxValue {
    Set<Component> disabledStack = new HashSet<>();
    String defaultValue;
    String fieldName;
    JCheckBox cb;
    JTextField tf;
    int x;
    int y;

    public CheckBoxValue(String fieldName, boolean selected, String defaultValue) {
        this.defaultValue = defaultValue;
        tf = new JTextField();
        tf.setText(defaultValue == null ? "" : defaultValue);
        tf.setColumns(20);
        this.fieldName = fieldName;
        cb = new JCheckBox(fieldName + " : ");
        cb.setName(fieldName+"_cb");
        cb.setSelected(selected);
        setEnabled(cb, selected);
        cb.addItemListener(e-> setEnabled(cb, e.getStateChange() == ItemEvent.SELECTED));
        tf.setName(fieldName+"_value");
    }

    public void add(JComponent component, int x, int y) {
        this.x = x;
        this.y = y;
        component.add(cb, new GridBagConstraints(x, y, 1, 1, 0.0, 0.0
                , LINE_START, NONE, new Insets(2, 2, 2, 2), 5, 5));
        component.add(tf, new GridBagConstraints(x-1, y, 3, 1, 1.0, 0.0
                , LINE_START, HORIZONTAL, new Insets(2, 2, 2, 2), 5, 5));

    }

    public void remove(JComponent component) {
        component.remove(cb);
        component.remove(tf);
    }

    public void setEnabled(Component component, boolean enabled) {
        if (enabled) {
            enable(component);
        } else {
            disable(component);
        }
    }

    public void disable(Component component) {
        if (component != null) {
            disabledStack.add(component);
        }
        if (cb != component) {
            cb.setEnabled(false);
        }
        tf.setEnabled(false);
    }
    public void enable(Component component) {
        disabledStack.remove(component);
        cb.setEnabled(disabledStack.isEmpty() || (disabledStack.size()==1 && disabledStack.contains(cb)));
        tf.setEnabled(disabledStack.isEmpty() && cb.isSelected());
    }

    public void computeFieldName(boolean lowercaseHeader, boolean exploitOFT) {
        if (lowercaseHeader) {
            fieldName = fieldName.toLowerCase();
        } else {
            fieldName = fieldName.toUpperCase();
        }
        if (exploitOFT) {
            fieldName = fieldName.replace('_','-');
        } else {
            fieldName = fieldName.replace('-','_');
        }
        if (cb != null) {
            cb.setText(fieldName);
        }
    }

    public void addIfActive(Map<String, String> map) {
        if (cb.isSelected()) {
            map.put(fieldName, tf.getText());
        }
    }

    public int getX() {
        return x;
    }

    public int getY() {
        return y;
    }

    public String getValue() {
        return cb.isSelected() ? tf.getText().trim() : null;
    }
/*
    private String emptyToNull(String s){
        if (s==null) {
            return s;
        } else {
            s = s.trim();
            return "".equals(s) ? null : s;
        }
    }*/

    public void setValue(String value) {
        cb.setSelected(value != null);
        if (value != null) {
            tf.setText(value.trim());
        }
    }

    public String getFieldName() {
        return fieldName;
    }
}