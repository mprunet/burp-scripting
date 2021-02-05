package fr.safepic.burp.ui.common;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;

import javax.swing.*;
import javax.swing.text.JTextComponent;
import java.awt.*;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

public interface PreferenceFriendly {
    default boolean excludeInSave(Component c) {
        return false;
    }

    default void save(Preferences prefs, Container component) {
        for (int i = 0; i< component.getComponentCount();i++) {
            Component c = component.getComponent(i);
            String name = c.getName();
            if (excludeInSave(c)) {
                continue;
            }
            if (c instanceof JCheckBox) {
                JCheckBox cb = (JCheckBox)c;
                if (name == null) {
                    name = cb.getText();
                }
                prefs.putBoolean(name, cb.isSelected());
            } else if (c instanceof JTextComponent) {
                JTextComponent tf = (JTextComponent)c;
                if (name != null) {
                    prefs.put(name, tf.getText());
                } else {
                    JOptionPane.showMessageDialog((Component)this, "Impossible to save this field " + prefs.absolutePath()  + " with value " + tf.getText());
                }
            } else if (c instanceof Container) {
                Preferences subPref = c.getName() == null ? prefs : prefs.node(c.getName());
                if (c instanceof JTabbedPane) {
                    subPref.putInt("_selected", ((JTabbedPane)c).getSelectedIndex());
                }
                if (c instanceof PreferenceFriendly) {
                    PreferenceFriendly pf = (PreferenceFriendly) c;
                    pf.save(subPref,  (Container)c);
                } else {
                    save(subPref, (Container)c);
                }
            }
        }
        try {
            prefs.flush();
        } catch (BackingStoreException e) {
            e.printStackTrace();
        }

    }

    default void load(Preferences prefs, Container component) {
        for (int i = 0; i< component.getComponentCount();i++) {
            Component c = component.getComponent(i);
            if (c instanceof RSyntaxTextArea) {
                String s="";
            }
            String name = c.getName();
            if (excludeInSave(c)) {
                continue;
            }
            if (c instanceof JCheckBox) {
                JCheckBox cb = (JCheckBox)c;
                if (name == null) {
                    name = cb.getText();
                }
                //String key = StringToKey.transform(parentName+"."+name);
                cb.setSelected(prefs.getBoolean(name, cb.isSelected()));
            } else if (c instanceof JTextComponent) {
                JTextComponent tf = (JTextComponent)c;
                if (name != null) {
                    tf.setText(prefs.get(name, tf.getText()));
                }
            } else if (c instanceof Container) {
                Preferences subPref = c.getName() == null ? prefs : prefs.node(c.getName());
                if (c instanceof JTabbedPane) {
                    ((JTabbedPane)c).setSelectedIndex(subPref.getInt("_selected",0));
                }
                if (c instanceof PreferenceFriendly) {
                    PreferenceFriendly pf = (PreferenceFriendly) c;
                    pf.load(subPref, (Container)c);
                } else {
                    load(subPref, (Container)c);
                }
            }
        }
    }

}
