package fr.safepic.burp.script.ui.model;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.util.List;

public class ScriptTableModel extends AbstractTableModel implements TableCellRenderer {
    private final DefaultTableCellRenderer DEFAULT_RENDERER = new DefaultTableCellRenderer();
    private volatile Color defaultBackgroundColor;

    private final List<ScriptRef> scripts;

    public ScriptTableModel(List<ScriptRef> scripts) {
        this.scripts =scripts;
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return columnIndex == 0;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "Enabled";
            case 1:
                return "Scope Only";
            case 2:
                return "Name";
            case 3:
                return "Description";
            case 4:
                return "State";
            default:
                return null;
        }
    }

    @Override
    public int getRowCount() {
        return scripts.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        switch (columnIndex) {
            case 0:
            case 1:
                return Boolean.class;
            case 2:
            case 3:
            case 4:
                return String.class;
            default:
                return null;
        }
    }

    public void fireDataChanged(ScriptRef sr) {
        int idx = scripts.indexOf(sr);
        for (int i = 0; i<getColumnCount();i++) {
            fireTableCellUpdated(idx,i);
        }
    }

    @Override
    public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
        ScriptRef ref = scripts.get(rowIndex);
        switch (columnIndex) {
            case 0:
                ref.setEnabled((Boolean)aValue);
                if (Boolean.TRUE.equals(aValue)) {
                    ref.setScriptError(false);
                }
                break;
        }
        if (ref.getPanel() != null) {
            ref.getPanel().refresh();
        }
    }

    public ScriptRef getValueAt(int rowIndex) {
        return scripts.get(rowIndex);
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        ScriptRef ref = scripts.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return ref.isEnabled() && !ref.isScriptError();
            case 1:
                return ref.isInScope();
            case 2:
                return ref.getName();
            case 3:
                return ref.getDescription();
            case 4:
                boolean savedGlobally = ref.isSavedGlobally();
                return savedGlobally ? (ref.needsSave()  ? "Changes will be lost" : "Saved") : "Not saved";

            default:
                return null;
        }
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        Component c = DEFAULT_RENDERER.getTableCellRendererComponent(table, value, false, hasFocus, row, column);
        if (defaultBackgroundColor == null) {
            synchronized (this) {
                if (defaultBackgroundColor == null) {
                    defaultBackgroundColor = c.getBackground();
                }
            }
        }
        if (c instanceof JLabel) {
            JLabel tf =(JLabel)c;
            if (column == 3) {
                tf.setHorizontalAlignment(JTextField.CENTER);
            } else {
                tf.setHorizontalAlignment(JTextField.LEFT);
            }

        }
        Color color = defaultBackgroundColor;
        if (column == 3) {
            ScriptRef sr = getValueAt(row);
            if (!sr.isSavedGlobally()) {
                color = Color.CYAN;
            } else if (sr.needsSave()) {
                color = Color.RED;
            }
        }
        c.setBackground(color);
        return c;
    }
}
