package fr.safepic.burp.ui.common;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

public class CloseableTabbedPane extends JTabbedPane implements MouseListener {
    Map<Component, Supplier<Void>> iconCallback = Collections.synchronizedMap(new HashMap<>());
    Supplier<Void> addListener;

    /**
     * Creates a new instance of ClosableTabbedPane
     */
    public CloseableTabbedPane(String name, JPanel component, Supplier<Void> addListener) {
        super();
        this.addListener = addListener;
        super.addTab(name, new JScrollPane(component, JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED, JScrollPane.HORIZONTAL_SCROLLBAR_NEVER));
        JPanel empty = new JPanel();
        iconCallback.put(empty, addListener);
        super.addTab("", null, empty, "Click here to create new script");
        initializeMouseListener();
        setEnabledAt(1, false);
        setDisabledIconAt(1, new NewTabIcon());
        /*addChangeListener((l)->{
            if (getTabCount() -1 == getSelectedIndex()) {
                addListener.get();
            }
        });*/
    }

    /**
     * Appends a tab without closing-capabilities, just as the standard JTabbedPane would do.
     *
     * @see javax.swing.JTabbedPane#addTab(String title, Component component) addTab
     */
    @Override
    public void addTab(String title, Component component) {
        this.addTab(title, null, component, null, null);
    }

    @Override
    public void addTab(String title, Icon icon, Component component, String tip) {
        this.addTab(title, icon, component, tip, null);
    }

    @Override
    public void addTab(String title, Icon icon, Component component) {
        this.addTab(title, icon, component, null, null);
    }

    /**
     * Appends a tab with or without closing-capabilities, depending on the flag isClosable. If isClosable is true, a
     * close-icon ('X') is displayed left of the title. If extraIcon is not null, it will be displayed between the closing
     * icon (if present) and the tab's title. The extraIcon will be displayed indepently of the closing-icon.
     *
     * @param title Title of this tab.
     * @param component Contents of this tab.
     * @param extraIcon Extra icon to be displayed.
     * @see javax.swing.JTabbedPane#addTab(String title, Component component) addTab
     */
    public void addTab(String title, Icon extraIcon, Component component, String tip, Supplier<Void> iconCallback) {
        if (iconCallback != null) {
            this.iconCallback.put(component, iconCallback);
        }
        if (extraIcon != null) {
            super.insertTab(title, extraIcon, component, tip, getTabCount() - 1);
        } else {
            super.insertTab(title, null, component, null, getTabCount() - 1);
        }
    }

    @Override
    public void removeTabAt(int index) {
        iconCallback.remove(getComponentAt(index));
        super.removeTabAt(index);
    }

    @Override
    public void mouseClicked(MouseEvent evt) {
        int tabIndex = getUI().tabForCoordinate(this, evt.getX(), evt.getY());
        if (tabIndex < 0) {
            return;
        }

        Icon icon = getIconAt(tabIndex);
        if (icon == null) {
            icon = getDisabledIconAt(tabIndex);
        }

        if ((icon == null) || !(icon instanceof ClickableTabIcon)) {
            // This tab is not intended to be closeable.
            return;
        }

        Rectangle rect = ((ClickableTabIcon) icon).getBounds();
        if (rect.contains(evt.getX(), evt.getY())) {
            //the tab is being closed
            Supplier<Void> listener = iconCallback.get(getComponentAt(tabIndex));
            if (listener!=null) {
                listener.get();
            }
        }
    }

    @Override
    public void mouseEntered(MouseEvent evt) {
    }

    @Override
    public void mouseExited(MouseEvent evt) {
    }

    @Override
    public void mousePressed(MouseEvent evt) {
    }

    @Override
    public void mouseReleased(MouseEvent evt) {
    }

    private void initializeMouseListener() {
        addMouseListener(this);
    }
}