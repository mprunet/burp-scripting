package fr.safepic.burp.ui.common;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Rectangle;
import javax.swing.Icon;

/**
 * Draws an icon representing an "X" in a box. The constructor accepts an icon, which will be placed next (right) to the
 * 'X' icon drawn by this class. If no extra icon is needed, the empty default constructor can be used, or provide
 * "null" as a value for the icon-object.
 *
 * @author mjoellnir
 * @version 1.0
 */
public class CloseTabIcon implements ClickableTabIcon {

    private int xPos;
    private int yPos;
    private int width = 16;
    private int height = 16;
    private final int offsetFrame = 2;
    private final int offsetCross1 = 3;
    private final int offsetCross2 = 4;
    private Icon extraIcon = null;

    /**
     * Creates new "X" Icon.
     */
    public CloseTabIcon() {
    }

    /**
     * Creates new "X" Icon with an extra icon next to it.
     *
     * @param fileIcon the Icon-object to be placed next to this icon.
     * @see javax.swing.Icon
     */
    public CloseTabIcon(Icon fileIcon) {
        extraIcon = fileIcon;
    }

    @Override
    public void paintIcon(Component component, Graphics graphics, int x, int y) {
        setXPos(x);
        setYPos(y);

        Color col = graphics.getColor();

        graphics.setColor(Color.black);

        // prepare coordinates for the frame...
        int frameTop = y + offsetFrame;
        int frameBottom = y + (height - offsetFrame);
        int frameLeft = x + offsetFrame;
        int frameRight = x + (width - offsetFrame);

        // top line of rectangle-frame...
        graphics.drawLine(frameLeft + 2, frameTop, frameRight - 2, frameTop);
        // bottom line of rectangle-frame...
        graphics.drawLine(frameLeft + 2, frameBottom, frameRight - 2, frameBottom);
        // left line of rectangle-frame...
        graphics.drawLine(frameLeft, frameTop + 2, frameLeft, frameBottom - 2);
        // right line of rectangle-frame...
        graphics.drawLine(frameRight, frameTop + 2, frameRight, frameBottom - 2);

        // rounding
        graphics.drawLine(frameLeft + 1, frameTop + 1, frameLeft + 1, frameTop + 1);
        graphics.drawLine(frameRight - 1, frameTop + 1, frameRight - 1, frameTop + 1);
        graphics.drawLine(frameLeft + 1, frameBottom - 1, frameLeft + 1, frameBottom - 1);
        graphics.drawLine(frameRight - 1, frameBottom - 1, frameRight - 1, frameBottom - 1);

        // prepare coordinates for the "X"
        int crossTop1 = frameTop + offsetCross1;
        int crossBottom1 = frameBottom - offsetCross1;
        int crossTop2 = frameTop + offsetCross2;
        int crossBottom2 = frameBottom - offsetCross2;

        int crossRight1 = frameRight - offsetCross1;
        int crossLeft1 = frameLeft + offsetCross1;
        int crossRight2 = frameRight - offsetCross2;
        int crossLeft2 = frameLeft + offsetCross2;

        // first diagonal of "X": top left to bottom right...
        graphics.drawLine(crossLeft1, crossTop1, crossRight1, crossBottom1);
        graphics.drawLine(crossLeft1, crossTop2, crossRight2, crossBottom1);
        graphics.drawLine(crossLeft2, crossTop1, crossRight1, crossBottom2);

        // second diagonal of "X": top right to bottom left...
        graphics.drawLine(crossRight1, crossTop1, crossLeft1, crossBottom1);
        graphics.drawLine(crossRight1, crossTop2, crossLeft2, crossBottom1);
        graphics.drawLine(crossRight2, crossTop1, crossLeft1, crossBottom2);

        graphics.setColor(col);

        if (extraIcon != null) {
            extraIcon.paintIcon(component, graphics, x + getWidth(), y + 2);
        }
    }

    @Override
    public int getIconWidth() {
        return getWidth() + (extraIcon != null ? extraIcon.getIconWidth() : 0);
    }

    @Override
    public int getIconHeight() {
        return getHeight();
    }


    /**
     * Returns the x-coordinate of the position of this icon.
     *
     * @return the x-coordinate of the position of this icon.
     */
    @Override
    public int getXPos() {
        return xPos;
    }

    /**
     * Returns the y-coordinate of the position of this icon.
     *
     * @return the y-coordinate of the position of this icon.
     */
    @Override
    public int getYPos() {
        return yPos;
    }

    /**
     * Returns the width of this icon.
     *
     * @return the width of this icon.
     */
    @Override
    public int getWidth() {
        return width;
    }

    /**
     * Returns the height of this icon.
     *
     * @return the height of this icon.
     */
    @Override
    public int getHeight() {
        return height;
    }

    /**
     * Returns the extra-icon, which is to be displayed next to this icon. Might be null.
     *
     * @return the extra-icon.
     */
    public Icon getExtraIcon() {
        return extraIcon;
    }

    /**
     * Sets the x-coordinate of the position of this icon.
     *
     * @param xPos the x-coordinate of the position of this icon.
     */
    protected void setXPos(int xPos) {
        this.xPos = xPos;
    }

    /**
     * Sets the y-coordinate of the position of this icon.
     *
     * @param yPos the y-coordinate of the position of this icon.
     */
    protected void setYPos(int yPos) {
        this.yPos = yPos;
    }

    /**
     * Sets the width of this icon.
     * <p>
     * This method should be called only within the constructor-methods.</p>
     *
     * @param width the width of this icon.
     */
    protected void setWidth(int width) {
        this.width = width;
    }

    /**
     * Sets the height of this icon.
     * <p>
     * This method should be called only within the constructor-methods.</p>
     *
     * @param height the height of this icon.
     */
    protected void setHeight(int height) {
        this.height = height;
    }

    /**
     * Sets the extra-icon to be displayed next to this icon.
     * <p>
     * This method should be called only within the constructor-methods.</p>
     *
     * @param extraIcon the extra icon to display.
     */
    protected void setExtraIcon(Icon extraIcon) {
        this.extraIcon = extraIcon;
    }
}