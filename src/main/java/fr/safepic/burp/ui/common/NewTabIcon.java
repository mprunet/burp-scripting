package fr.safepic.burp.ui.common;

import javax.swing.*;
import java.awt.*;

/**
 * Draws an icon representing an "X" in a box. The constructor accepts an icon, which will be placed next (right) to the
 * 'X' icon drawn by this class. If no extra icon is needed, the empty default constructor can be used, or provide
 * "null" as a value for the icon-object.
 *
 * @author mjoellnir
 * @version 1.0
 */
public class NewTabIcon implements ClickableTabIcon {

    private int xPos;
    private int yPos;
    private int width = 16;
    private int height = 16;
    private final int offsetFrame = 2;
    private final int offsetCross = 2;
    private Icon extraIcon = null;

    /**
     * Creates new "X" Icon.
     */
    public NewTabIcon() {
    }

    /**
     * Creates new "X" Icon with an extra icon next to it.
     *
     * @param fileIcon the Icon-object to be placed next to this icon.
     * @see Icon
     */
    public NewTabIcon(Icon fileIcon) {
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

        // prepare coordinates for the "+"
        int horizontalXPos1 = frameLeft + offsetCross;
        int horizontalXPos2 = frameRight - offsetCross;
        int horizontalYPos= frameTop + (frameBottom - frameTop -2) / 2;

        int verticalYPos1 = frameTop + offsetCross;
        int verticalYPos2 = frameBottom - offsetCross;
        int verticalXPos= frameLeft + (frameRight - frameLeft -2) / 2;
        int yPos = (frameRight - frameLeft - 2) / 2;
        int xPos = (frameBottom - frameTop - 2) / 2;

        // Horizontal
        graphics.drawLine(horizontalXPos1, horizontalYPos, horizontalXPos2, horizontalYPos);
        graphics.drawLine(horizontalXPos1, horizontalYPos+1, horizontalXPos2, horizontalYPos+1);
        graphics.drawLine(horizontalXPos1, horizontalYPos+2, horizontalXPos2, horizontalYPos+2);
        // Vertical
        graphics.drawLine(verticalXPos, verticalYPos1, verticalXPos, verticalYPos2);
        graphics.drawLine(verticalXPos+1, verticalYPos1, verticalXPos+1, verticalYPos2);
        graphics.drawLine(verticalXPos+2, verticalYPos1, verticalXPos+2, verticalYPos2);

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
     * Returns the bounding rectangle of this icon.
     *
     * @return the bounding rectangle of this icon.
     * @see Rectangle
     */
    public Rectangle getBounds() {
        return new Rectangle(getXPos(), getYPos(), getWidth(), getHeight());
    }

    /**
     * Returns the x-coordinate of the position of this icon.
     *
     * @return the x-coordinate of the position of this icon.
     */
    public int getXPos() {
        return xPos;
    }

    /**
     * Returns the y-coordinate of the position of this icon.
     *
     * @return the y-coordinate of the position of this icon.
     */
    public int getYPos() {
        return yPos;
    }

    /**
     * Returns the width of this icon.
     *
     * @return the width of this icon.
     */
    public int getWidth() {
        return width;
    }

    /**
     * Returns the height of this icon.
     *
     * @return the height of this icon.
     */
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