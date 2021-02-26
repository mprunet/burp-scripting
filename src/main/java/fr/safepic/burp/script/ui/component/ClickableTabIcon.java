package fr.safepic.burp.script.ui.component;

import javax.swing.*;
import java.awt.*;

public abstract class ClickableTabIcon implements Icon {

    private int xPos;
    private int yPos;
    private int width = 16;
    private int height = 16;
    private final static int offsetFrame = 2;
    protected Icon extraIcon = null;
    protected int frameTop;
    protected int frameBottom;
    protected int frameLeft;
    protected int frameRight;

    protected ClickableTabIcon() {

    }

    protected ClickableTabIcon(Icon extraIcon) {
        this.extraIcon =extraIcon;
    }

    public Color preparePaint(Graphics graphics, int x, int y) {
        setXYPos(x, y);

        Color col = graphics.getColor();

        graphics.setColor(Color.black);

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
        return col;
    }

    public int getIconWidth() {
        return getWidth() + (extraIcon != null ? extraIcon.getIconWidth() : 0);
    }

    public int getIconHeight() {
        return getHeight();
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
    protected void setXYPos(int xPos, int yPos) {
        this.xPos = xPos;
        this.yPos = yPos;
        this.frameLeft = xPos + offsetFrame;
        this.frameRight = xPos + (width - offsetFrame);
        this.frameTop = yPos + offsetFrame;
        this.frameBottom = yPos + (height - offsetFrame);

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


    public Rectangle getBounds() {
        return new Rectangle(getXPos(), getYPos(), getWidth(), getHeight());
    }

}
