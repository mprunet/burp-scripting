package fr.safepic.burp.script.ui.component;

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
public class NewTabIcon extends ClickableTabIcon {
    private final static int offsetCross = 2;

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
        super(fileIcon);
    }

    @Override
    public void paintIcon(Component component, Graphics graphics, int x, int y) {
        Color col = preparePaint(graphics, x, y);
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

}