package fr.safepic.burp.script.ui.component;

import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import javax.swing.Icon;

/**
 * Draws an icon representing an "X" in a box. The constructor accepts an icon, which will be placed next (right) to the
 * 'X' icon drawn by this class. If no extra icon is needed, the empty default constructor can be used, or provide
 * "null" as a value for the icon-object.
 *
 * @author mjoellnir
 * @version 1.0
 */
public class CloseTabIcon extends ClickableTabIcon {
    private final static int offsetCross1 = 3;
    private final static int offsetCross2 = 4;

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
        super(fileIcon);
    }

    @Override
    public void paintIcon(Component component, Graphics graphics, int x, int y) {
        Color col = preparePaint(graphics, x, y);

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
}