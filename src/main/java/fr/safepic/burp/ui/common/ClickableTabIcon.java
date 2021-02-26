package fr.safepic.burp.ui.common;

import javax.swing.*;
import java.awt.*;

public interface ClickableTabIcon extends Icon {
    default Rectangle getBounds() {
        return new Rectangle(getXPos(), getYPos(), getWidth(), getHeight());
    }

    int getHeight();

    int getWidth();

    int getYPos();

    int getXPos();


}
