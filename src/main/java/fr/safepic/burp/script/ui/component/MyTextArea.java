package fr.safepic.burp.script.ui.component;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.*;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class MyTextArea extends JPanel {
    private final RSyntaxTextArea coloredArea = new FSRTextArea(15, 80);
    private final JTextArea  normalArea = new FSJTextArea(15, 80);
    private final CardLayout layout = new CardLayout();
    private boolean colored = true;

    private class MenuEntry {
        JPopupMenu popup;
        JMenu menu;

        public MenuEntry(JMenu menu) {
            this.menu = menu;
        }

        public MenuEntry(JPopupMenu popup) {
            this.popup = popup;
        }

        public void add(JMenu child) {
            if (popup != null) {
                popup.add(child);
            } else {
                menu.add(child);
            }
        }
        public void add(JMenuItem child) {
            if (popup != null) {
                popup.add(child);
            } else {
                menu.add(child);
            }
        }

    }

    public MyTextArea(String name) {
        setName(name);
        setLayout(layout);
        coloredArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT);
        RTextScrollPane coloredAreaSP = new RTextScrollPane(coloredArea);
        add(coloredAreaSP, "colored");
        JScrollPane normalAreaSP = new JScrollPane(normalArea);
        add(normalAreaSP, "normal");
        layout.show(this, "colored");

        normalArea.getDocument().addDocumentListener(new ScriptDocumentListener(false));
        coloredArea.getDocument().addDocumentListener(new ScriptDocumentListener(true));
        JPopupMenu coloredAreaMenu = coloredArea.getPopupMenu();
        JPopupMenu normalAreaMenu = new JPopupMenu();
        normalArea.setComponentPopupMenu(normalAreaMenu);
        try {
            URI uri = MyTextArea.class.getResource("/sample-menu-item").toURI();
            if ("jar".equals(uri.getScheme())) {
                try {
                    FileSystems.getFileSystem(uri);
                } catch( FileSystemNotFoundException e ) {
                    Map<String, String> env = new HashMap<>();
                    env.put("create", "true");
                    FileSystems.newFileSystem(uri, env);
                }
            }
            Path myPath = Paths.get(uri);
            Stack<MenuEntry> stack = new Stack<>();

            List<Path> paths = new ArrayList<>();
            SimpleFileVisitor visitor = new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (!myPath.equals(dir)) {
                        MenuEntry parent = stack.peek();
                        JMenu child = new JMenu(dir.getFileName().toString());
                        parent.add(child);
                        stack.push(new MenuEntry(child));
                    }
                    return super.preVisitDirectory(dir, attrs);
                }
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    paths.add(file);
                    return super.visitFile(file, attrs);
                }
                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
                    return super.visitFileFailed(file, exc);
                }
                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    paths.stream().sorted(Comparator.comparing(file->file.getFileName().toString()))
                            .forEach(file->{
                                String value = file.getFileName().toString();
                                value = value.substring(0, value.length() - 4);
                                stack.peek().add(new JMenuItem(new AbstractAction(value) {
                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        insertSample(file);
                                    }
                                }));
                            });
                    paths.clear();
                    if (!myPath.equals(dir)) {
                        stack.pop();
                    }
                    return super.postVisitDirectory(dir, exc);
                }
            };

            JMenu sample = new JMenu("Code sample");
            coloredAreaMenu.add(sample);
            stack.push(new MenuEntry(sample));
            Files.walkFileTree(myPath, visitor);
            stack.clear();

            stack.push(new MenuEntry(normalAreaMenu));
            Files.walkFileTree(myPath, visitor);


/*            Stream<Path> walk = Files.walk(myPath, 2);
            Map<Path, JMenu> menus = new
            walk.forEach(path -> {
                System.out.println(myPath.relativize(path));
            });*/
        } catch (Exception ex) {
            ex.printStackTrace();
        }



    }

    public void insertSample(Path path) {
        try {
            if (colored) {
                coloredArea.insert(Files.readString(path, StandardCharsets.UTF_8), coloredArea.getCaretPosition());
            } else {
                normalArea.insert(Files.readString(path, StandardCharsets.UTF_8), normalArea.getCaretPosition());
            }
        }catch (Exception ex) {
            ex.printStackTrace();
        }
    }
    public void addDocumentListener(DocumentListener listener) {
        listenerList.add(DocumentListener.class, listener);
    }


    private class ScriptDocumentListener implements DocumentListener {
        private final boolean fireWhenColored;
        ScriptDocumentListener(boolean fireWhenColored){
            this.fireWhenColored = fireWhenColored;
        }

        @Override
        public void insertUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.insertUpdate(e);
                }
            }
        }

        @Override
        public void removeUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.removeUpdate(e);
                }
            }
        }

        @Override
        public void changedUpdate(DocumentEvent e) {
            if (fireWhenColored == colored) {
                for (DocumentListener listener : listenerList.getListeners(DocumentListener.class)) {
                    listener.changedUpdate(e);
                }
            }
        }
    }

    public void setColored(boolean b) {
        String currentValue = getText();
        colored = b;
        layout.show(this, b ? "colored" : "normal");
        setText(currentValue);
    }


    public String getText() {
        return colored ? coloredArea.getText() : normalArea.getText();
   }

    public void setText(String txt) {
        if (colored) {
            coloredArea.setText(txt);
        } else {
            normalArea.setText(txt);
        }
    }

}
