/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mispconnector.tool;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;

/**
 *
 * @author lMasciullo
 */
public class Settings {
    static final String CONFIG_FILE = "config.txt";
    static String url, key, cmd;
    
    public VBox getRoot() {
        try{
            BufferedReader br = new BufferedReader(new FileReader(CONFIG_FILE));
            url = br.readLine();
            key = br.readLine();
            cmd = br.readLine();
            br.close();
        }catch(IOException ex){
            System.err.println(ex);
        }
        
        Label url_lbl = new Label("Instance URL: ");
        TextField url_txt = new TextField(url);
        url_txt.setPrefWidth(300);
        url_txt.setPromptText("https://misp-url.org");
        HBox url_bar = new HBox(url_lbl, url_txt);
        url_bar.setAlignment(Pos.CENTER);
        url_bar.setSpacing(10);
        
        Label key_lbl = new Label("Auth key: ");
        TextField key_txt = new TextField(key);
        key_txt.setPrefWidth(300);
        key_txt.setPromptText("a4PLf8QICdDdOmFjwdtSYqkCqn9CvN0VQt7mpUUf");
        HBox key_bar = new HBox(key_lbl, key_txt);
        key_bar.setAlignment(Pos.CENTER);
        key_bar.setSpacing(10);
        
        Label cmd_lbl = new Label("Execution command: ");
        TextField cmd_txt = new TextField(cmd);
        cmd_txt.setPrefWidth(300);
        HBox cmd_bar = new HBox(cmd_lbl, cmd_txt);
        cmd_bar.setAlignment(Pos.CENTER);
        cmd_bar.setSpacing(10);
        
        Button save_btn = new Button("Save");
        
        save_btn.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if(!url_txt.getText().isEmpty() && !key_txt.getText().isEmpty() && !cmd_txt.getText().isEmpty()){
                    try{
                        BufferedWriter br = new BufferedWriter(new FileWriter(CONFIG_FILE));
                        br.write(url_txt.getText() + '\n');
                        br.write(key_txt.getText() + '\n');
                        br.write(cmd_txt.getText() + '\n');
                        br.close();
                    }catch(IOException ex){
                        System.err.println(ex);
                    }
                }else{
                    MISPConnectorTool.showErrorDialog("Impossibile salvare!", "Assicurati di aver compilato tutti i campi necessari.");
                }
            }
        });
        
        
        VBox root = new VBox(url_bar, key_bar, cmd_bar, save_btn);
        root.setAlignment(Pos.CENTER);
        root.setSpacing(20);
        return root;
    }
    
}
