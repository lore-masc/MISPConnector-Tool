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
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 *
 * @author lMasciullo
 */
public class Settings {
    static final ObservableList<String> tags_orgs = FXCollections.observableArrayList();
    static final String CONFIG_FILE = "config.txt";
    static String url, key, cmd, org;
    private Stage stage;

    public Settings(Stage stage) {
        this.stage = stage;
    }
    
    public VBox getRoot() {
        try{
            BufferedReader br = new BufferedReader(new FileReader(CONFIG_FILE));
            url = br.readLine();
            key = br.readLine();
            cmd = br.readLine();
            org = br.readLine();
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
        cmd_txt.setPromptText("cmd /C start update_event.exe");
        cmd_txt.setPrefWidth(300);
        HBox cmd_bar = new HBox(cmd_lbl, cmd_txt);
        cmd_bar.setAlignment(Pos.CENTER);
        cmd_bar.setSpacing(10);
        
        load_orgs();
        Label starorg_lbl = new Label("Org tag: ");
        ChoiceBox<String> tagsorg_box = new ChoiceBox<String>(tags_orgs);
        if(!tags_orgs.isEmpty())
            tagsorg_box.setValue(tags_orgs.get(0));
        tagsorg_box.setPrefWidth(300);
        HBox org_bar = new HBox(starorg_lbl, tagsorg_box);
        org_bar.setAlignment(Pos.CENTER);
        org_bar.setSpacing(10);
        
        Button save_btn = new Button("Save");
        
        save_btn.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if(!url_txt.getText().isEmpty() && !key_txt.getText().isEmpty() && !cmd_txt.getText().isEmpty()){
                    try{
                        BufferedWriter br = new BufferedWriter(new FileWriter(CONFIG_FILE));
                        String url = url_txt.getText();
                        if(!url.endsWith("/"))
                            url += "/";
                        br.write(url + '\n');
                        br.write(key_txt.getText().replaceAll(" ", "") + '\n');
                        br.write(cmd_txt.getText() + '\n');
                        br.write(tagsorg_box.getValue() + '\n');
                        br.close();
                        MISPConnectorTool.showInfoDialog("Salvataggio riuscito!", "Riavvia il tool per poter rendere effettivi i cambiamenti effettuati.");
                        stage.close();
                    }catch(IOException ex){
                        System.err.println(ex);
                    }
                }else{
                    MISPConnectorTool.showErrorDialog("Impossibile salvare!", "Assicurati di aver compilato tutti i campi necessari.");
                }
            }
        });
        
        
        VBox root = new VBox(url_bar, key_bar, cmd_bar, org_bar, save_btn);
        root.setAlignment(Pos.CENTER);
        root.setSpacing(20);
        return root;
    }
    
    public void load_orgs(){
        tags_orgs.clear();
        try {
            HttpsURLConnection conn = MISPConnectorTool.MISP_connect("organisations/index.json", "GET");
            conn.disconnect();
            String resp = MISPConnectorTool.getResponseConnection(conn);
            JSONArray datajson = new JSONArray(resp);
            for(int i = 0; i < datajson.length(); i++){
                JSONObject org = datajson.getJSONObject(i).getJSONObject("Organisation");
                String name_org = org.getString("name");
                tags_orgs.add(new String(name_org));
                if(name_org.contains(Settings.org)){
                    String tmp = tags_orgs.get(0);
                    tags_orgs.set(0, name_org);
                    tags_orgs.set(i, tmp);
                }
            }
        } catch (Exception ex) {
            MISPConnectorTool.showErrorDialog("Impossibile stabilire la connessione con il server", ex.getMessage());
        }
    }
}
