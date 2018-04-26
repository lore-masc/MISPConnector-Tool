/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mispconnector.tool;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Date;
import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.DatePicker;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 *
 * @author lmasciullo
 */
public class MISPConnectorTool extends Application {
    static final String CONFIG_FILE = "config.txt";
    static String url, key;
    static final ObservableList<String> files = FXCollections.observableArrayList();
    static final ObservableList<String> groups = FXCollections.observableArrayList("Your organisation only", "This community only", "Connected communities", "All communities", "Convezionati");   //Leggere gli sharing groups dinamicamente
    static final ObservableList<String> analysis_options = FXCollections.observableArrayList("Initial", "Ongoing", "Completed");
    static final ObservableList<String> threat_options = FXCollections.observableArrayList("High", "Medium", "Low", "Undefined");
    static final ObservableList<String> platform_options = FXCollections.observableArrayList("google android", "apple ios", "microsoft windows", "unix unix");
    static final ObservableList<String> tlp_options = FXCollections.observableArrayList("amber", "ex:chr", "green", "red", "white");
    
    @Override
    public void start(Stage primaryStage) {
        
        try{
            BufferedReader br = new BufferedReader(new FileReader(CONFIG_FILE));
            url = br.readLine();
            key = br.readLine();
            br.close();
        }catch(IOException ex){
            System.err.println(ex);
        }
        
        //---------------------------- LEFT BAR ----------------------------------
        Label recent_events = new Label("Recents:");
        ListView list_files = new ListView(files);
        list_files.setPrefSize(200, 700);
        populate_files(list_files);
        VBox left_bar = new VBox(recent_events, list_files);
        //------------------------------------------------------------------------
        
        //---------------------------- RIGHT BAR ---------------------------------
        
        //-------------- AUTH KEY BAR ------------------------
        Label auth_key_lbl = new Label("Auth key: ");
        TextField auth_key_txt = new TextField(key);
        auth_key_txt.setMinWidth(300);
        
        HBox topBar1 = new HBox(auth_key_lbl, auth_key_txt);
        topBar1.setAlignment(Pos.CENTER);
        topBar1.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- DISTRIBUTION ANALYSIS BAR ----------
        Label distribution_lbl = new Label("Distribution: ");
        ChoiceBox distribution_box = new ChoiceBox(groups);
        distribution_box.setValue(groups.get(groups.size()-1));
        Label analysis_lbl = new Label("Analysis: ");
        ChoiceBox analysis_box = new ChoiceBox(analysis_options);
        analysis_box.setValue(analysis_options.get(2));
        
        HBox topBar2 = new HBox(distribution_lbl, distribution_box, analysis_lbl, analysis_box);
        topBar2.setAlignment(Pos.CENTER);
        topBar2.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- THREAT DATA BAR --------------------
        Label threat_lbl = new Label("Threat level: ");
        ChoiceBox threat_box = new ChoiceBox(threat_options);
        threat_box.setValue(threat_options.get(1));
        Label data_lbl = new Label("Date:");
        DatePicker date_picker = new DatePicker(LocalDate.now());
        
        HBox topBar3 = new HBox(threat_lbl, threat_box, data_lbl, date_picker);
        topBar3.setAlignment(Pos.CENTER);
        topBar3.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- TITLE BAR --------------------------
        Label title_lbl = new Label("Title: ");
        TextField title_txt = new TextField();
        
        VBox topBar4 = new VBox(title_lbl, title_txt);
        topBar4.setAlignment(Pos.CENTER);
        topBar4.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- DESCRIPTION BAR --------------------
        Label description_lbl = new Label("Description: ");
        TextArea description_txt = new TextArea();
        
        VBox topBar5 = new VBox(description_lbl, description_txt);
        topBar5.setAlignment(Pos.CENTER);
        topBar5.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- IOCs BAR ---------------------------
        Label iocs_lbl = new Label("IOCs: ");
        TextArea iocs_txt = new TextArea();
        
        VBox topBar6 = new VBox(iocs_lbl, iocs_txt);
        topBar6.setAlignment(Pos.CENTER);
        topBar6.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- TAGs BAR ---------------------------
        Label platform_lbl = new Label("Platform: ");
        ChoiceBox platform_box = new ChoiceBox(platform_options);
        
        Label tlp_lbl = new Label("TLP: ");
        ChoiceBox tlp_box = new ChoiceBox(tlp_options);
        tlp_box.setValue(tlp_options.get(0));
        
        Button submit = new Button("IMPORT");
        
        HBox top_bar7 = new HBox(platform_lbl, platform_box, tlp_lbl, tlp_box, submit);
        top_bar7.setAlignment(Pos.CENTER);
        top_bar7.setSpacing(10);
        //---------------------------------------------------
        
        VBox content = new VBox(topBar1, topBar2, topBar3, topBar4, topBar5, topBar6, top_bar7);
        content.setAlignment(Pos.CENTER);
        content.setSpacing(20);
        content.setPrefSize(600, 700);
        //------------------------------------------------------------------------

        //---------------------- BUTTON CLICK EVENT ------------------------------
        submit.setOnAction(new EventHandler<ActionEvent>() {
            @Override public void handle(ActionEvent e) {
                try{
                    BufferedWriter br;
                    DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
                    Date date = new Date();
                    String now = dateFormat.format(date);
                    String[] iocs;
                    System.out.println(now); 
                    int distr_index = distribution_box.getSelectionModel().getSelectedIndex();
                    br = new BufferedWriter(new FileWriter(now + ".json"));
                    br.append("{\n");
                    br.append("\t\"distibution\": \"" + distr_index + "\",\n");
                    if(distr_index > 3)
                    br.append("\t\"sharing_group\": \"" + distr_index + "\",\n");
                    br.append("\t\"analysis\": \"" + analysis_box.getSelectionModel().getSelectedIndex() + "\",\n");
                    br.append("\t\"threat\": \"" + threat_box.getSelectionModel().getSelectedIndex() + "\",\n");
                    br.append("\t\"data\": \"" + date_picker.getValue() + "\",\n");
                    br.append("\t\"info\": \"" + title_txt.getText() + "\",\n");
                    br.append("\t\"comment\": \"" + description_txt.getText().replaceAll("\n", " ") + "\",\n");
                    br.append("\t\"iocs\": [");
                    iocs = iocs_txt.getText().split("\n");
                    for(String ioc : iocs){
                        br.append("{\"value\":\"" + ioc + "\"}");
                        if(iocs[iocs.length - 1] != ioc)  br.append(", ");
                    }
                    br.append("],\n");
                    br.append("\t\"platform\": [");
                    br.append("{\"name\":\"" + platform_box.getValue() + "\"}");
                    br.append("],\n");
                    br.append("\t\"tlp\": \"" + tlp_box.getValue()+ "\"\n");
                    br.append("}");
                    br.close();
                    populate_files(list_files);
                }catch(IOException ex){
                    System.err.println(ex);
                }
            }
        });
        //------------------------------------------------------------------------
                
        HBox root = new HBox(left_bar, content);
        root.setSpacing(20);
        
        Scene scene = new Scene(root, 850, 700);
        
        primaryStage.setTitle("MISP Connector Tool (connected to " + url + ")");
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    public void populate_files(ListView list_files) {
        try {
            exe_MISP_api();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyManagementException ex) {
            Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
        }
        files.clear();
        File f = new File(".");
        if(f.isDirectory())
            for(File file : f.listFiles())
                if(file.isFile() && file.getName().contains(".json"))
                    files.add(file.getName());
        list_files.setItems(files);
    }
    
    public void exe_MISP_api() throws NoSuchAlgorithmException, KeyManagementException, MalformedURLException, IOException{
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);

        URL url = new URL(MISPConnectorTool.url + "sharing_groups/index.json");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        });
        System.out.println(conn.getResponseMessage());
        
        
        
        conn.disconnect();
    }

    private static class DefaultTrustManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        launch(args);
    }
    
}
