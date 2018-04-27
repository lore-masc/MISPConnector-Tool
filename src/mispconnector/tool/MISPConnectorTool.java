/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package mispconnector.tool;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
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
import javafx.scene.control.Alert;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.SelectionMode;
import javafx.scene.input.MouseEvent;
import javafx.util.Pair;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.json.JSONObject;

/**
 *
 * @author lmasciullo
 */
public class MISPConnectorTool extends Application {
    static final String CONFIG_FILE = "config.txt";
    static String url, key;
    static final ObservableList<String> files = FXCollections.observableArrayList();
    static final ObservableList<Pair<Integer, String>> groups = FXCollections.observableArrayList(new Pair<Integer, String>(0, "Your organisation only"), new Pair<Integer, String>(1, "This community only"), new Pair<Integer, String>(2, "Connected communities"), new Pair<Integer, String>(3, "All communities"));
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
        list_files.getSelectionModel().setSelectionMode(SelectionMode.SINGLE);
        populate_files(list_files);
        VBox left_bar = new VBox(recent_events, list_files);
        //------------------------------------------------------------------------
        
        //---------------------------- RIGHT BAR ---------------------------------
        
        //-------------- AUTH KEY BAR ------------------------
        Label auth_key_lbl = new Label("*Auth key: ");
        TextField auth_key_txt = new TextField(key);
        auth_key_txt.setMinWidth(300);
        
        HBox topBar1 = new HBox(auth_key_lbl, auth_key_txt);
        topBar1.setAlignment(Pos.CENTER);
        topBar1.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- DISTRIBUTION ANALYSIS BAR ----------
        load_groups();
        Label distribution_lbl = new Label("Distribution: ");
        ChoiceBox distribution_box = new ChoiceBox(groups);
        distribution_box.setValue(groups.get(4));
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
        Label data_lbl = new Label("*Date:");
        DatePicker date_picker = new DatePicker(LocalDate.now());
        
        HBox topBar3 = new HBox(threat_lbl, threat_box, data_lbl, date_picker);
        topBar3.setAlignment(Pos.CENTER);
        topBar3.setSpacing(10);
        //---------------------------------------------------
        
        //-------------- TITLE BAR --------------------------
        Label title_lbl = new Label("*Title: ");
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
        Label platform_lbl = new Label("*Platform: ");
        ChoiceBox platform_box = new ChoiceBox(platform_options);
        platform_box.setValue("");
        
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
                if(auth_key_txt.getText().equals("") || title_txt.getText().equals("") || date_picker.getValue().equals("") || platform_box.getValue().equals("")){
                    showErrorDialog("Sono presenti campi obbligatori non compilati!", "");
                    return;
                }
                try{
                    BufferedWriter br;
                    DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd-HH-mm-ss");
                    Date date = new Date();
                    String now = dateFormat.format(date);
                    String[] iocs;
                    int distr_index = distribution_box.getSelectionModel().getSelectedIndex();
                    br = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(now + ".json"), StandardCharsets.UTF_8));
                    br.append("{\n");
                    br.append("\t\"distribution\": \"" + distr_index + "\",\n");
                    if(distr_index > 3)
                        br.append("\t\"sharing_group\": \"" + groups.get(distr_index).getKey()+ "\",\n");
                    br.append("\t\"analysis\": \"" + analysis_box.getSelectionModel().getSelectedIndex() + "\",\n");
                    br.append("\t\"threat\": \"" + (threat_box.getSelectionModel().getSelectedIndex() + 1) + "\",\n");
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
                    import_event(now + ".json");                    
                }catch(IOException ex){
                    System.err.println(ex);
                }
            }
        });
        //------------------------------------------------------------------------
        
        //---------------------- LIST FILES CLICK EVENT --------------------------
        list_files.setOnMouseClicked(new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                try {
                    String filename = list_files.getSelectionModel().getSelectedItems().get(0).toString();
                    FileReader fr = new FileReader(filename);
                    BufferedReader br = new BufferedReader(fr);
                    String sCurrentLine, file = "";
                    while ((sCurrentLine = br.readLine()) != null) 
                            file += sCurrentLine;
                    fr.close();
                    
                    JSONObject datajson = new JSONObject(file);
                    //System.out.println(datajson);
                    int distr_index = datajson.getInt("distribution");
                    if(distr_index > 3){
                        distr_index = datajson.getInt("sharing_group");
                        Iterator<Pair<Integer, String>> myIter = groups.subList(4, groups.size()).iterator();
                        while (myIter.hasNext()) {
                            Pair<Integer, String> tmp1 = myIter.next();
                            if ((int)tmp1.getKey() == distr_index) {
                                distribution_box.setValue(tmp1);
                            }
                        }
                    }else
                        distribution_box.getSelectionModel().select(distr_index);
                    
                    analysis_box.getSelectionModel().select(datajson.getInt("analysis"));
                    threat_box.getSelectionModel().select(datajson.getInt("threat") - 1);
                    date_picker.setValue(LocalDate.parse(datajson.getString("data")));
                    title_txt.setText(datajson.getString("info"));
                    description_txt.setText(datajson.getString("comment"));
                    for(int i = 0; i < datajson.getJSONArray("iocs").length(); i++){
                        JSONObject ioc = datajson.getJSONArray("iocs").getJSONObject(i);
                        iocs_txt.setText(iocs_txt.getText() + ((i > 0) ? "\n" : "") + ioc.getString("value"));
                    }
                    platform_box.setValue(datajson.getJSONArray("platform").getJSONObject(0).getString("name"));
                    tlp_box.setValue(datajson.getString("tlp"));
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
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
    
    public void import_event(String json){
        Runtime rt = Runtime.getRuntime();
        try {
            Process pr = rt.exec("update_event.exe " + json);
        } catch (IOException ex) {
            Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void load_groups(){
        try {
            HttpsURLConnection conn = MISP_connect("sharing_groups/index.json", "GET");
            conn.disconnect();
            String resp = getResponseConnection(conn);
            JSONObject datajson = new JSONObject(resp);
            for(int i = 0; i < datajson.getJSONArray("response").length(); i++){
                JSONObject group = datajson.getJSONArray("response").getJSONObject(i);
                String name_group = group.getJSONObject("SharingGroup").getString("name");
                int id_group = group.getJSONObject("SharingGroup").getInt("id");
                groups.add(new Pair<Integer, String>(id_group, name_group));
            }
        } catch (Exception ex) {
            showErrorDialog("Impossibile stabilire la connessione con il server", ex.getMessage());
            Logger.getLogger(MISPConnectorTool.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void showErrorDialog(String header, String err){
        Alert alert = new Alert(AlertType.ERROR);
        alert.setTitle("Error Dialog");
        alert.setHeaderText("Ooops, è presente un errore!");
        alert.setContentText(header + "\n\n" + err);
        alert.showAndWait();
    }

    public void populate_files(ListView list_files) {
        files.clear();
        File f = new File(".");
        if(f.isDirectory())
            for(File file : f.listFiles())
                if(file.isFile() && file.getName().contains(".json"))
                    files.add(file.getName());
        list_files.setItems(files);
    }
    
    public String getResponseConnection(HttpsURLConnection conn) throws IOException{
        BufferedReader in = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
        String inputLine;
        String response = "";

        while ((inputLine = in.readLine()) != null) {
                response += inputLine;
        }
        in.close();
        return response;
    }
    
    public HttpsURLConnection MISP_connect(String get_request, String method) throws NoSuchAlgorithmException, KeyManagementException, MalformedURLException, IOException{
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[0], new TrustManager[] {new DefaultTrustManager()}, new SecureRandom());
        SSLContext.setDefault(ctx);

        URL url = new URL(MISPConnectorTool.url + get_request);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setHostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String arg0, SSLSession arg1) {
                return true;
            }
        });
        conn.setRequestProperty("Authorization", key);
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestMethod(method);
        return conn;
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
