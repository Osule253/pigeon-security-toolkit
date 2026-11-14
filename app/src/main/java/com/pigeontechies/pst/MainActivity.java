package com.pigeontechies.pst;

import android.app.Activity;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import java.io.InputStream;
import java.net.URL;
import java.net.InetAddress;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {

    private LinearLayout root;
    private EditText domainInput;
    private TextView output;
    private ExecutorService executor = Executors.newSingleThreadExecutor();

    private final int BG = Color.rgb(12, 12, 12);
    private final int PANEL = Color.rgb(28, 28, 28);
    private final int SILVER = Color.rgb(210, 210, 210);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildInterface();
    }

    private void buildInterface() {
        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(22, 30, 22, 30);
        root.setBackgroundColor(BG);

        scroll.setFillViewport(true);
        scroll.addView(root);
        setContentView(scroll);

        TextView brand = new TextView(this);
        brand.setText("PIGEON TECHIES");
        brand.setTextColor(SILVER);
        brand.setTextSize(13);
        brand.setLetterSpacing(0.18f);
        root.addView(brand);

        TextView title = new TextView(this);
        title.setText("PIGEON SECURITY\nTOOLKIT");
        title.setTextColor(Color.WHITE);
        title.setTextSize(29);
        title.setTypeface(null, Typeface.BOLD);
        title.setPadding(0, 18, 0, 5);
        root.addView(title);

        TextView version = new TextView(this);
        version.setText("ANDROID EDITION  •  VERSION 1.0.0");
        version.setTextColor(SILVER);
        version.setTextSize(11);
        root.addView(version);

        TextView status = new TextView(this);
        status.setText("SECURE. INSPECT. DEFEND.");
        status.setTextColor(Color.GREEN);
        status.setTextSize(12);
        status.setPadding(0, 25, 0, 20);
        root.addView(status);

        section("WEBSITE SECURITY");

        domainInput = new EditText(this);
        domainInput.setSingleLine(true);
        domainInput.setHint("Enter domain e.g. example.com");
        domainInput.setHintTextColor(Color.GRAY);
        domainInput.setTextColor(Color.WHITE);
        domainInput.setPadding(15, 12, 15, 12);
        domainInput.setBackgroundColor(PANEL);
        root.addView(domainInput);

        addButton("DNS LOOKUP", v -> runTask("DNS lookup", this::dnsLookup));
        addButton("WEBSITE SECURITY AUDIT", v -> runTask("Website audit", this::websiteAudit));
        addButton("SSL / TLS INSPECTION", v -> runTask("SSL inspection", this::sslInspect));

        section("FILE SECURITY");
        addButton("SELECT FILE & CALCULATE SHA-256", v -> chooseFile());

        section("SCAN RESULTS");

        output = new TextView(this);
        output.setText("Ready. Select a security tool to begin.");
        output.setTextColor(SILVER);
        output.setTextSize(13);
        output.setPadding(16, 18, 16, 18);
        output.setBackgroundColor(PANEL);
        root.addView(output);

        TextView footer = new TextView(this);
        footer.setText("\nPIGEON TECHIES\npigeontechies.com");
        footer.setTextColor(Color.GRAY);
        footer.setTextSize(12);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, 30, 0, 10);
        root.addView(footer);
    }

    private void section(String name) {
        TextView label = new TextView(this);
        label.setText(name);
        label.setTextColor(SILVER);
        label.setTextSize(12);
        label.setTypeface(null, Typeface.BOLD);
        label.setPadding(0, 25, 0, 12);
        root.addView(label);
    }

    private void addButton(String name, View.OnClickListener listener) {
        Button button = new Button(this);
        button.setText(name);
        button.setTextColor(Color.WHITE);
        button.setTextSize(12);
        button.setBackgroundTintList(
            android.content.res.ColorStateList.valueOf(PANEL)
        );
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
            -1, -2
        );
        params.setMargins(0, 7, 0, 7);
        root.addView(button, params);
        button.setOnClickListener(listener);
    }

    private String getDomain() {
        String value = domainInput.getText().toString().trim();
        value = value.replaceFirst("^https?://", "");
        value = value.split("/")[0].split(":")[0];
        if (value.isEmpty() || !value.matches(
            "(?i)[a-z0-9.-]+\\.[a-z]{2,}"
        )) {
            throw new IllegalArgumentException("Enter a valid domain name.");
        }
        return value;
    }

    private void runTask(String name, Runnable task) {
        output.setText(name + " in progress...");
        executor.execute(() -> {
            try {
                task.run();
            } catch (Exception e) {
                showResult("ERROR\n" + e.getMessage());
            }
        });
    }

    private void showResult(String result) {
        runOnUiThread(() -> output.setText(result));
    }

    private void dnsLookup() {
        try {
            String domain = getDomain();
            InetAddress[] addresses = InetAddress.getAllByName(domain);
            StringBuilder result = new StringBuilder();
            result.append("DNS LOOKUP\n\nDomain: ").append(domain);
            result.append("\n\nResolved addresses:\n");
            for (InetAddress address : addresses) {
                result.append("\n").append(address.getHostAddress());
            }
            showResult(result.toString());
        } catch (Exception e) {
            showResult("DNS LOOKUP FAILED\n\n" + e.getMessage());
        }
    }

    private void websiteAudit() {
        try {
            String domain = getDomain();
            URL url = new URL("https://" + domain);
            HttpURLConnection connection =
                (HttpURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "PST-Android/1.0");

            int code = connection.getResponseCode();

            String[] headers = {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            };

            StringBuilder result = new StringBuilder();
            result.append("WEBSITE SECURITY AUDIT\n\n");
            result.append("Domain: ").append(domain);
            result.append("\nHTTP Status: ").append(code).append("\n\n");

            for (String header : headers) {
                String value = connection.getHeaderField(header);
                result.append(header).append(": ");
                result.append(value == null ? "NOT DETECTED" : value);
                result.append("\n\n");
            }

            connection.disconnect();
            showResult(result.toString());

        } catch (Exception e) {
            showResult("WEBSITE AUDIT FAILED\n\n" + e.getMessage());
        }
    }

    private void sslInspect() {
        try {
            String domain = getDomain();
            URL url = new URL("https://" + domain);
            HttpsURLConnection connection =
                (HttpsURLConnection) url.openConnection();

            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.connect();

            StringBuilder result = new StringBuilder();
            result.append("SSL / TLS INSPECTION\n\n");
            result.append("Domain: ").append(domain);
            result.append("\nCipher suite: ");
            result.append(connection.getCipherSuite()).append("\n");

            Certificate[] certificates =
                connection.getServerCertificates();

            for (Certificate certificate : certificates) {
                if (certificate instanceof X509Certificate) {
                    X509Certificate cert = (X509Certificate) certificate;
                    result.append("\nCertificate subject:\n");
                    result.append(cert.getSubjectX500Principal());
                    result.append("\n\nIssuer:\n");
                    result.append(cert.getIssuerX500Principal());
                    result.append("\n\nValid from: ");
                    result.append(cert.getNotBefore());
                    result.append("\nValid until: ");
                    result.append(cert.getNotAfter());
                }
            }

            connection.disconnect();
            showResult(result.toString());

        } catch (Exception e) {
            showResult("SSL INSPECTION FAILED\n\n" + e.getMessage());
        }
    }

    private void chooseFile() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(intent, 101);
    }

    @Override
    protected void onActivityResult(
        int requestCode, int resultCode, Intent data
    ) {
        super.onActivityResult(requestCode, resultCode, data);

        if (requestCode == 101 && resultCode == RESULT_OK && data != null) {
            Uri uri = data.getData();
            output.setText("Calculating SHA-256...");
            executor.execute(() -> hashFile(uri));
        }
    }

    private void hashFile(Uri uri) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            InputStream input = getContentResolver().openInputStream(uri);

            if (input == null) {
                throw new Exception("Cannot open selected file.");
            }

            byte[] buffer = new byte[8192];
            int count;

            try (InputStream stream = input) {
                while ((count = stream.read(buffer)) != -1) {
                    digest.update(buffer, 0, count);
                }
            }

            StringBuilder hash = new StringBuilder();
            for (byte b : digest.digest()) {
                hash.append(String.format("%02x", b & 0xff));
            }

            showResult("FILE SHA-256\n\n" + hash.toString());

        } catch (Exception e) {
            showResult("FILE HASH FAILED\n\n" + e.getMessage());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
