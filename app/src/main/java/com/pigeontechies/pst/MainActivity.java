package com.pigeontechies.pst;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.provider.Settings;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.graphics.Color;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.net.InetAddress;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;
import org.json.JSONArray;
import androidx.core.content.FileProvider;

public class MainActivity extends Activity {

    private LinearLayout root;
    private EditText domainInput;
    private TextView output;
    private JSONObject lastScanReport;
    private ExecutorService executor = Executors.newSingleThreadExecutor();

    private static final String UPDATE_MANIFEST_URL =
        "https://raw.githubusercontent.com/Osule253/pigeon-security-toolkit/main/pst-update.json";

    private TextView versionLabel;
    private TextView updateStatus;
    private boolean updateCheckInProgress = false;
    private File pendingUpdateFile;

    private final int BG = Color.rgb(12, 12, 12);
    private final int PANEL = Color.rgb(28, 28, 28);
    private final int SILVER = Color.rgb(210, 210, 210);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildInterface();
        checkForUpdates(false);
    }

    private String getAppVersion() {
        try {
            PackageInfo info = getPackageManager().getPackageInfo(getPackageName(), 0);
            return info.versionName;
        } catch (Exception e) {
            return "Unknown";
        }
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

        versionLabel = new TextView(this);
        versionLabel.setText("ANDROID EDITION  •  VERSION " + getAppVersion());
        versionLabel.setTextColor(SILVER);
        versionLabel.setTextSize(11);
        root.addView(versionLabel);

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

        section("SCAN HISTORY");
        addButton("SAVE CURRENT SCAN", v -> saveCurrentScan());
        addButton("VIEW SCAN HISTORY", v -> viewScanHistory());
        addButton("VIEW SAVED SCAN", v -> promptSavedScan());
        addButton("COMPARE TWO SCANS", v -> promptCompareScans());


        section("SOFTWARE UPDATES");

        updateStatus = new TextView(this);
        updateStatus.setText("Checking for updates will be available here.");
        updateStatus.setTextColor(SILVER);
        updateStatus.setTextSize(12);
        updateStatus.setPadding(12, 14, 12, 14);
        updateStatus.setBackgroundColor(PANEL);
        root.addView(updateStatus);

        addButton("CHECK FOR UPDATES", v -> checkForUpdates(true));

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


    private void checkForUpdates(boolean manual) {
        if (updateCheckInProgress) return;

        updateCheckInProgress = true;
        updateStatus.setText("Checking for updates...");

        executor.execute(() -> {
            HttpURLConnection connection = null;

            try {
                URL url = new URL(UPDATE_MANIFEST_URL);
                connection = (HttpURLConnection) url.openConnection();
                connection.setConnectTimeout(15000);
                connection.setReadTimeout(15000);
                connection.setRequestMethod("GET");
                connection.setRequestProperty("User-Agent", "PST-Android-Updater");

                if (connection.getResponseCode() != 200) {
                    throw new Exception("Update server returned HTTP " +
                        connection.getResponseCode());
                }

                StringBuilder body = new StringBuilder();
                try (InputStream input = connection.getInputStream()) {
                    byte[] buffer = new byte[4096];
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        body.append(new String(buffer, 0, count,
                            java.nio.charset.StandardCharsets.UTF_8));
                    }
                }

                JSONObject metadata = new JSONObject(body.toString());
                int latestCode = metadata.getInt("versionCode");
                String latestName = metadata.getString("versionName");
                String apkUrl = metadata.getString("apkUrl");
                String checksum = metadata.getString("sha256");
                String notes = metadata.optString("releaseNotes", "No release notes.");

                PackageInfo installed = getPackageManager()
                    .getPackageInfo(getPackageName(), 0);

                int currentCode = installed.versionCode;

                if (latestCode <= currentCode) {
                    runOnUiThread(() -> {
                        updateStatus.setText("PST is up to date. Version " +
                            getAppVersion());
                        updateCheckInProgress = false;
                    });
                    return;
                }

                runOnUiThread(() -> {
                    updateStatus.setText("Update available: " + latestName);
                    new AlertDialog.Builder(this)
                        .setTitle("PST update available")
                        .setMessage("Version " + latestName + "\n\n" + notes +
                            "\n\nDownload and verify this update?")
                        .setNegativeButton("Later", (dialog, which) -> {})
                        .setPositiveButton("Download", (dialog, which) ->
                            downloadUpdate(apkUrl, checksum))
                        .show();
                    updateCheckInProgress = false;
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    updateStatus.setText("Update check failed: " + e.getMessage());
                    updateCheckInProgress = false;
                });
            } finally {
                if (connection != null) connection.disconnect();
            }
        });
    }


    private void downloadUpdate(String apkUrl, String expectedSha256) {
        if (apkUrl == null || !apkUrl.startsWith("https://github.com/Osule253/pigeon-security-toolkit/releases/download/") ||
            expectedSha256 == null ||
            !expectedSha256.matches("(?i)[a-f0-9]{64}")) {
            updateStatus.setText("Rejected: Invalid update URL or checksum.");
            return;
        }

        updateStatus.setText("Downloading update...");

        executor.execute(() -> {
            HttpURLConnection connection = null;
            File apkFile = null;

            try {
                connection = (HttpURLConnection)
                    new URL(apkUrl).openConnection();
                connection.setConnectTimeout(20000);
                connection.setReadTimeout(30000);
                connection.setInstanceFollowRedirects(true);

                int responseCode = connection.getResponseCode();

                if (responseCode != 200) {
                    throw new Exception("Download failed: HTTP " + responseCode);
                }

                URL finalUrl = connection.getURL();
                String finalHost = finalUrl.getHost();

                if (!"https".equalsIgnoreCase(finalUrl.getProtocol()) ||
                    !(finalHost.equalsIgnoreCase("github.com") ||
                      finalHost.equalsIgnoreCase("release-assets.githubusercontent.com"))) {
                    throw new Exception("Untrusted download destination.");
                }

                File directory = getExternalFilesDir(
                    Environment.DIRECTORY_DOWNLOADS);

                if (directory == null) {
                    throw new Exception("Download directory unavailable.");
                }

                if (!directory.exists() && !directory.mkdirs()) {
                    throw new Exception("Cannot create download directory.");
                }

                apkFile = new File(directory, "pst-update.apk");
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] buffer = new byte[8192];
                long total = 0;

                try (InputStream input = connection.getInputStream();
                     OutputStream outputStream =
                         new FileOutputStream(apkFile)) {
                    int count;

                    while ((count = input.read(buffer)) != -1) {
                        total += count;

                        if (total > 100L * 1024 * 1024) {
                            throw new Exception("APK exceeds 100 MB.");
                        }

                        digest.update(buffer, 0, count);
                        outputStream.write(buffer, 0, count);
                    }
                }

                StringBuilder hash = new StringBuilder();

                for (byte b : digest.digest()) {
                    hash.append(String.format("%02x", b & 0xff));
                }

                if (!hash.toString().equalsIgnoreCase(expectedSha256)) {
                    throw new Exception("SHA-256 verification failed.");
                }

                File verifiedFile = apkFile;
                pendingUpdateFile = verifiedFile;

                runOnUiThread(() -> {
                    updateStatus.setText("Download verified.");
                    installUpdate(verifiedFile);
                });

            } catch (Exception e) {
                if (apkFile != null) apkFile.delete();

                runOnUiThread(() ->
                    updateStatus.setText("UPDATE FAILED: " + e.getMessage()));
            } finally {
                if (connection != null) connection.disconnect();
            }
        });
    }

    private void installUpdate(File apkFile) {
        try {
            if (apkFile == null || !apkFile.isFile()) {
                throw new Exception("Update APK not found.");
            }

            if (android.os.Build.VERSION.SDK_INT >= 26 &&
                !getPackageManager().canRequestPackageInstalls()) {

                updateStatus.setText(
                    "Allow PST to install updates, then return.");

                Intent settingsIntent = new Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:" + getPackageName()));

                startActivityForResult(settingsIntent, 102);
                return;
            }

            Uri apkUri = FileProvider.getUriForFile(
                this,
                getPackageName() + ".fileprovider",
                apkFile);

            Intent intent = new Intent(Intent.ACTION_VIEW);
            intent.setDataAndType(
                apkUri,
                "application/vnd.android.package-archive");
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

            startActivity(intent);

            updateStatus.setText(
                "Android installer opened. Approve the update there.");

        } catch (Exception e) {
            updateStatus.setText(
                "INSTALLATION ERROR: " + e.getMessage());
        }
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


    private void saveCurrentScan() {
        if (lastScanReport == null) {
            Toast.makeText(
                this,
                "No structured scan report available yet.",
                Toast.LENGTH_LONG
            ).show();
            return;
        }

        runTask("Saving scan", () -> {
            try {
                JSONObject copy = new JSONObject(lastScanReport.toString());
                int id = PstHistory.saveScan(this, copy);

                showResult(
                    "SCAN SAVED SUCCESSFULLY\n\n" +
                    "History ID: #" + id + "\n" +
                    "Target: " + copy.optString("target", "Unknown") + "\n" +
                    "Type: " + copy.optString("scan_type", "Unknown")
                );
            } catch (Exception e) {
                showResult("SAVE FAILED\n\n" + e.getMessage());
            }
        });
    }

    private void viewScanHistory() {
        runTask("Loading scan history", () -> {
            try {
                java.util.List<JSONObject> scans =
                    PstHistory.newestFirst(this);

                if (scans.isEmpty()) {
                    showResult("SCAN HISTORY\n\nNo saved scans yet.");
                    return;
                }

                StringBuilder result = new StringBuilder();
                result.append("PIGEON SECURITY TOOLKIT\n");
                result.append("SCAN HISTORY\n\n");

                for (JSONObject scan : scans) {
                    result.append("ID: #")
                        .append(scan.optInt("history_id", -1))
                        .append("\n");

                    result.append("Type: ")
                        .append(scan.optString("scan_type", "Unknown"))
                        .append("\n");

                    result.append("Target: ")
                        .append(scan.optString("target", "Unknown"))
                        .append("\n");

                    result.append("Date: ")
                        .append(scan.optString("finished_at", "Unknown"))
                        .append("\n");

                    result.append("-------------------------\n");
                }

                showResult(result.toString());

            } catch (Exception e) {
                showResult("HISTORY ERROR\n\n" + e.getMessage());
            }
        });
    }

    private void promptSavedScan() {
        EditText input = new EditText(this);
        input.setSingleLine(true);
        input.setInputType(
            android.text.InputType.TYPE_CLASS_NUMBER
        );
        input.setHint("Enter saved scan ID");

        new AlertDialog.Builder(this)
            .setTitle("VIEW SAVED SCAN")
            .setView(input)
            .setNegativeButton("CANCEL", null)
            .setPositiveButton("VIEW", (dialog, which) -> {
                String value = input.getText().toString().trim();

                try {
                    int id = Integer.parseInt(value);
                    showSavedScan(id);
                } catch (Exception e) {
                    Toast.makeText(
                        this,
                        "Enter a valid scan ID.",
                        Toast.LENGTH_SHORT
                    ).show();
                }
            })
            .show();
    }

    private void showSavedScan(int scanId) {
        runTask("Loading saved scan", () -> {
            try {
                JSONObject scan = PstHistory.getScan(this, scanId);

                showResult(
                    "SAVED SECURITY REPORT\n\n" +
                    scan.toString(2)
                );
            } catch (Exception e) {
                showResult("SCAN NOT FOUND\n\n" + e.getMessage());
            }
        });
    }

    private void promptCompareScans() {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(25, 10, 25, 5);

        EditText oldInput = new EditText(this);
        oldInput.setSingleLine(true);
        oldInput.setInputType(
            android.text.InputType.TYPE_CLASS_NUMBER
        );
        oldInput.setHint("Older scan ID");

        EditText newInput = new EditText(this);
        newInput.setSingleLine(true);
        newInput.setInputType(
            android.text.InputType.TYPE_CLASS_NUMBER
        );
        newInput.setHint("Newer scan ID");

        layout.addView(oldInput);
        layout.addView(newInput);

        new AlertDialog.Builder(this)
            .setTitle("COMPARE SECURITY REPORTS")
            .setView(layout)
            .setNegativeButton("CANCEL", null)
            .setPositiveButton("COMPARE", (dialog, which) -> {
                try {
                    int oldId = Integer.parseInt(
                        oldInput.getText().toString().trim()
                    );

                    int newId = Integer.parseInt(
                        newInput.getText().toString().trim()
                    );

                    if (oldId == newId) {
                        throw new Exception(
                            "Choose two different scan IDs."
                        );
                    }

                    compareSavedScans(oldId, newId);

                } catch (Exception e) {
                    Toast.makeText(
                        this,
                        e.getMessage() == null
                            ? "Enter two valid scan IDs."
                            : e.getMessage(),
                        Toast.LENGTH_LONG
                    ).show();
                }
            })
            .show();
    }

    private boolean isPortScanReport(JSONObject scan) {
        JSONArray results = scan.optJSONArray("results");

        if (results == null || results.length() == 0) {
            return false;
        }

        for (int i = 0; i < results.length(); i++) {
            JSONObject item = results.optJSONObject(i);

            if (item == null ||
                !item.has("port") ||
                !item.has("state")) {
                return false;
            }
        }

        return true;
    }

    private void compareSavedScans(int oldId, int newId) {
        runTask("Comparing security reports", () -> {
            try {
                JSONObject oldScan = PstHistory.getScan(this, oldId);
                JSONObject newScan = PstHistory.getScan(this, newId);

                if (!isPortScanReport(oldScan) ||
                    !isPortScanReport(newScan)) {
                    throw new Exception(
                        "Comparison currently supports port scan reports only."
                    );
                }

                if (!oldScan.optString("target").equalsIgnoreCase(
                    newScan.optString("target")
                )) {
                    throw new Exception(
                        "Both scans must belong to the same target."
                    );
                }

                JSONObject comparison =
                    PstHistory.compareScans(oldScan, newScan);

                showResult(
                    "PIGEON SECURITY TOOLKIT\n" +
                    "SECURITY COMPARISON\n\n" +
                    comparison.toString(2)
                );

            } catch (Exception e) {
                showResult(
                    "COMPARISON FAILED\n\n" + e.getMessage()
                );
            }
        });
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
        lastScanReport = null;
        try {
            String domain = getDomain();

            JSONObject report = PstDns.inspect(domain);

            JSONObject historyReport = new JSONObject();
            historyReport.put("tool", "Pigeon Security Toolkit");
            historyReport.put("scan_type", "DNS Intelligence");
            historyReport.put("target", domain);
            historyReport.put("details", report);
            lastScanReport = historyReport;

            showResult(
                "PIGEON SECURITY TOOLKIT\n" +
                "DNS INTELLIGENCE\n\n" +
                report.toString(2)
            );

        } catch (Exception e) {
            showResult("DNS INTELLIGENCE FAILED\n\n" + e.getMessage());
        }
    }

    private void websiteAudit() {
        lastScanReport = null;
        HttpURLConnection connection = null;

        try {
            String domain = getDomain();
            URL url = new URL("https://" + domain);

            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(10000);
            connection.setReadTimeout(10000);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("User-Agent", "PST-Android/2.0");

            int code = connection.getResponseCode();
            String finalUrl = connection.getURL().toString();
            boolean finalUrlHttps =
                "https".equalsIgnoreCase(new URL(finalUrl).getProtocol());

            String[] headers = {
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy",
                "Permissions-Policy"
            };

            StringBuilder result = new StringBuilder();
            int findings = 0;

            result.append("PIGEON SECURITY TOOLKIT\n");
            result.append("WEBSITE SECURITY AUDIT\n\n");
            result.append("Domain: ").append(domain).append("\n");
            result.append("Final URL: ").append(finalUrl).append("\n");
            result.append("HTTP Status: ").append(code).append("\n");
            result.append("HTTPS: ")
                .append(finalUrlHttps ? "VERIFIED CONNECTION" : "NOT HTTPS AFTER REDIRECT")
                .append("\n\n");
            result.append("SECURITY HEADERS\n");
            result.append("------------------------------\n");

            for (String header : headers) {
                String value = connection.getHeaderField(header);

                result.append("\n").append(header).append(":\n");

                if (value == null || value.trim().isEmpty()) {
                    result.append("NOT DETECTED\n");
                    findings++;
                } else {
                    result.append(value).append("\n");
                }
            }

            result.append("\nCOOKIE SECURITY\n");
            result.append("------------------------------\n");

            int cookieCount = 0;

            for (java.util.Map.Entry<String, java.util.List<String>> entry
                    : connection.getHeaderFields().entrySet()) {

                if (entry.getKey() == null ||
                        !entry.getKey().equalsIgnoreCase("Set-Cookie") ||
                        entry.getValue() == null) {
                    continue;
                }

                for (String cookie : entry.getValue()) {
                    cookieCount++;

                    String[] attributes = cookie.split(";");
                    boolean secure = false;
                    boolean httpOnly = false;
                    boolean sameSite = false;

                    for (String attribute : attributes) {
                        String flag = attribute.trim()
                            .toLowerCase(java.util.Locale.ROOT);

                        if ("secure".equals(flag)) {
                            secure = true;
                        } else if ("httponly".equals(flag)) {
                            httpOnly = true;
                        } else if (flag.startsWith("samesite=")) {
                            sameSite = true;
                        }
                    }

                    result.append("\nCookie ").append(cookieCount).append("\n");
                    result.append("Secure: ")
                        .append(secure ? "YES" : "NO").append("\n");
                    result.append("HttpOnly: ")
                        .append(httpOnly ? "YES" : "NO").append("\n");
                    result.append("SameSite: ")
                        .append(sameSite ? "PRESENT" : "NOT DETECTED")
                        .append("\n");

                    if (!secure) findings++;
                    if (!httpOnly) findings++;
                    if (!sameSite) findings++;
                }
            }

            if (cookieCount == 0) {
                result.append("No Set-Cookie headers observed.\n");
            }

            result.append("\n------------------------------\n");
            result.append("MISSING / REVIEW ITEMS: ")
                .append(findings).append("\n");
            result.append("\nNOTICE: These are review indicators, not confirmed vulnerabilities.");
            result.append("\nHeader presence alone does not prove a secure configuration.");

            JSONObject auditReport = new JSONObject();
            auditReport.put("tool", "Pigeon Security Toolkit");
            auditReport.put("scan_type", "Website Security Audit");
            auditReport.put("target", domain);
            auditReport.put("http_status", code);
            auditReport.put("final_url", finalUrl);
            auditReport.put("review_items", findings);
            auditReport.put("details", result.toString());
            lastScanReport = auditReport;

            showResult(result.toString());

        } catch (Exception e) {
            showResult("WEBSITE AUDIT FAILED\n\n" + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private void sslInspect() {
        lastScanReport = null;
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

            JSONObject sslReport = new JSONObject();
            sslReport.put("tool", "Pigeon Security Toolkit");
            sslReport.put("scan_type", "SSL/TLS Inspection");
            sslReport.put("target", domain);
            sslReport.put("cipher_suite", connection.getCipherSuite());
            sslReport.put("details", result.toString());
            lastScanReport = sslReport;

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

        if (requestCode == 102) {
            if (android.os.Build.VERSION.SDK_INT < 26 ||
                getPackageManager().canRequestPackageInstalls()) {
                installUpdate(pendingUpdateFile);
            } else {
                updateStatus.setText("Installation permission not granted.");
            }
            return;
        }

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
