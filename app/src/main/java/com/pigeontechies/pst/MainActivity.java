package com.pigeontechies.pst;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.Manifest;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.provider.Settings;
import android.os.Bundle;
import android.content.Intent;
import android.net.Uri;
import android.graphics.Color;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.pdf.PdfDocument;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.View;
import android.widget.FrameLayout;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.view.animation.RotateAnimation;
import android.view.animation.ScaleAnimation;
import android.os.Handler;
import android.os.Looper;
import android.graphics.drawable.GradientDrawable;
import android.widget.*;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.net.InetAddress;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.net.HttpURLConnection;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;
import org.json.JSONArray;
import java.util.ArrayList;
import androidx.core.content.FileProvider;

public class MainActivity extends Activity {

    private LinearLayout root;
    private LinearLayout mainLayout;
    private LinearLayout navigationBar;
    private FrameLayout pageContainer;
    private int currentPage = 0;
    private EditText domainInput;
    private TextView output;
    private JSONObject lastScanReport;
    private ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler splashHandler = new Handler(Looper.getMainLooper());

    private static final String UPDATE_MANIFEST_URL =
        "https://raw.githubusercontent.com/Osule253/pigeon-security-toolkit/main/pst-update.json";

    private TextView versionLabel;
    private TextView updateStatus;
    private boolean updateCheckInProgress = false;
    private File pendingUpdateFile;
    private static final int UPDATE_NOTIFICATION_ID = 1300;
    private static final String UPDATE_CHANNEL_ID = "pst_updates";

    private final int BG = Color.rgb(12, 12, 12);
    private final int PANEL = Color.rgb(28, 28, 28);
    private final int SILVER = Color.rgb(210, 210, 210);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        showSplashScreen();
    }


    private int dp(float value) {
        return (int) (value * getResources().getDisplayMetrics().density + 0.5f);
    }

    private void showSplashScreen() {
        LinearLayout splash = new LinearLayout(this);
        splash.setOrientation(LinearLayout.VERTICAL);
        splash.setGravity(Gravity.CENTER);
        splash.setBackgroundColor(Color.rgb(8, 8, 8));
        splash.setPadding(dp(24), dp(24), dp(24), dp(24));

        FrameLayout emblem = new FrameLayout(this);

        GradientDrawable ringShape = new GradientDrawable();
        ringShape.setShape(GradientDrawable.OVAL);
        ringShape.setColor(Color.TRANSPARENT);
        ringShape.setStroke(dp(3), SILVER);

        View ring = new View(this);
        ring.setBackground(ringShape);

        FrameLayout.LayoutParams ringParams = new FrameLayout.LayoutParams(
            dp(170), dp(170), Gravity.CENTER
        );
        emblem.addView(ring, ringParams);

        TextView logo = new TextView(this);
        logo.setText("PST");
        logo.setTextColor(Color.WHITE);
        logo.setTextSize(38);
        logo.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        logo.setGravity(Gravity.CENTER);

        GradientDrawable logoShape = new GradientDrawable();
        logoShape.setColor(Color.rgb(24, 24, 24));
        logoShape.setCornerRadius(dp(24));
        logoShape.setStroke(dp(2), SILVER);
        logo.setBackground(logoShape);

        FrameLayout.LayoutParams logoParams = new FrameLayout.LayoutParams(
            dp(112), dp(112), Gravity.CENTER
        );
        emblem.addView(logo, logoParams);

        LinearLayout.LayoutParams emblemParams = new LinearLayout.LayoutParams(
            dp(190), dp(190)
        );
        splash.addView(emblem, emblemParams);

        RotateAnimation rotation = new RotateAnimation(
            0, 360,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        );
        rotation.setDuration(8000);
        rotation.setRepeatCount(Animation.INFINITE);
        rotation.setInterpolator(new android.view.animation.LinearInterpolator());
        ring.startAnimation(rotation);

        ScaleAnimation pulse = new ScaleAnimation(
            0.96f, 1.04f, 0.96f, 1.04f,
            Animation.RELATIVE_TO_SELF, 0.5f,
            Animation.RELATIVE_TO_SELF, 0.5f
        );
        pulse.setDuration(1800);
        pulse.setRepeatMode(Animation.REVERSE);
        pulse.setRepeatCount(Animation.INFINITE);
        pulse.setInterpolator(new AccelerateDecelerateInterpolator());
        logo.startAnimation(pulse);

        TextView brand = new TextView(this);
        brand.setText("PIGEON SECURITY TOOLKIT");
        brand.setTextColor(SILVER);
        brand.setTextSize(14);
        brand.setLetterSpacing(0.16f);
        brand.setGravity(Gravity.CENTER);
        brand.setPadding(0, dp(28), 0, dp(20));
        splash.addView(brand);

        TextView phase = new TextView(this);
        phase.setTextColor(Color.WHITE);
        phase.setTextSize(19);
        phase.setTypeface(Typeface.create("sans-serif", Typeface.BOLD));
        phase.setLetterSpacing(0.20f);
        phase.setGravity(Gravity.CENTER);
        splash.addView(phase);

        TextView tagline = new TextView(this);
        tagline.setText("ANDROID SECURITY EDITION");
        tagline.setTextColor(Color.GRAY);
        tagline.setTextSize(10);
        tagline.setGravity(Gravity.CENTER);
        tagline.setPadding(0, dp(22), 0, 0);
        splash.addView(tagline);

        setContentView(splash);

        showSplashPhase(phase, "SECURE");

        splashHandler.postDelayed(
            () -> showSplashPhase(phase, "INSPECT"), 3000
        );

        splashHandler.postDelayed(
            () -> showSplashPhase(phase, "DEFEND"), 6000
        );

        splashHandler.postDelayed(() -> {
            if (!isFinishing() && !isDestroyed()) {
                buildInterface();
                checkForUpdates(false);
            }
        }, 10000);
    }

    private void showSplashPhase(TextView phase, String word) {
        AlphaAnimation fadeOut = new AlphaAnimation(1f, 0f);
        fadeOut.setDuration(250);
        fadeOut.setAnimationListener(new Animation.AnimationListener() {
            @Override
            public void onAnimationStart(Animation animation) {}

            @Override
            public void onAnimationEnd(Animation animation) {
                phase.setText(word);

                AlphaAnimation fadeIn = new AlphaAnimation(0f, 1f);
                fadeIn.setDuration(450);
                fadeIn.setInterpolator(new AccelerateDecelerateInterpolator());
                phase.startAnimation(fadeIn);
            }

            @Override
            public void onAnimationRepeat(Animation animation) {}
        });

        phase.startAnimation(fadeOut);
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
        mainLayout = new LinearLayout(this);
        mainLayout.setOrientation(LinearLayout.VERTICAL);
        mainLayout.setBackgroundColor(BG);

        pageContainer = new FrameLayout(this);
        mainLayout.addView(pageContainer,
            new LinearLayout.LayoutParams(-1, 0, 1));

        navigationBar = new LinearLayout(this);
        navigationBar.setOrientation(LinearLayout.HORIZONTAL);
        navigationBar.setBackgroundColor(PANEL);
        mainLayout.addView(navigationBar,
            new LinearLayout.LayoutParams(-1, dp(64)));

        setContentView(mainLayout);
        showPage(0);
    }

    private void showPage(int page) {
        currentPage = page;
        pageContainer.removeAllViews();

        ScrollView scroll = new ScrollView(this);
        root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(22), dp(25), dp(22), dp(25));
        root.setBackgroundColor(BG);
        scroll.addView(root);

        pageContainer.addView(scroll,
            new FrameLayout.LayoutParams(-1, -1));

        if (page == 0) {
            showHomePage();
        } else if (page == 1) {
            showToolsPage();
        } else if (page == 2) {
            showReportsPage();
        } else {
            showSettingsPage();
        }

        buildNavigation();
    }

    private void showHomePage() {
        TextView brand = new TextView(this);
        brand.setText("PIGEON TECHIES");
        brand.setTextColor(SILVER);
        brand.setTextSize(13);
        brand.setLetterSpacing(0.18f);
        root.addView(brand);

        TextView title = new TextView(this);
        title.setText("PIGEON SECURITY\\nTOOLKIT");
        title.setTextColor(Color.WHITE);
        title.setTextSize(29);
        title.setTypeface(null, Typeface.BOLD);
        title.setPadding(0, dp(18), 0, dp(5));
        root.addView(title);

        versionLabel = new TextView(this);
        versionLabel.setText("ANDROID EDITION  •  VERSION " + getAppVersion());
        versionLabel.setTextColor(SILVER);
        versionLabel.setTextSize(11);
        root.addView(versionLabel);

        section("SECURITY STATUS");
        TextView status = new TextView(this);
        status.setText("SECURE. INSPECT. DEFEND.");
        status.setTextColor(Color.GREEN);
        status.setTextSize(13);
        root.addView(status);

        section("QUICK ACCESS");
        addButton("OPEN SECURITY TOOLS", v -> showPage(1));
        addButton("VIEW REPORTS & SCAN HISTORY", v -> showPage(2));
        addButton("SETTINGS & LANGUAGE", v -> showPage(3));

        section("SOFTWARE UPDATES");
        updateStatus = new TextView(this);
        updateStatus.setText("Checking for updates will be available here.");
        updateStatus.setTextColor(SILVER);
        updateStatus.setTextSize(12);
        updateStatus.setPadding(dp(12), dp(14), dp(12), dp(14));
        updateStatus.setBackgroundColor(PANEL);
        root.addView(updateStatus);
        addButton("CHECK FOR UPDATES", v -> checkForUpdates(true));

        TextView footer = new TextView(this);
        footer.setText("\\nPIGEON TECHIES\\npigeontechies.com");
        footer.setTextColor(Color.GRAY);
        footer.setTextSize(12);
        footer.setGravity(Gravity.CENTER);
        footer.setPadding(0, dp(30), 0, dp(10));
        root.addView(footer);
    }

    private void showToolsPage() {
        section("WEBSITE SECURITY");

        domainInput = new EditText(this);
        domainInput.setSingleLine(true);
        domainInput.setHint("Enter domain e.g. example.com");
        domainInput.setHintTextColor(Color.GRAY);
        domainInput.setTextColor(Color.WHITE);
        domainInput.setPadding(dp(15), dp(12), dp(15), dp(12));
        domainInput.setBackgroundColor(PANEL);
        root.addView(domainInput);

        addButton("DNS LOOKUP", v -> runTask("DNS lookup", this::dnsLookup));
        addButton("WEBSITE SECURITY AUDIT", v -> runTask("Website audit", this::websiteAudit));
        addButton("SSL / TLS INSPECTION", v -> runTask("SSL inspection", this::sslInspect));
        addButton("TCP PORT SCAN (COMMON PORTS)", v -> runTask("TCP port scan", this::portScan));

        section("FILE SECURITY");
        addButton("SELECT FILE & CALCULATE SHA-256", v -> chooseFile());

        section("SCAN RESULTS");
        output = new TextView(this);
        output.setText("Ready. Select a security tool to begin.");
        output.setTextColor(SILVER);
        output.setTextSize(13);
        output.setPadding(dp(16), dp(18), dp(16), dp(18));
        output.setBackgroundColor(PANEL);
        root.addView(output);
    }

    private void showReportsPage() {
        section("REPORTS");
        addButton("SAVE CURRENT SCAN", v -> saveCurrentScan());
        addButton("VIEW SCAN HISTORY", v -> viewScanHistory());
        addButton("VIEW SAVED SCAN", v -> promptSavedScan());
        addButton("COMPARE TWO SCANS", v -> promptCompareScans());
        section("REPORT EXPORT");
        addButton("GENERATE PDF REPORT", v -> generatePdfReport());
    }

    private void showSettingsPage() {
        section("SETTINGS");
        section("LANGUAGE");
        addButton("ENGLISH", v ->
            Toast.makeText(this, "English selected.", Toast.LENGTH_SHORT).show());
        addButton("KISWAHILI", v ->
            Toast.makeText(this, "Kiswahili will be configured next.", Toast.LENGTH_SHORT).show());
        addButton("FRANÇAIS", v ->
            Toast.makeText(this, "French will be configured next.", Toast.LENGTH_SHORT).show());

        section("ABOUT");
        TextView about = new TextView(this);
        about.setText("PIGEON SECURITY TOOLKIT\\nPIGEON TECHIES\\nVersion " + getAppVersion() +
            "\\npigeontechies.com");
        about.setTextColor(SILVER);
        about.setTextSize(13);
        root.addView(about);
    }

    private void buildNavigation() {
        navigationBar.removeAllViews();
        String[] labels = {"HOME", "TOOLS", "REPORTS", "SETTINGS"};

        for (int i = 0; i < labels.length; i++) {
            final int selected = i;
            TextView tab = new TextView(this);
            tab.setText(labels[i]);
            tab.setTextSize(10);
            tab.setGravity(Gravity.CENTER);
            tab.setTypeface(null, Typeface.BOLD);
            tab.setTextColor(currentPage == i ? Color.WHITE : SILVER);
            tab.setBackgroundColor(currentPage == i
                ? Color.rgb(55, 55, 55) : PANEL);
            navigationBar.addView(tab,
                new LinearLayout.LayoutParams(0, -1, 1));
            tab.setOnClickListener(v -> showPage(selected));
        }
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


    private void setUpdateStatus(String message) {
        runOnUiThread(() -> {
            if (updateStatus != null) updateStatus.setText(message);
        });
    }

    private void postUpdateNotification(
            String message, int progress, boolean indeterminate, boolean ongoing) {
        try {
            NotificationManager manager =
                (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (manager == null) return;

            if (android.os.Build.VERSION.SDK_INT >= 26) {
                NotificationChannel channel = new NotificationChannel(
                    UPDATE_CHANNEL_ID, "PST software updates",
                    NotificationManager.IMPORTANCE_LOW);
                manager.createNotificationChannel(channel);
            }

            Notification.Builder builder;
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                builder = new Notification.Builder(this, UPDATE_CHANNEL_ID);
            } else {
                builder = new Notification.Builder(this);
            }

            builder.setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("Pigeon Security Toolkit")
                .setContentText(message)
                .setOnlyAlertOnce(true)
                .setOngoing(ongoing);

            if (ongoing) {
                builder.setProgress(100, progress, indeterminate);
            } else {
                builder.setProgress(0, 0, false).setAutoCancel(true);
            }

            manager.notify(UPDATE_NOTIFICATION_ID, builder.build());
        } catch (SecurityException ignored) {
            // A denied notification permission must not interrupt the download.
        }
    }

    private void downloadUpdate(String apkUrl, String expectedSha256) {
        if (apkUrl == null || !apkUrl.startsWith("https://github.com/Osule253/pigeon-security-toolkit/releases/download/") ||
            expectedSha256 == null ||
            !expectedSha256.matches("(?i)[a-f0-9]{64}")) {
            updateStatus.setText("Rejected: Invalid update URL or checksum.");
            return;
        }

        if (android.os.Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(
                new String[]{Manifest.permission.POST_NOTIFICATIONS}, 104);
        }

        setUpdateStatus("Downloading update...");
        postUpdateNotification("Preparing secure download...", 0, true, true);

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
                int contentLength = connection.getContentLength();
                int lastProgress = -1;

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

                        int progress = contentLength > 0
                            ? (int) Math.min(100, total * 100 / contentLength)
                            : -1;

                        if (progress >= 0 && progress / 5 != lastProgress / 5) {
                            lastProgress = progress;
                            postUpdateNotification(
                                "Downloading update: " + progress + "%",
                                progress, false, true);
                            setUpdateStatus("Downloading update: " + progress + "%");
                        } else if (progress < 0 &&
                                   total / (1024 * 1024) !=
                                   (total - count) / (1024 * 1024)) {
                            postUpdateNotification(
                                "Downloaded " + (total / 1024 / 1024) + " MB",
                                0, true, true);
                        }
                    }
                }

                StringBuilder hash = new StringBuilder();

                for (byte b : digest.digest()) {
                    hash.append(String.format("%02x", b & 0xff));
                }

                if (!hash.toString().equalsIgnoreCase(expectedSha256)) {
                    throw new Exception("SHA-256 verification failed.");
                }

                if (!verifyUpdateSignature(apkFile)) {
                    throw new Exception(
                        "APK signing certificate does not match installed PST.");
                }

                File verifiedFile = apkFile;
                pendingUpdateFile = verifiedFile;
                postUpdateNotification(
                    "Download verified. Opening installer.",
                    100, false, false);

                runOnUiThread(() -> {
                    updateStatus.setText("Download verified.");
                    installUpdate(verifiedFile);
                });

            } catch (Exception e) {
                if (apkFile != null) apkFile.delete();

                postUpdateNotification(
                    "Update failed: " + e.getMessage(), 0, false, false);
                runOnUiThread(() ->
                    updateStatus.setText("UPDATE FAILED: " + e.getMessage()));
            } finally {
                if (connection != null) connection.disconnect();
            }
        });
    }

    private boolean verifyUpdateSignature(File apkFile) throws Exception {
        int flags = android.os.Build.VERSION.SDK_INT >= 28
            ? PackageManager.GET_SIGNING_CERTIFICATES
            : PackageManager.GET_SIGNATURES;

        PackageInfo installed =
            getPackageManager().getPackageInfo(getPackageName(), flags);

        PackageInfo downloaded =
            getPackageManager().getPackageArchiveInfo(
                apkFile.getAbsolutePath(), flags);

        if (downloaded == null ||
            !getPackageName().equals(downloaded.packageName)) {
            return false;
        }

        android.content.pm.Signature[] installedSigners;
        android.content.pm.Signature[] downloadedSigners;

        if (android.os.Build.VERSION.SDK_INT >= 28) {
            if (installed.signingInfo == null ||
                downloaded.signingInfo == null) return false;

            installedSigners =
                installed.signingInfo.getApkContentsSigners();
            downloadedSigners =
                downloaded.signingInfo.getApkContentsSigners();
        } else {
            installedSigners = installed.signatures;
            downloadedSigners = downloaded.signatures;
        }

        if (installedSigners == null || downloadedSigners == null ||
            installedSigners.length == 0 ||
            installedSigners.length != downloadedSigners.length) {
            return false;
        }

        java.util.Set<String> installedHashes = new java.util.HashSet<>();
        java.util.Set<String> downloadedHashes = new java.util.HashSet<>();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

        for (android.content.pm.Signature signer : installedSigners) {
            installedHashes.add(
                bytesToHex(sha256.digest(signer.toByteArray())));
        }

        for (android.content.pm.Signature signer : downloadedSigners) {
            downloadedHashes.add(
                bytesToHex(sha256.digest(signer.toByteArray())));
        }

        return installedHashes.equals(downloadedHashes);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b & 0xff));
        }
        return result.toString();
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


    private void portScan() {
        lastScanReport = null;
        try {
            String host = getDomain();
            int[] ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017};

            InetAddress address = InetAddress.getByName(host);
            JSONArray openPorts = new JSONArray();
            StringBuilder result = new StringBuilder();

            result.append("PIGEON SECURITY TOOLKIT\nTCP PORT SCAN\n\n")
                    .append("Target: ").append(host).append("\n")
                    .append("Resolved IP: ").append(address.getHostAddress()).append("\n")
                    .append("Ports checked: ").append(ports.length).append("\n\n");

            for (int port : ports) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(address, port), 400);
                    openPorts.put(port);
                    result.append(port).append("/tcp OPEN\n");
                } catch (java.io.IOException ignored) {
                    // Closed, filtered or unreachable.
                }
            }

            if (openPorts.length() == 0) {
                result.append("No open ports found in the selected list.\n");
            }

            result.append("\nOnly scan systems you own or are authorized to assess.");

            JSONObject report = new JSONObject();
            report.put("tool", "Pigeon Security Toolkit");
            report.put("scan_type", "TCP Port Scan");
            report.put("target", host);
            report.put("resolved_ip", address.getHostAddress());
            report.put("ports_scanned", ports.length);
            report.put("open_ports", openPorts);
            report.put("finished_at", new java.text.SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
                    .format(new java.util.Date()));

            lastScanReport = report;
            showResult(result.toString());

        } catch (Exception e) {
            showResult("TCP PORT SCAN FAILED\n\n" + e.getMessage());
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

        if (requestCode == CREATE_PDF_REQUEST &&
            resultCode == RESULT_OK && data != null) {
            Uri pdfUri = data.getData();
            if (pdfUri != null) {
                writePdfReport(pdfUri);
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


    private static final int CREATE_PDF_REQUEST = 103;

    private void generatePdfReport() {
        if (lastScanReport == null) {
            Toast.makeText(this, "Run a security scan first.",
                Toast.LENGTH_LONG).show();
            return;
        }

        try {
            Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
            intent.addCategory(Intent.CATEGORY_OPENABLE);
            intent.setType("application/pdf");
            intent.putExtra(Intent.EXTRA_TITLE,
                "PST-Security-Report-" + System.currentTimeMillis() + ".pdf");
            startActivityForResult(intent, CREATE_PDF_REQUEST);
        } catch (Exception e) {
            Toast.makeText(this, "Cannot open PDF save dialog: " +
                e.getMessage(), Toast.LENGTH_LONG).show();
        }
    }

    private void writePdfReport(Uri uri) {
        PdfDocument document = new PdfDocument();
        Bitmap logo = null;

        try {
            ArrayList<String> lines = new ArrayList<>();
            String scanType = lastScanReport.optString("scan_type", "Security Assessment");
            String target = lastScanReport.optString("target", "Not specified");
            String finished = lastScanReport.optString("finished_at", "Not recorded");

            reportHeading(lines, "ASSESSMENT OVERVIEW");
            reportLine(lines, "Assessment type: " + scanType);
            reportLine(lines, "Target assessed: " + target);
            reportLine(lines, "Date completed: " + finished);
            reportLine(lines, "This document presents the results of a security assessment "
                    + "performed using Pigeon Security Toolkit.");

            String type = scanType.toLowerCase(java.util.Locale.US);

            if (type.contains("tcp") || type.contains("port")) {
                reportHeading(lines, "NETWORK PORT SCAN RESULTS");

                String ip = lastScanReport.optString("resolved_ip", "");
                if (!ip.isEmpty()) {
                    reportLine(lines, "Resolved network address: " + ip);
                }

                int checked = lastScanReport.optInt("ports_scanned", 0);
                JSONArray ports = lastScanReport.optJSONArray("open_ports");
                int count = ports == null ? 0 : ports.length();

                reportLine(lines, "Number of ports tested: " + checked);
                reportLine(lines, "Open ports detected: " + count);

                reportHeading(lines, "WHAT THE RESULTS MEAN");

                if (count == 0) {
                    reportLine(lines, "No open ports were detected among the ports tested. "
                            + "This does not prove that the entire system has no exposed services.");
                } else {
                    reportLine(lines, count + " port(s) accepted a TCP connection during "
                            + "the assessment. This means a service may be reachable through "
                            + "those network ports.");
                    reportLine(lines, "An open port is not automatically a security "
                            + "vulnerability. The service, its purpose and its configuration "
                            + "must be examined before a risk can be confirmed.");

                    reportHeading(lines, "PORT-BY-PORT FINDINGS");

                    for (int i = 0; i < ports.length(); i++) {
                        int port = ports.optInt(i, -1);
                        String service;
                        String explanation;

                        switch (port) {
                            case 21:
                                service = "FTP";
                                explanation = "File Transfer Protocol. Check whether "
                                        + "file transfers are necessary and securely configured.";
                                break;
                            case 22:
                                service = "SSH";
                                explanation = "Secure Shell. Used for remote administration. "
                                        + "Restrict access to trusted administrators.";
                                break;
                            case 23:
                                service = "Telnet";
                                explanation = "Remote terminal service. It does not encrypt "
                                        + "traffic and should generally be avoided.";
                                break;
                            case 25:
                                service = "SMTP";
                                explanation = "Mail transfer service. Review relay restrictions "
                                        + "and mail server configuration.";
                                break;
                            case 53:
                                service = "DNS";
                                explanation = "Domain Name System. Used to resolve domain "
                                        + "names into network addresses. Review DNS exposure "
                                        + "and configuration.";
                                break;
                            case 80:
                                service = "HTTP";
                                explanation = "Standard web traffic. Confirm that the website "
                                        + "redirects visitors to HTTPS where appropriate.";
                                break;
                            case 110:
                                service = "POP3";
                                explanation = "Email retrieval service. Check encryption "
                                        + "and whether public access is required.";
                                break;
                            case 143:
                                service = "IMAP";
                                explanation = "Email access service. Confirm secure "
                                        + "configuration and authentication.";
                                break;
                            case 443:
                                service = "HTTPS";
                                explanation = "Encrypted web traffic. Review the TLS "
                                        + "certificate and server configuration.";
                                break;
                            case 445:
                                service = "SMB";
                                explanation = "File sharing service. Public exposure should "
                                        + "be carefully restricted.";
                                break;
                            case 3306:
                                service = "MySQL";
                                explanation = "Database service. Database access should "
                                        + "normally be restricted to trusted systems.";
                                break;
                            case 3389:
                                service = "RDP";
                                explanation = "Remote Desktop Protocol. Restrict remote "
                                        + "access and enforce strong authentication.";
                                break;
                            case 5432:
                                service = "PostgreSQL";
                                explanation = "Database service. Check network restrictions "
                                        + "and authentication controls.";
                                break;
                            case 5900:
                                service = "VNC";
                                explanation = "Remote desktop service. Restrict access "
                                        + "and use secure remote administration.";
                                break;
                            case 6379:
                                service = "Redis";
                                explanation = "Data store service. Ensure it is not exposed "
                                        + "unnecessarily to untrusted networks.";
                                break;
                            case 8080:
                                service = "Alternative HTTP";
                                explanation = "Often used by web applications or proxy "
                                        + "services. Identify the application using this port.";
                                break;
                            case 8443:
                                service = "Alternative HTTPS";
                                explanation = "Often used for secure web applications or "
                                        + "administration interfaces. Review access controls.";
                                break;
                            case 9200:
                                service = "Elasticsearch";
                                explanation = "Search and data service. Check authentication "
                                        + "and network exposure.";
                                break;
                            case 27017:
                                service = "MongoDB";
                                explanation = "Database service. Verify authentication "
                                        + "and restrict external access.";
                                break;
                            default:
                                service = "Unknown service";
                                explanation = "Identify the application listening on this "
                                        + "port and verify that its exposure is intentional.";
                                break;
                        }

                        reportLine(lines, "Port " + port + "/TCP — " + service);
                        reportLine(lines, "Explanation: " + explanation);
                    }
                }

                reportHeading(lines, "SECURITY RECOMMENDATIONS");
                reportLine(lines, "1. Confirm that each exposed service is required.");
                reportLine(lines, "2. Restrict unnecessary public network access.");
                reportLine(lines, "3. Review firewall rules and access permissions.");
                reportLine(lines, "4. Check service versions and security configurations.");
                reportLine(lines, "5. Conduct further testing before declaring a vulnerability.");
            } else if (type.contains("dns")) {
                reportHeading(lines, "DNS ASSESSMENT");
                reportLine(lines, "A DNS lookup examines how the target domain is resolved "
                        + "and identifies the DNS information returned during the assessment.");
                reportLine(lines, "Review the returned records to confirm that they point "
                        + "to the intended services and infrastructure.");
            } else if (type.contains("ssl") || type.contains("tls")) {
                reportHeading(lines, "SSL / TLS ASSESSMENT");
                reportLine(lines, "This assessment examines information available about "
                        + "the target's encrypted connection.");
                reportLine(lines, "Certificate validity, expiration, hostname matching "
                        + "and supported security settings should be reviewed.");
            } else if (type.contains("website") || type.contains("audit")) {
                reportHeading(lines, "WEBSITE SECURITY ASSESSMENT");
                reportLine(lines, "This assessment reviews the website security indicators "
                        + "collected by Pigeon Security Toolkit.");
                reportLine(lines, "Review the findings below to identify configurations "
                        + "that may require further investigation.");
            } else if (type.contains("hash") || type.contains("file")) {
                reportHeading(lines, "FILE INTEGRITY ASSESSMENT");
                reportLine(lines, "A SHA-256 file hash is a digital fingerprint of the "
                        + "file contents. It can help identify whether two files have "
                        + "identical contents or whether a file has changed.");
                reportLine(lines, "A hash alone does not establish whether a file is "
                        + "malicious or safe.");
            } else {
                reportHeading(lines, "ASSESSMENT FINDINGS");
                reportLine(lines, "The following section explains the technical information "
                        + "collected during this assessment.");
            }

            reportHeading(lines, "TECHNICAL EVIDENCE");
            java.util.Iterator<String> keys = lastScanReport.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                if ("tool".equals(key) || "scan_type".equals(key)
                        || "target".equals(key) || "finished_at".equals(key)
                        || "resolved_ip".equals(key) || "ports_scanned".equals(key)
                        || "open_ports".equals(key)) {
                    continue;
                }
                reportJsonField(lines, key, lastScanReport.opt(key), 0);
            }

            reportHeading(lines, "ASSESSMENT CONCLUSION");
            reportLine(lines, "This report documents the observations collected during "
                    + "the assessment. Findings should be reviewed by the system owner "
                    + "and investigated where necessary.");
            reportLine(lines, "The results represent the tested scope and conditions "
                    + "at the time of scanning. They do not guarantee that all security "
                    + "weaknesses have been identified.");

            reportHeading(lines, "ASSESSMENT INFORMATION");
            reportLine(lines, "Generated by: Pigeon Security Toolkit");
            reportLine(lines, "Report type: Automated security assessment");
            reportLine(lines, "Authorized testing notice: Assess only systems you own "
                    + "or have permission to examine.");

            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inSampleSize = 4;
            logo = BitmapFactory.decodeResource(
                    getResources(), R.drawable.pst_launcher_source, options);

            int linesPerPage = 47;
            int totalPages = Math.max(1,
                    (lines.size() + linesPerPage - 1) / linesPerPage);

            Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
            paint.setTextSize(9);
            paint.setColor(Color.rgb(35, 35, 35));

            for (int pageNumber = 0; pageNumber < totalPages; pageNumber++) {
                PdfDocument.PageInfo info =
                        new PdfDocument.PageInfo.Builder(595, 842,
                                pageNumber + 1).create();
                PdfDocument.Page page = document.startPage(info);
                Canvas canvas = page.getCanvas();
                canvas.drawColor(Color.WHITE);

                paint.setColor(Color.BLACK);
                canvas.drawRect(0, 0, 595, 125, paint);

                if (logo != null) {
                    paint.setFilterBitmap(true);
                    canvas.drawBitmap(logo, null,
                            new RectF(28, 22, 105, 99), paint);
                }

                paint.setColor(Color.WHITE);
                paint.setTextSize(18);
                paint.setTypeface(Typeface.create(
                        Typeface.DEFAULT, Typeface.BOLD));
                canvas.drawText("PIGEON SECURITY TOOLKIT", 125, 55, paint);

                paint.setTextSize(11);
                paint.setTypeface(Typeface.DEFAULT);
                paint.setColor(Color.LTGRAY);
                canvas.drawText("SECURITY ASSESSMENT REPORT", 125, 78, paint);

                paint.setColor(Color.rgb(160, 160, 160));
                canvas.drawText("BUILD. AUTOMATE. INNOVATE.", 125, 98, paint);

                paint.setColor(Color.rgb(35, 35, 35));
                paint.setTextSize(9);
                paint.setTypeface(Typeface.DEFAULT);

                int start = pageNumber * linesPerPage;
                int end = Math.min(start + linesPerPage, lines.size());
                int y = 155;

                for (int i = start; i < end; i++) {
                    String line = lines.get(i);
                    if (line.startsWith("## ")) {
                        paint.setTypeface(Typeface.create(
                                Typeface.DEFAULT, Typeface.BOLD));
                        paint.setTextSize(10);
                        paint.setColor(Color.BLACK);
                        canvas.drawText(line.substring(3), 35, y, paint);
                        paint.setTypeface(Typeface.DEFAULT);
                        paint.setTextSize(9);
                        paint.setColor(Color.rgb(35, 35, 35));
                    } else {
                        canvas.drawText(line, 35, y, paint);
                    }
                    y += 13;
                }

                paint.setColor(Color.GRAY);
                paint.setTextSize(9);
                canvas.drawText("Pigeon Security Toolkit", 35, 817, paint);
                canvas.drawText("Page " + (pageNumber + 1)
                        + " of " + totalPages, 490, 817, paint);

                document.finishPage(page);
            }

            try (OutputStream stream =
                    getContentResolver().openOutputStream(uri)) {
                if (stream == null) {
                    throw new Exception("Cannot open destination file.");
                }
                document.writeTo(stream);
            }

            Toast.makeText(this, "Professional PDF report saved successfully.",
                    Toast.LENGTH_LONG).show();

        } catch (Exception e) {
            Toast.makeText(this, "PDF export failed: " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        } finally {
            document.close();
            if (logo != null) {
                logo.recycle();
            }
        }
    }

    private void reportHeading(ArrayList<String> lines, String heading) {
        lines.add("");
        lines.add("## " + heading);
        lines.add("");
    }

    private void reportLine(ArrayList<String> lines, String text) {
        if (text == null || text.trim().isEmpty()) {
            lines.add("");
            return;
        }

        String remaining = text.trim();
        while (remaining.length() > 88) {
            int split = remaining.lastIndexOf(' ', 88);
            if (split < 30) {
                split = 88;
            }
            lines.add(remaining.substring(0, split));
            remaining = "   " + remaining.substring(split).trim();
        }
        lines.add(remaining);
    }

    private String reportLabel(String key) {
        String label = key.replace('_', ' ').replace('-', ' ');
        StringBuilder result = new StringBuilder();
        for (String word : label.split("\\s+")) {
            if (word.isEmpty()) continue;
            if (result.length() > 0) result.append(' ');
            result.append(Character.toUpperCase(word.charAt(0)));
            if (word.length() > 1) result.append(word.substring(1));
        }
        return result.toString();
    }

    private void reportJsonField(ArrayList<String> lines,
            String key, Object value, int depth) {
        if (depth > 3 || value == null || value == JSONObject.NULL) {
            return;
        }

        String indent = depth == 0 ? "" : "   ".repeat(depth);
        String label = indent + reportLabel(key) + ": ";

        if (value instanceof JSONObject) {
            reportLine(lines, indent + reportLabel(key) + ":");
            JSONObject object = (JSONObject) value;
            java.util.Iterator<String> iterator = object.keys();
            while (iterator.hasNext()) {
                String child = iterator.next();
                reportJsonField(lines, child, object.opt(child), depth + 1);
            }
        } else if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            reportLine(lines, indent + reportLabel(key)
                    + " (" + array.length() + " entries):");
            for (int i = 0; i < array.length(); i++) {
                reportJsonField(lines, "Item " + (i + 1),
                        array.opt(i), depth + 1);
            }
        } else {
            reportLine(lines, label + String.valueOf(value));
        }
    }

    @Override
    protected void onDestroy() {
        splashHandler.removeCallbacksAndMessages(null);
        super.onDestroy();
        executor.shutdown();
    }
}
