package com.pigeontechies.pst;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class PstDns {

    private static final String RESOLVER =
        "https://cloudflare-dns.com/dns-query";

    private static final int[] TYPES = {1, 28, 15, 2, 16, 5, 257};

    private static final String[] NAMES = {
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "CAA"
    };

    private PstDns() {}

    public static JSONObject inspect(String domain) throws Exception {
        domain = validateDomain(domain);

        JSONObject report = new JSONObject();
        JSONObject records = new JSONObject();

        report.put("tool", "Pigeon Security Toolkit");
        report.put("module", "DNS Intelligence");
        report.put("target", domain);

        for (int i = 0; i < TYPES.length; i++) {
            JSONObject answer = query(domain, TYPES[i]);
            records.put(NAMES[i], answer);
        }

        JSONObject dmarc = query("_dmarc." + domain, 16);
        records.put("DMARC", dmarc);

        JSONArray findings = new JSONArray();

        boolean spfFound = false;
        int spfCount = 0;
        boolean dmarcFound = false;
        boolean caaFound = false;

        JSONObject txt = records.optJSONObject("TXT");

        if (txt != null) {
            JSONArray answers = txt.optJSONArray("Answer");

            if (answers != null) {
                for (int i = 0; i < answers.length(); i++) {
                    String value = answers.optJSONObject(i)
                        .optString("data", "");

                    if (value.toLowerCase().contains("v=spf1")) {
                        spfFound = true;
                        spfCount++;

                        if (value.contains("+all")) {
                            findings.put("SPF policy uses +all; review this permissive policy.");
                        }
                    }
                }
            }
        }

        JSONObject dmarcAnswers = dmarc;

        if (dmarcAnswers != null) {
            JSONArray answers = dmarcAnswers.optJSONArray("Answer");

            if (answers != null) {
                for (int i = 0; i < answers.length(); i++) {
                    String value = answers.optJSONObject(i)
                        .optString("data", "").toLowerCase();

                    if (value.contains("v=dmarc1")) {
                        dmarcFound = true;

                        if (value.contains("p=none")) {
                            findings.put("DMARC policy is p=none; it does not enforce rejection or quarantine.");
                        }
                    }
                }
            }
        }

        JSONObject caa = records.optJSONObject("CAA");

        if (caa != null) {
            JSONArray answers = caa.optJSONArray("Answer");
            caaFound = answers != null && answers.length() > 0;
        }

        if (!spfFound) {
            findings.put("No SPF record detected.");
        }

        if (spfCount > 1) {
            findings.put("Multiple SPF records detected; consolidate them.");
        }

        if (!dmarcFound) {
            findings.put("No DMARC record detected.");
        }

        if (!caaFound) {
            findings.put("No CAA records detected.");
        }

        report.put("records", records);
        report.put("findings", findings);
        report.put("status", "completed");

        return report;
    }

    private static JSONObject query(
            String domain, int type) throws Exception {

        String encoded = URLEncoder.encode(domain, "UTF-8");

        URL url = new URL(
            RESOLVER + "?name=" + encoded + "&type=" + type
        );

        HttpURLConnection connection =
            (HttpURLConnection) url.openConnection();

        connection.setRequestMethod("GET");
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        connection.setRequestProperty(
            "Accept", "application/dns-json"
        );
        connection.setRequestProperty(
            "User-Agent", "Pigeon-Security-Toolkit/2.0"
        );

        try {
            int status = connection.getResponseCode();

            if (status != 200) {
                throw new Exception(
                    "DNS resolver returned HTTP " + status
                );
            }

            StringBuilder body = new StringBuilder();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                        connection.getInputStream(), "UTF-8"))) {

                String line;

                while ((line = reader.readLine()) != null) {
                    body.append(line);
                }
            }

            return new JSONObject(body.toString());

        } finally {
            connection.disconnect();
        }
    }

    private static String validateDomain(String domain)
            throws Exception {

        if (domain == null) {
            throw new Exception("Enter a domain name.");
        }

        domain = domain.trim().toLowerCase();

        if (domain.startsWith("https://")) {
            domain = domain.substring(8);
        } else if (domain.startsWith("http://")) {
            domain = domain.substring(7);
        }

        if (domain.contains("/") ||
            domain.contains(":") ||
            domain.contains(" ")) {
            throw new Exception("Enter a domain only, without a path or port.");
        }

        if (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }

        domain = java.net.IDN.toASCII(domain);

        if (domain.length() > 253 ||
            !domain.matches("(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\\.[a-z]{2,63}$") ||
            domain.contains("..")) {
            throw new Exception("Invalid domain name.");
        }

        return domain;
    }
}
