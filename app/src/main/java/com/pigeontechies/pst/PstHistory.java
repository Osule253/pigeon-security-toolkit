package com.pigeontechies.pst;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class PstHistory {

    private static final String HISTORY_FILE = "pigeon_scan_history.jsonl";

    private PstHistory() {}

    private static String timestamp() {
        SimpleDateFormat format = new SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US
        );
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(new Date());
    }


    private static File getFile(Context context) {
        return new File(context.getFilesDir(), HISTORY_FILE);
    }

    public static synchronized int saveScan(
            Context context, JSONObject report) throws Exception {

        List<JSONObject> scans = loadScans(context);

        int nextId = 1;

        for (JSONObject scan : scans) {
            nextId = Math.max(
                nextId,
                scan.optInt("history_id", 0) + 1
            );
        }

        report.put("history_id", nextId);

        if (!report.has("finished_at")) {
            report.put("finished_at", timestamp());
        }

        File file = getFile(context);

        try (BufferedWriter writer =
                 new BufferedWriter(new FileWriter(file, true))) {

            writer.write(report.toString());
            writer.newLine();
        }

        return nextId;
    }

    public static synchronized List<JSONObject> loadScans(
            Context context) throws Exception {

        List<JSONObject> scans = new ArrayList<>();
        File file = getFile(context);

        if (!file.exists()) {
            return scans;
        }

        try (BufferedReader reader =
                 new BufferedReader(new FileReader(file))) {

            String line;

            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty()) continue;

                try {
                    scans.add(new JSONObject(line));
                } catch (Exception ignored) {
                    // Skip damaged records without losing other history.
                }
            }
        }

        return scans;
    }

    public static synchronized List<JSONObject> newestFirst(
            Context context) throws Exception {

        List<JSONObject> scans = loadScans(context);
        Collections.reverse(scans);
        return scans;
    }

    public static synchronized JSONObject getScan(
            Context context, int scanId) throws Exception {

        for (JSONObject scan : loadScans(context)) {
            if (scan.optInt("history_id", -1) == scanId) {
                return scan;
            }
        }

        throw new Exception("Scan #" + scanId + " does not exist.");
    }

    public static JSONObject compareScans(
            JSONObject oldScan,
            JSONObject newScan) throws Exception {

        Map<Integer, JSONObject> oldPorts = getPorts(oldScan);
        Map<Integer, JSONObject> newPorts = getPorts(newScan);

        JSONArray newlyOpen = new JSONArray();
        JSONArray newlyClosed = new JSONArray();
        JSONArray stillOpen = new JSONArray();
        JSONArray otherChanges = new JSONArray();
        JSONArray onlyOld = new JSONArray();
        JSONArray onlyNew = new JSONArray();

        for (Integer port : oldPorts.keySet()) {
            if (!newPorts.containsKey(port)) {
                onlyOld.put(port);
            }
        }

        for (Integer port : newPorts.keySet()) {
            if (!oldPorts.containsKey(port)) {
                onlyNew.put(port);
            }
        }

        for (Integer port : oldPorts.keySet()) {
            if (!newPorts.containsKey(port)) continue;

            String before = oldPorts.get(port).optString("state");
            String after = newPorts.get(port).optString("state");

            if (!"OPEN".equals(before) && "OPEN".equals(after)) {
                newlyOpen.put(port);

            } else if ("OPEN".equals(before) &&
                       !"OPEN".equals(after)) {
                newlyClosed.put(port);

            } else if ("OPEN".equals(before) &&
                       "OPEN".equals(after)) {
                stillOpen.put(port);

            } else if (!before.equals(after)) {
                JSONObject change = new JSONObject();
                change.put("port", port);
                change.put("before", before);
                change.put("after", after);
                otherChanges.put(change);
            }
        }

        JSONObject result = new JSONObject();

        result.put("tool", "Pigeon History");
        result.put("version", "1.0.0");
        result.put("old_scan_id",
            oldScan.optInt("history_id", -1));
        result.put("new_scan_id",
            newScan.optInt("history_id", -1));
        result.put("old_target", oldScan.optString("target"));
        result.put("new_target", newScan.optString("target"));
        result.put("newly_open", newlyOpen);
        result.put("newly_closed", newlyClosed);
        result.put("still_open", stillOpen);
        result.put("other_changes", otherChanges);
        result.put("only_in_old_scan", onlyOld);
        result.put("only_in_new_scan", onlyNew);
        result.put("compared_at", timestamp());

        return result;
    }

    private static Map<Integer, JSONObject> getPorts(
            JSONObject scan) throws Exception {

        Map<Integer, JSONObject> ports = new HashMap<>();
        JSONArray results = scan.optJSONArray("results");

        if (results == null) return ports;

        for (int i = 0; i < results.length(); i++) {
            JSONObject item = results.getJSONObject(i);

            if (item.has("port")) {
                ports.put(item.getInt("port"), item);
            }
        }

        return ports;
    }
}
