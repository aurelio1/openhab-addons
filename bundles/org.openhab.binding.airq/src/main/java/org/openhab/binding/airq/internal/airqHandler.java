/**
 * Copyright (c) 2010-2020 Contributors to the openHAB project
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 */
package org.openhab.binding.airq.internal;

import static org.openhab.binding.airq.internal.airqBindingConstants.CHANNEL_1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.smarthome.core.library.types.DateTimeType;
import org.eclipse.smarthome.core.library.types.DecimalType;
import org.eclipse.smarthome.core.library.types.OnOffType;
import org.eclipse.smarthome.core.library.types.PointType;
import org.eclipse.smarthome.core.library.types.StringType;
import org.eclipse.smarthome.core.thing.ChannelUID;
import org.eclipse.smarthome.core.thing.Thing;
import org.eclipse.smarthome.core.thing.ThingStatus;
import org.eclipse.smarthome.core.thing.ThingStatusDetail;
import org.eclipse.smarthome.core.thing.binding.BaseThingHandler;
import org.eclipse.smarthome.core.types.Command;
import org.eclipse.smarthome.core.types.RefreshType;
import org.eclipse.smarthome.core.types.UnDefType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The {@link airqHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Aurelio Caliaro - Initial contribution
 */
@NonNullByDefault
public class airqHandler extends BaseThingHandler {

    private final Logger logger = LoggerFactory.getLogger(airqHandler.class);
    private @Nullable ScheduledFuture<?> pollingJob;
    private @Nullable ScheduledFuture<?> getConfigDataJob;
    private @Nullable String ipaddress;
    private @Nullable String password;
    private @Nullable ThingStatus thStatus;

    final class ResultPair {
        private final float value;
        private final float maxdev;

        public float getvalue() {
            return value;
        }

        public float getmaxdev() {
            return maxdev;
        }

        // ResultPair() expects a string formed as this: [1234,56,789,012] and gives back a ResultPair
        // consisting of the two numbers
        public ResultPair(String input) {
            value = new Float(input.substring(1, input.indexOf(',')));
            maxdev = new Float(input.substring(input.indexOf(',') + 1, input.length() - 1));
        }
    }

    public airqHandler(Thing thing) {
        super(thing);
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        if (CHANNEL_1.equals(channelUID.getId())) {
            if (command instanceof RefreshType) {
                // TODO: handle data refresh
            }

            // TODO: handle command

            // Note: if communication with thing fails for some reason,
            // indicate that by setting the status with detail information:
            // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR,
            // "Could not control device at IP address x.x.x.x");
        }
    }

    @Override
    public void initialize() {
        logger.debug("air-Q - airqHandler - initialize(): ipaddress={}, password={}",
                getThing().getConfiguration().get("ipAddress"), getThing().getConfiguration().get("password"));
        // set the thing status to UNKNOWN temporarily and let the background task decide for the real status.
        // the framework is then able to reuse the resources from the thing handler initialization.
        // we set this upfront to reliably check status updates in unit tests.
        updateStatus(ThingStatus.UNKNOWN);
        if (getThing().getConfiguration().get("ipAddress") != null) {
            ipaddress = getThing().getConfiguration().get("ipAddress").toString();
        }
        if (getThing().getConfiguration().get("password") != null) {
            password = getThing().getConfiguration().get("password").toString();
        }
        if ((ipaddress == null) || (password == null)) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                    "IP Address and the device password must be provided to access your air-Q.");
            return;
        }
        // TODO: Initialize the handler.
        // The framework requires you to return from this method quickly. Also, before leaving this method a thing
        // status from one of ONLINE, OFFLINE or UNKNOWN must be set. This might already be the real thing status in
        // case you can decide it directly.
        // In case you can not decide the thing status directly (e.g. for long running connection handshake using
        // WAN
        // access or similar) you should set status UNKNOWN here and then decide the real status asynchronously in
        // the
        // background.

        // Example for background initialization:
        scheduler.execute(() -> {
            boolean thingReachable = true; // <background task with long running initialization here>
            // when done do:
            if (thingReachable) {
                updateStatus(ThingStatus.ONLINE);
            } else {
                updateStatus(ThingStatus.OFFLINE);
            }
        });

        // The following code will be called regularly. We only have it here to test the function
        // Gson code based on https://riptutorial.com/de/gson
        Runnable pollData = new Runnable() {

            @Override
            public void run() {
                Result res = null;
                logger.trace("air-Q - airqHandler - run(): starting polled handler");
                if ((ipaddress != null) && (password != null)) {
                    try {
                        String url = "http://".concat(ipaddress.concat("/data"));
                        res = doNetwork(url, "GET", null);
                        if (res == null) {
                            if (thStatus != ThingStatus.OFFLINE) {
                                logger.error(
                                        "air-Q - airqHandler - run(): cannot reach air-Q device. Status set to OFFLINE.");
                                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR);
                                thStatus = ThingStatus.OFFLINE;
                            } else {
                                logger.warn(
                                        "air-Q - airqHandler - run(): retried but still cannot reach the air-Q device.");
                            }
                        } else {
                            if (thStatus == ThingStatus.OFFLINE) {
                                logger.error(
                                        "air-Q - airqHandler - run(): can reach air-Q device again, Status set back to ONLINE.");
                                thStatus = ThingStatus.ONLINE;
                                updateStatus(ThingStatus.ONLINE);
                            }
                            String jsontext = res.getBody();
                            logger.trace("air-Q - airqHandler - run(): Result from doNetwork is {} with body={}", res,
                                    res.getBody());
                            Gson gson = new Gson();
                            JsonElement ans = gson.fromJson(jsontext, JsonElement.class);
                            JsonObject jsonObj = ans.getAsJsonObject();
                            String jsonAnswer = decode(jsonObj.get("content").getAsString().getBytes(),
                                    (String) (getThing().getConfiguration().get("password")));
                            JsonElement decEl = gson.fromJson(jsonAnswer, JsonElement.class);
                            JsonObject decObj = decEl.getAsJsonObject();
                            logger.trace("air-Q - airqHandler - run(): decObj={}", decObj);
                            processType(decObj, "bat", "bat", "pair");
                            processType(decObj, "cnt0_3", "cnt0_3", "pair");
                            processType(decObj, "cnt0_5", "cnt0_5", "pair");
                            processType(decObj, "cnt1", "cnt1", "pair");
                            processType(decObj, "cnt2_5", "cnt2_5", "pair");
                            processType(decObj, "cnt5", "cnt5", "pair");
                            processType(decObj, "cnt10", "cnt10", "pair");
                            processType(decObj, "co2", "co2", "pair");
                            processType(decObj, "dewpt", "dewpt", "pair");
                            processType(decObj, "humidity", "humidity", "pair");
                            processType(decObj, "humidity_abs", "humidity_abs", "pair");
                            processType(decObj, "no2", "no2", "pair");
                            processType(decObj, "o3", "o3", "pair");
                            processType(decObj, "oxygen", "oxygen", "pair");
                            processType(decObj, "pm1", "pm1", "pair");
                            processType(decObj, "pm2_5", "pm2_5", "pair");
                            processType(decObj, "pm10", "pm10", "pair");
                            processType(decObj, "pressure", "pressure", "pair");
                            processType(decObj, "so2", "so2", "pair");
                            processType(decObj, "sound", "sound", "pair");
                            processType(decObj, "temperature", "temperature", "pair");
                            processType(decObj, "DeviceID", "DeviceID", "string");
                            processType(decObj, "Status", "Status", "string");
                            processType(decObj, "TypPS", "TypPS", "number");
                            processType(decObj, "dCO2dt", "dCO2dt", "number");
                            processType(decObj, "dHdt", "dHdt", "number");
                            processType(decObj, "door_event", "door_event", "boolean");
                            processType(decObj, "health", "health", "number");
                            processType(decObj, "measuretime", "measuretime", "number");
                            processType(decObj, "performance", "performance", "number");
                            processType(decObj, "timestamp", "timestamp", "datetime");
                            processType(decObj, "uptime", "uptime", "number");
                            processType(decObj, "tvoc", "tvoc", "pair");
                        }
                    } catch (Exception e) {
                        System.out.println("air-Q - airqHandler - polldata.run(): Error while retrieving air-Q data: "
                                + e.toString());
                    }
                }
            }

        };

        pollingJob = scheduler.scheduleAtFixedRate(pollData, 0, 15000, TimeUnit.MILLISECONDS);
        getConfigDataJob = scheduler.scheduleAtFixedRate(getConfigData, 0, 1, TimeUnit.MINUTES);

        // Note: When initialization can NOT be done set the status with more details for further
        // analysis. See also class ThingStatusDetail for all available status details.
        // Add a description to give user information to understand why thing does not work as expected. E.g.
        // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
        // "Can not access device as username and/or password are invalid");
        logger.debug("air-Q - airqHandler - initialize() finished");
    }

    // AES decoding based on this tutorial: https://www.javainterviewpoint.com/aes-256-encryption-and-decryption/
    public String decode(byte[] base64text, String password) {
        String content = "";
        logger.trace("air-Q - airqHandler - decode(): content BEFORE Base64={}", base64text);
        byte[] encodedtextwithIV = Base64.getDecoder().decode(base64text);
        logger.trace("air-Q - airqHandler - decode(): content AFTER Base64={}", encodedtextwithIV);
        byte[] ciphertext = Arrays.copyOfRange(encodedtextwithIV, 16, encodedtextwithIV.length);
        byte[] passkey = Arrays.copyOf(password.getBytes(), 32);
        if (password.length() < 32) {
            Arrays.fill(passkey, password.length(), 32, (byte) '0');
        }
        byte[] IV = Arrays.copyOf(encodedtextwithIV, 16);
        logger.trace("air-Q - airqHandler - decode(): passkey={}, IV={}", passkey, IV);
        logger.trace("air-Q - airqHandler - decode(): encodedtext={}", ciphertext);
        SecretKey seckey = new SecretKeySpec(passkey, 0, passkey.length, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(seckey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedText = cipher.doFinal(ciphertext);
            content = new String(decryptedText);
            logger.debug("air-Q - airqHandler - decode(): content={}", content);
        } catch (Exception e) {
            System.out.println("air-Q - airqHandler - decode(): Error while decrypting: " + e.toString());
        }
        return content;
    }

    protected @Nullable Result doNetwork(String address, String requestMethod, @Nullable String body)
            throws IOException {
        int timeout = 10000;
        logger.debug("air-Q - airqHandler - doNetwork(): connecting to {} with method {} and body {}", address,
                requestMethod, body);
        HttpURLConnection conn = (HttpURLConnection) new URL(address).openConnection();
        try {
            conn.setRequestMethod(requestMethod);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            if (body != null && !"".equals(body)) {
                conn.setDoOutput(true);
                try (Writer out = new OutputStreamWriter(conn.getOutputStream())) {
                    out.write(body);
                }
            }
            try (InputStream in = conn.getInputStream(); ByteArrayOutputStream result = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int length;
                while ((length = in.read(buffer)) != -1) {
                    result.write(buffer, 0, length);
                }
                return new Result(result.toString(StandardCharsets.UTF_8.name()), conn.getResponseCode());
            } catch (IOException exc) {
                return null;
            }
        } finally {
            conn.disconnect();
        }
    }

    public static class Result {
        private final String body;
        private final int responseCode;

        public Result(String body, int responseCode) {
            this.body = body;
            this.responseCode = responseCode;
        }

        public String getBody() {
            return body;
        }

        public int getResponseCode() {
            return responseCode;
        }
    }

    @Override
    public void dispose() {
        if (pollingJob != null) {
            pollingJob.cancel(true);
        }
        if (getConfigDataJob != null) {
            getConfigDataJob.cancel(true);
        }
    }

    Runnable getConfigData = new Runnable() {

        @Override
        public void run() {
            Result res = null;
            logger.trace("air-Q - airqHandler - processConfigData(): starting processing data");
            if ((ipaddress != null) && (password != null)) {
                try {
                    String url = "http://".concat(ipaddress.concat("/config"));
                    res = doNetwork(url, "GET", null);
                    if (res == null) {
                        if (thStatus != ThingStatus.OFFLINE) {
                            logger.error(
                                    "air-Q - airqHandler - run(): cannot reach air-Q device. Status set to OFFLINE.");
                            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR);
                            thStatus = ThingStatus.OFFLINE;
                        } else {
                            logger.warn(
                                    "air-Q - airqHandler - run(): retried but still cannot reach the air-Q device.");
                        }
                    } else {
                        if (thStatus == ThingStatus.OFFLINE) {
                            logger.error(
                                    "air-Q - airqHandler - run(): can reach air-Q device again, Status set back to ONLINE.");
                            thStatus = ThingStatus.ONLINE;
                            updateStatus(ThingStatus.ONLINE);
                        }
                        String jsontext = res.getBody();
                        logger.trace(
                                "air-Q - airqHandler - processConfigData(): Result from doNetwork is {} with body={}",
                                res, res.getBody());
                        Gson gson = new Gson();
                        JsonElement ans = gson.fromJson(jsontext, JsonElement.class);
                        JsonObject jsonObj = ans.getAsJsonObject();
                        String jsonAnswer = decode(jsonObj.get("content").getAsString().getBytes(),
                                (String) (getThing().getConfiguration().get("password")));
                        JsonElement decEl = gson.fromJson(jsonAnswer, JsonElement.class);
                        JsonObject decObj = decEl.getAsJsonObject();
                        logger.trace("air-Q - airqHandler - processConfigData(): decObj={}", decObj);
                        processType(decObj, "WIFI", "WIFI", "boolean");
                        processType(decObj, "WIFIssid", "WIFIssid", "string");
                        processType(decObj, "WIFIpass", "WIFIpass", "string");
                        processType(decObj, "WIFIbssid", "WIFIbssid", "string");
                        processType(decObj, "WLANssid", "WLANssid", "string");
                        processType(decObj, "pass", "pass", "string");
                        processType(decObj, "WifiInfo", "WifiInfo", "boolean");
                        processType(decObj, "Timeserver", "Timeserver", "boolean");
                        processType(decObj, "geopos", "geopos", "coord");
                        processType(decObj, "nightmode_StartDay", "nightmode_StartDay", "time");
                        processType(decObj, "nightmode_StartNight", "nightmode_StartNight", "time");
                        processType(decObj, "nightmode_BrightnessDay", "nightmode_BrightnessDay", "time");
                        processType(decObj, "nightmode_BrightnessNight", "nightmode_BrightnessNight", "time");
                        processType(decObj, "nightmode_FanNightOff", "nightmode_FanNightOff", "boolean");
                        processType(decObj, "nightmode_WifiNightOff", "nightmode_WifiNightOff", "boolean");
                        processType(decObj, "devicename", "devicename", "string");
                        processType(decObj, "RoomType", "RoomType", "string");
                        processType(decObj, "Logging", "Logging", "string");
                        processType(decObj, "DeleteKey", "DeleteKey", "string");
                        processType(decObj, "FireAlarm", "FireAlarm", "boolean");
                        processType(decObj, "air-Q-Hardware-Version", "air-Q-Hardware-Version", "string");
                        processType(decObj, "WLAN_config_Gateway", "WLAN_config_Gateway", "string");
                        processType(decObj, "WLAN_config_MAC", "WLAN_config_MAC", "string");
                        processType(decObj, "WLAN_config_SSID", "WLAN_config_SSID", "string");
                        processType(decObj, "WLAN_config_IPAddress", "WLAN_config_IPAddress", "string");
                        processType(decObj, "WLAN_config_NetMask", "WLAN_config_NetMask", "string");
                        processType(decObj, "WLAN_config_BSSID", "WLAN_config_BSSID", "string");
                        processType(decObj, "cloudUpload", "cloudUpload", "boolean");
                        processType(decObj, "SecondsMeasurementDelay", "SecondsMeasurementDelay", "number");
                        processType(decObj, "Rejection", "Rejection", "string");
                        processType(decObj, "air-Q-Software-Version", "air-Q-Software-Version", "string");
                        processType(decObj, "sensors", "sensors", "string");
                        processType(decObj, "AutoDriftCompensation", "AutoDriftCompensation", "boolean");
                        processType(decObj, "AutoUpdate", "AutoUpdate", "boolean");
                        processType(decObj, "AdvancedDataProcessing", "AdvancedDataProcessing", "boolean");
                        processType(decObj, "Industry", "Industry", "boolean");
                        processType(decObj, "ppm&ppb", "ppm_and_ppb", "boolean");
                        processType(decObj, "id", "id", "string");
                        processType(decObj, "SoundInfo", "SoundInfo", "boolean");
                        processType(decObj, "AlarmForwarding", "AlarmForwarding", "boolean");
                        processType(decObj, "usercalib", "usercalib", "string");
                        processType(decObj, "InitialCalFinished", "InitialCalFinished", "boolean");
                        processType(decObj, "Averaging", "Averaging", "boolean");
                        processType(decObj, "SensorInfo", "SensorInfo", "string");
                        processType(decObj, "ErrorBars", "ErrorBars", "boolean");
                    }
                } catch (Exception e) {
                    System.out.println("Error in processConfigData(): " + e.toString());
                }
            }
        }
    };

    private void processType(JsonObject dec, String airqName, String channelName, String type) {
        logger.trace("air-Q - airqHandler - processType(): airqName={}, channelName={}, type={}, dec={}", airqName,
                channelName, type, dec);
        if (dec.get(airqName) == null) {
            logger.trace("air-Q - airqHandler - processType(): get({}) is null", airqName);
            updateState(channelName, UnDefType.UNDEF);
            if (type.contentEquals("pair")) {
                updateState(channelName + "_maxerr", UnDefType.UNDEF);
            }
        } else {
            switch (type) {
                case "boolean":
                    String itemval = dec.get(airqName).toString();
                    if (itemval.contentEquals("true")) {
                        updateState(channelName, OnOffType.ON);
                    } else if (itemval.contentEquals("false")) {
                        updateState(channelName, OnOffType.OFF);
                    }
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName, itemval);
                    break;
                case "string":
                case "time":
                    updateState(channelName, new StringType(dec.get(airqName).toString()));
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName,
                            dec.get(airqName).toString());
                    break;
                case "number":
                    updateState(channelName, new DecimalType(dec.get(airqName).toString()));
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName,
                            dec.get(airqName).toString());
                    break;
                case "pair":
                    ResultPair pair = new ResultPair(dec.get(airqName).toString());
                    updateState(channelName, new DecimalType(pair.getvalue()));
                    updateState(channelName + "_maxerr", new DecimalType(pair.getmaxdev()));
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}, channel {} set to {}",
                            channelName, pair.getvalue(), channelName + "_maxerr", pair.getmaxdev());
                    break;
                case "datetime":
                    Long timest = new Long(dec.get(airqName).toString());
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
                    String timestampString = sdf.format(new Date(timest));
                    updateState(channelName, DateTimeType.valueOf(timestampString));
                    break;
                case "coord":
                    Gson gson_coord = new Gson();
                    JsonElement ans_coord = gson_coord.fromJson(dec.get(airqName).toString(), JsonElement.class);
                    JsonObject json_coord = ans_coord.getAsJsonObject();
                    Float latitude = json_coord.get("lat").getAsFloat();
                    Float longitude = json_coord.get("long").getAsFloat();
                    updateState(channelName, new PointType(new DecimalType(latitude), new DecimalType(longitude)));
                    break;
                default:
                    break;
            }
        }
    }

};
