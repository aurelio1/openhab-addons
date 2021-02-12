/**
 * Copyright (c) 2010-2021 Contributors to the openHAB project
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Map.Entry;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.core.library.types.DateTimeType;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.OnOffType;
import org.openhab.core.library.types.PointType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.UnDefType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The {@link airqHandler} is responsible for retrieving all information from the air-Q device
 * and change properties and channels accordingly.
 *
 * @author Aurelio Caliaro - Initial contribution
 */
@NonNullByDefault
public class AirqHandler extends BaseThingHandler {

    private final Logger logger = LoggerFactory.getLogger(AirqHandler.class);
    private @Nullable ScheduledFuture<?> pollingJob;
    private @Nullable ScheduledFuture<?> getConfigDataJob;
    private @Nullable ThingStatus thStatus;
    protected static final int POLLING_PERIOD_DATA = 15000; // in milliseconds
    protected static final int POLLING_PERIOD_CONFIG = 1; // in minutes
    AirqConfiguration config = new AirqConfiguration();

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
            value = Float.parseFloat(input.substring(1, input.indexOf(',')));
            maxdev = Float.parseFloat(input.substring(input.indexOf(',') + 1, input.length() - 1));
        }
    }

    public AirqHandler(Thing thing) {
        super(thing);
    }

    private boolean isTimeFormat(String str) {
        try {
            LocalTime.parse(str);
        } catch (DateTimeParseException e) {
            return false;
        }
        return true;
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        logger.trace(
                "air-Q - airqHandler - handleCommand(): request received to handle value {} command {} of channelUID={}",
                command, command.getClass(), channelUID);
        if ((command instanceof OnOffType) || (command instanceof StringType)) {
            JsonObject newobj = new JsonObject();
            JsonObject subjson = new JsonObject();
            switch (channelUID.getId()) {
                case "wifi":
                    // we do not allow to switch off Wifi because otherwise we can't connect to the air-Q device anymore
                    break;
                case "wifiInfo":
                    newobj.addProperty("WifiInfo", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "fireAlarm":
                    newobj.addProperty("FireAlarm", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "cloudUpload":
                    newobj.addProperty("cloudUpload", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "autoDriftCompensation":
                    newobj.addProperty("AutoDriftCompensation", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "autoUpdate":
                    // note that this property is binary but uses 1 and 0 instead of true and false
                    newobj.addProperty("AutoUpdate", command == OnOffType.ON ? 1 : 0);
                    changeSettings(newobj);
                    break;
                case "advancedDataProcessing":
                    newobj.addProperty("AdvancedDataProcessing", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "gasAlarm":
                    newobj.addProperty("GasAlarm", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "soundPressure":
                    newobj.addProperty("SoundInfo", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "alarmForwarding":
                    newobj.addProperty("AlarmForwarding", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "averaging":
                    newobj.addProperty("averaging", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "errorBars":
                    newobj.addProperty("ErrorBars", command == OnOffType.ON);
                    changeSettings(newobj);
                    break;
                case "ppm_and_ppb":
                    newobj.addProperty("ppm&ppb", command == OnOffType.ON);
                    changeSettings(newobj);
                case "nightmode_FanNightOff":
                    subjson.addProperty("FanNightOff", command == OnOffType.ON);
                    newobj.add("NightMode", subjson);
                    changeSettings(newobj);
                    break;
                case "nightmode_WifiNightOff":
                    subjson.addProperty("WifiNightOff", command == OnOffType.ON);
                    newobj.add("NightMode", subjson);
                    changeSettings(newobj);
                    break;
                case "SSID":
                    JsonElement wifidatael = new Gson().fromJson(command.toString(), JsonElement.class);
                    if (wifidatael != null) {
                        JsonObject wifidataobj = wifidatael.getAsJsonObject();
                        newobj.addProperty("WiFissid", wifidataobj.get("WiFissid").getAsString());
                        newobj.addProperty("WiFipass", wifidataobj.get("WiFipass").getAsString());
                        String bssid = wifidataobj.get("WiFibssid").getAsString();
                        if (!bssid.isEmpty()) {
                            newobj.addProperty("WiFibssid", bssid);
                        }
                        newobj.addProperty("reset", wifidataobj.get("reset").getAsString());
                        changeSettings(newobj);
                    } else {
                        logger.warn("Cannot extract wlan data from this string: {}", wifidatael);
                    }
                    break;
                case "timeServer":
                    newobj.addProperty(channelUID.getId(), command.toString());
                    changeSettings(newobj);
                    break;
                case "nightmode_StartDay":
                    if (isTimeFormat(command.toString())) {
                        subjson.addProperty("StartDay", command.toString());
                        newobj.add("NightMode", subjson);
                        changeSettings(newobj);
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} should be set to {} but it isn't a correct time format (eg. 08:00)",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "nightmode_StartNight":
                    if (isTimeFormat(command.toString())) {
                        subjson.addProperty("StartNight", command.toString());
                        newobj.add("NightMode", subjson);
                        changeSettings(newobj);
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} should be set to {} but it isn't a correct time format (eg. 08:00)",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "location":
                    PointType pt = (PointType) command;
                    subjson.addProperty("lat", pt.getLatitude());
                    subjson.addProperty("long", pt.getLongitude());
                    newobj.add("geopos", subjson);
                    changeSettings(newobj);
                    break;
                case "nightmode_BrightnessDay":
                    try {
                        subjson.addProperty("BrightnessDay", Float.parseFloat(command.toString()));
                        newobj.add("NightMode", subjson);
                        changeSettings(newobj);
                    } catch (Exception exc) {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} only accepts a float value, and {} is not.",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "nightmode_BrightnessNight":
                    try {
                        subjson.addProperty("BrightnessNight", Float.parseFloat(command.toString()));
                        newobj.add("NightMode", subjson);
                        changeSettings(newobj);
                    } catch (Exception exc) {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} only accepts a float value, and {} is not.",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "roomType":
                    newobj.addProperty("RoomType", command.toString());
                    changeSettings(newobj);
                    break;
                case "logLevel":
                    String ll = command.toString();
                    if (ll.equals("Error") || ll.equals("Warning") || ll.equals("Info")) {
                        newobj.addProperty("Logging", ll);
                        changeSettings(newobj);
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} should be set to {} but it isn't a correct setting for the power frequency suppression (only 50Hz or 60Hz)",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "averagingRhythm":
                    try {
                        newobj.addProperty("SecondsMeasurementDelay", Integer.parseUnsignedInt(command.toString()));
                    } catch (Exception exc) {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} only accepts an integer value, and {} is not.",
                                channelUID.getId(), command.toString());
                    }
                    break;
                case "powerFreqSuppression":
                    String newFreq = command.toString();
                    if (newFreq.equals("50Hz") || newFreq.equals("60Hz") || newFreq.equals("50Hz+60Hz")) {
                        newobj.addProperty("Rejection", newFreq);
                        changeSettings(newobj);
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - handleCommand(): {} should be set to {} but it isn't a correct setting for the power frequency suppression (only 50Hz or 60Hz)",
                                channelUID.getId(), command.toString());
                    }
                    break;
                default:
                    logger.warn(
                            "air-Q - airqHandler - handleCommand(): unknown command {} received (channelUID={}, value={})",
                            command, channelUID, command);
            }
        }
    }

    @Override
    public void initialize() {
        config = getThing().getConfiguration().as(AirqConfiguration.class);
        logger.debug("air-Q - airqHandler - initialize(): config={}", config);
        updateStatus(ThingStatus.UNKNOWN);
        // We don't have to test if ipAddress and password have been set because we have defined them
        // as being 'required' in thing-types.xml and OpenHAB will only initialize the handler if both are set.
        String data = getDecryptedContentString("http://".concat(config.ipAddress.concat("/data")), "GET", null);
        // we try if the device is reachable and the password is correct. Otherwise a corresponding message is
        // thrown in Thing manager.
        if (data == null) {
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                    "Unable to retrieve get data from air-Q device. Probable cause: invalid password.");
        } else {
            updateStatus(ThingStatus.ONLINE);
        }
        pollingJob = scheduler.scheduleWithFixedDelay(this::pollData, 0, POLLING_PERIOD_DATA, TimeUnit.MILLISECONDS);
        getConfigDataJob = scheduler.scheduleWithFixedDelay(this::getConfigData, 0, POLLING_PERIOD_CONFIG,
                TimeUnit.MINUTES);
        logger.debug("air-Q - airqHandler - initialize() finished");
    }

    // AES decoding based on this tutorial: https://www.javainterviewpoint.com/aes-256-encryption-and-decryption/
    public @Nullable String decrypt(byte[] base64text, String password) {
        String content = "";
        logger.trace("air-Q - airqHandler - decrypt(): content to decypt: {}", base64text);
        byte[] encodedtextwithIV = Base64.getDecoder().decode(base64text);
        byte[] ciphertext = Arrays.copyOfRange(encodedtextwithIV, 16, encodedtextwithIV.length);
        byte[] passkey = Arrays.copyOf(password.getBytes(), 32);
        if (password.length() < 32) {
            Arrays.fill(passkey, password.length(), 32, (byte) '0');
        }
        byte[] IV = Arrays.copyOf(encodedtextwithIV, 16);
        SecretKey seckey = new SecretKeySpec(passkey, 0, passkey.length, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(seckey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedText = cipher.doFinal(ciphertext);
            content = new String(decryptedText);
            logger.trace("air-Q - airqHandler - decrypt(): Text decoded as String: {}", content);
        } catch (BadPaddingException bpe) {
            logger.warn("Error while decrypting. Probably the provided password is wrong.");
            return null;
        } catch (Exception e) {
            logger.warn("air-Q - airqHandler - decrypt(): Error while decrypting: {}", e.toString());
            return null;
        }
        return content;
    }

    public String encrypt(byte[] toencode, String password) {
        String content = "";
        logger.trace("air-Q - airqHandler - encrypt(): text to encode: {}", new String(toencode));
        byte[] passkey = Arrays.copyOf(password.getBytes(), 32);
        if (password.length() < 32) {
            Arrays.fill(passkey, password.length(), 32, (byte) '0');
        }
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);
        SecretKey seckey = new SecretKeySpec(passkey, 0, passkey.length, "AES");
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(seckey.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encryptedText = cipher.doFinal(toencode);
            byte[] totaltext = new byte[16 + encryptedText.length];
            System.arraycopy(IV, 0, totaltext, 0, 16);
            System.arraycopy(encryptedText, 0, totaltext, 16, encryptedText.length);
            byte[] encodedcontent = Base64.getEncoder().encode(totaltext);
            logger.trace("air-Q - airqHandler - encrypt(): encrypted text: {}", encodedcontent);
            content = new String(encodedcontent);
        } catch (Exception e) {
            logger.warn("air-Q - airqHandler - encrypt(): Error while encrypting: {}", e.toString());
        }
        return content;
    }

    // gets the data after online/offline management and does the JSON work, or at least the first step.
    protected @Nullable String getDecryptedContentString(String url, String requestMethod, @Nullable String body) {
        Result res = null;
        String jsonAnswer = null;
        res = getData(url, "GET", null);
        if (res != null) {
            String jsontext = res.getBody();
            logger.trace("air-Q - airqHandler - getDecryptedContentString(): Result from doNetwork is {} with body={}",
                    res, res.getBody());
            // Gson code based on https://riptutorial.com/de/gson
            Gson gson = new Gson();
            JsonElement ans = gson.fromJson(jsontext, JsonElement.class);
            if (ans != null) {
                JsonObject jsonObj = ans.getAsJsonObject();
                jsonAnswer = decrypt(jsonObj.get("content").getAsString().getBytes(), config.password);
                if (jsonAnswer == null) {
                    updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                            "Decryption not possible, probably wrong password");
                }
            } else {
                logger.warn(
                        "air-Q - airqHandler - getDecryptedContentString(): The air-Q data could not be extracted from this string: {}",
                        ans);
            }
        }
        return jsonAnswer;
    }

    // calls the networking job and in addition does additional tests for online/offline management
    protected @Nullable Result getData(String address, String requestMethod, @Nullable String body) {
        Result res = null;
        res = doNetwork(address, "GET", body);
        if (res == null) {
            if (thStatus != ThingStatus.OFFLINE) {
                updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, "air-Q device not reachable");
                thStatus = ThingStatus.OFFLINE;
            } else {
                logger.warn("air-Q - airqHandler - getData(): retried but still cannot reach the air-Q device.");
            }
        } else {
            if (thStatus == ThingStatus.OFFLINE) {
                updateStatus(ThingStatus.ONLINE);
                thStatus = ThingStatus.ONLINE;
            }
        }
        return res;
    }

    // does the networking job (and only that)
    protected @Nullable Result doNetwork(String address, String requestMethod, @Nullable String body) {
        int timeout = 10000;
        HttpURLConnection conn = null;
        logger.debug("air-Q - airqHandler - doNetwork(): connecting to {} with method {} and body {}", address,
                requestMethod, body);
        try {
            conn = (HttpURLConnection) new URL(address).openConnection();
            conn.setRequestMethod(requestMethod);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            if (body != null && !body.isEmpty()) {
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
                conn.disconnect();
                return new Result(result.toString(StandardCharsets.UTF_8.name()), conn.getResponseCode());
            }
        } catch (IOException exc) {
            logger.warn("air-Q - airqHandler - doNetwork(): Error while accessing air-Q: {}", exc.toString());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return null;
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

    public void pollData() {
        logger.trace("air-Q - airqHandler - run(): starting polled data handler");
        if ((!config.ipAddress.isEmpty()) && (!config.password.isEmpty())) {
            try {
                String url = "http://".concat(config.ipAddress.concat("/data"));
                String jsonAnswer = getDecryptedContentString(url, "GET", null);
                if (jsonAnswer != null) {
                    Gson gson = new Gson();
                    JsonElement decEl = gson.fromJson(jsonAnswer, JsonElement.class);
                    if (decEl != null) {
                        JsonObject decObj = decEl.getAsJsonObject();
                        logger.debug("air-Q - airqHandler - run(): decObj={}, jsonAnswer={}", decObj, jsonAnswer);
                        // 'bat' is a field that is already delivered by air-Q but as
                        // there are no air-Q devices which are powered with batteries
                        // it is obsolete at this moment. We implemented the code anyway
                        // to make it easier to add afterwords, but for the moment it is not applicable.
                        // processType(decObj, "bat", "battery", "pair");
                        processType(decObj, "cnt0_3", "fineDustCnt00_3", "pair");
                        processType(decObj, "cnt0_5", "fineDustCnt00_5", "pair");
                        processType(decObj, "cnt1", "fineDustCnt01", "pair");
                        processType(decObj, "cnt2_5", "fineDustCnt02_5", "pair");
                        processType(decObj, "cnt5", "fineDustCnt05", "pair");
                        processType(decObj, "cnt10", "fineDustCnt10", "pair");
                        processType(decObj, "co", "co", "pair");
                        processType(decObj, "co2", "co2", "pair");
                        processType(decObj, "dewpt", "dewpt", "pair");
                        processType(decObj, "humidity", "humidityRelative", "pair");
                        processType(decObj, "humidity_abs", "humidityAbsolute", "pair");
                        processType(decObj, "no2", "no2", "pair");
                        processType(decObj, "o3", "o3", "pair");
                        processType(decObj, "oxygen", "o2", "pair");
                        processType(decObj, "pm1", "fineDustConc01", "pair");
                        processType(decObj, "pm2_5", "fineDustConc02_5", "pair");
                        processType(decObj, "pm10", "fineDustConc10", "pair");
                        processType(decObj, "pressure", "pressure", "pair");
                        processType(decObj, "so2", "so2", "pair");
                        processType(decObj, "sound", "sound", "pair");
                        processType(decObj, "temperature", "temperature", "pair");
                        // We have two places where the Device ID is delivered: with the measurement data and
                        // with the configuration.
                        // We take the info from the configuration and show it as a property, so we don't need
                        // something like processType(decObj, "DeviceID", "DeviceID", "string") at this moment. We leave
                        // this as a reminder in case for some reason it will be needed in future, e.g. when an air-Q
                        // device also sends data from other devices (then with another Device ID)
                        processType(decObj, "Status", "status", "string");
                        processType(decObj, "TypPS", "avgFineDustSize", "number");
                        processType(decObj, "dCO2dt", "dCO2dt", "number");
                        processType(decObj, "dHdt", "dHdt", "number");
                        processType(decObj, "door_event", "doorEvent", "number");
                        processType(decObj, "health", "health", "number");
                        processType(decObj, "measuretime", "measureTime", "number");
                        processType(decObj, "performance", "performance", "number");
                        processType(decObj, "timestamp", "timestamp", "datetime");
                        processType(decObj, "uptime", "uptime", "number");
                        processType(decObj, "tvoc", "tvoc", "pair");
                    } else {
                        logger.warn("The air-Q data could not be extracted from this string: {}", decEl);
                    }
                }
            } catch (Exception e) {
                logger.warn("air-Q - airqHandler - polldata.run(): Error while retrieving air-Q data: {}", toString());
            }
        }
    }

    public void getConfigData() {
        Result res = null;
        logger.trace("air-Q - airqHandler - getConfigData(): starting processing data");
        if ((!config.ipAddress.isEmpty()) && (!config.password.isEmpty())) {
            try {
                String url = "http://".concat(config.ipAddress.concat("/config"));
                res = getData(url, "GET", null);
                if (res != null) {
                    String jsontext = res.getBody();
                    logger.trace("air-Q - airqHandler - getConfigData(): Result from doNetwork is {} with body={}", res,
                            res.getBody());
                    Gson gson = new Gson();
                    JsonElement ans = gson.fromJson(jsontext, JsonElement.class);
                    if (ans != null) {
                        JsonObject jsonObj = ans.getAsJsonObject();
                        String jsonAnswer = decrypt(jsonObj.get("content").getAsString().getBytes(), config.password);
                        if (jsonAnswer != null) {
                            JsonElement decEl = gson.fromJson(jsonAnswer, JsonElement.class);
                            if (decEl != null) {
                                JsonObject decObj = decEl.getAsJsonObject();
                                logger.debug("air-Q - airqHandler - getConfigData(): decObj={}", decObj);
                                processType(decObj, "Wifi", "wifi", "boolean");
                                processType(decObj, "WLANssid", "SSID", "arr");
                                processType(decObj, "pass", "password", "string");
                                processType(decObj, "WifiInfo", "wifiInfo", "boolean");
                                processType(decObj, "TimeServer", "timeServer", "string");
                                processType(decObj, "geopos", "location", "coord");
                                processType(decObj, "NightMode", "", "nightmode");
                                processType(decObj, "devicename", "devicename", "string");
                                processType(decObj, "RoomType", "roomType", "string");
                                processType(decObj, "Logging", "logLevel", "string");
                                processType(decObj, "DeleteKey", "deleteKey", "string");
                                processType(decObj, "FireAlarm", "fireAlarm", "boolean");
                                processType(decObj, "air-Q-Hardware-Version", "hardwareVersion", "property");
                                processType(decObj, "WLAN config", "", "wlan");
                                processType(decObj, "cloudUpload", "cloudUpload", "boolean");
                                processType(decObj, "SecondsMeasurementDelay", "averagingRhythm", "number");
                                processType(decObj, "Rejection", "powerFreqSuppression", "string");
                                processType(decObj, "air-Q-Software-Version", "softwareVersion", "property");
                                processType(decObj, "sensors", "sensorList", "proparr");
                                processType(decObj, "AutoDriftCompensation", "autoDriftCompensation", "boolean");
                                processType(decObj, "AutoUpdate", "autoUpdate", "boolean");
                                processType(decObj, "AdvancedDataProcessing", "advancedDataProcessing", "boolean");
                                processType(decObj, "Industry", "Industry", "property");
                                processType(decObj, "ppm&ppb", "ppm_and_ppb", "boolean");
                                processType(decObj, "GasAlarm", "gasAlarm", "boolean");
                                processType(decObj, "id", "id", "property");
                                processType(decObj, "SoundInfo", "soundPressure", "boolean");
                                processType(decObj, "AlarmForwarding", "alarmForwarding", "boolean");
                                processType(decObj, "usercalib", "userCalib", "calib");
                                processType(decObj, "InitialCalFinished", "initialCalFinished", "boolean");
                                processType(decObj, "Averaging", "averaging", "boolean");
                                processType(decObj, "SensorInfo", "sensorInfo", "property");
                                processType(decObj, "ErrorBars", "errorBars", "boolean");
                            } else {
                                logger.warn(
                                        "air-Q - airqHandler - getConfigData(): The air-Q data could not be extracted from this string: {}",
                                        decEl);
                            }
                        }
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - getConfigData(): The air-Q data could not be extracted from this string: {}",
                                ans);
                    }
                }
            } catch (Exception e) {
                logger.warn("air-Q - airqHandler - getConfigData(): Error in processConfigData(): {}", e.toString());
            }
        }
    }

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
                    if (itemval.contentEquals("true") || itemval.contentEquals("1")) {
                        updateState(channelName, OnOffType.ON);
                    } else if (itemval.contentEquals("false") || itemval.contentEquals("0")) {
                        updateState(channelName, OnOffType.OFF);
                    }
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName, itemval);
                    break;
                case "string":
                case "time":
                    String strstr = dec.get(airqName).toString();
                    updateState(channelName, new StringType(strstr.substring(1, strstr.length() - 1)));
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName, strstr);
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
                    Long timest = Long.valueOf(dec.get(airqName).toString());
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
                    String timestampString = sdf.format(new Date(timest));
                    updateState(channelName, DateTimeType.valueOf(timestampString));
                    logger.trace("air-Q - airqHandler - processType(): channel {} set to {} (original: {})",
                            channelName, timestampString, timest);
                    break;
                case "coord":
                    JsonElement ans_coord = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if (ans_coord != null) {
                        JsonObject json_coord = ans_coord.getAsJsonObject();
                        Float latitude = json_coord.get("lat").getAsFloat();
                        Float longitude = json_coord.get("long").getAsFloat();
                        updateState(channelName, new PointType(new DecimalType(latitude), new DecimalType(longitude)));
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - processType(): Cannot extract coordinates from this data: {}",
                                dec.get(airqName).toString());
                    }
                    break;
                case "nightmode":
                    JsonElement daynightdata = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if (daynightdata != null) {
                        JsonObject json_daynightdata = daynightdata.getAsJsonObject();
                        processType(json_daynightdata, "StartDay", "nightMode_startDay", "string");
                        processType(json_daynightdata, "StartNight", "nightMode_startNight", "string");
                        processType(json_daynightdata, "BrightnessDay", "nightMode_brightnessDay", "number");
                        processType(json_daynightdata, "BrightnessNight", "nightMode_brightnessNight", "number");
                        processType(json_daynightdata, "FanNightOff", "nightMode_fanNightOff", "boolean");
                        processType(json_daynightdata, "WifiNightOff", "nightMode_wifiNightOff", "boolean");
                    } else {
                        logger.warn("air-Q - airqHandler - processType(): Cannot extract day/night data: {}",
                                dec.get(airqName).toString());
                    }
                    break;
                case "wlan":
                    JsonElement wlandata = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if (wlandata != null) {
                        JsonObject json_wlandata = wlandata.getAsJsonObject();
                        processType(json_wlandata, "Gateway", "WLAN_config_gateway", "string");
                        processType(json_wlandata, "MAC", "WLAN_config_MAC", "string");
                        processType(json_wlandata, "SSID", "WLAN_config_SSID", "string");
                        processType(json_wlandata, "IP address", "WLAN_config_IPAddress", "string");
                        processType(json_wlandata, "Net Mask", "WLAN_config_netMask", "string");
                        processType(json_wlandata, "BSSID", "WLAN_config_BSSID", "string");
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - processType(): Cannot extract WLAN data from this string: {}",
                                dec.get(airqName).toString());
                    }
                    break;
                case "arr":
                    JsonElement jsonarr = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if ((jsonarr != null) && (jsonarr.isJsonArray())) {
                        JsonArray arr = jsonarr.getAsJsonArray();
                        String str = new String();
                        for (JsonElement el : arr) {
                            str = str.concat(el.getAsString()).concat(", ");
                        }
                        logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName,
                                str.substring(0, str.length() - 2));
                        updateState(channelName, new StringType(str.substring(0, str.length() - 2)));
                    } else {
                        logger.warn("air-Q - airqHandler - processType(): cannot handle this as an array: {}", jsonarr);
                    }
                    break;
                case "calib":
                    JsonElement lastcalib = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if (lastcalib != null) {
                        JsonObject calibobj = lastcalib.getAsJsonObject();
                        String str = new String();
                        Long timecalib;
                        SimpleDateFormat sdfcalib = new SimpleDateFormat("dd.MM.yyyy' 'HH:mm:ss");
                        for (Entry<String, JsonElement> entry : calibobj.entrySet()) {
                            String attributeName = entry.getKey();
                            JsonObject attributeValue = (JsonObject) entry.getValue();
                            timecalib = Long.valueOf(attributeValue.get("timestamp").toString());
                            String timecalibString = sdfcalib.format(new Date(timecalib * 1000));
                            str = str.concat(attributeName).concat(": offset=")
                                    .concat(attributeValue.get("offset").getAsString()).concat(" [")
                                    .concat(timecalibString).concat("]");
                        }
                        logger.trace("air-Q - airqHandler - processType(): channel {} set to {}", channelName,
                                str.substring(0, str.length() - 1));
                        updateState(channelName, new StringType(str.substring(0, str.length() - 1)));
                    } else {
                        logger.warn(
                                "air-Q - airqHandler - processType(): Cannot extract calibration data from this string: {}",
                                dec.get(airqName).toString());
                    }
                    break;
                case "property":
                    String propstr = dec.get(airqName).toString();
                    getThing().setProperty(channelName, propstr);
                    logger.trace("air-Q - airqHandler - processType(): property {} set to {}", channelName, propstr);
                    break;
                case "proparr":
                    JsonElement proparr = new Gson().fromJson(dec.get(airqName).toString(), JsonElement.class);
                    if ((proparr != null) && proparr.isJsonArray()) {
                        JsonArray arr = proparr.getAsJsonArray();
                        String arrstr = new String();
                        for (JsonElement el : arr) {
                            arrstr = arrstr.concat(el.getAsString()).concat(", ");
                        }
                        logger.trace("air-Q - airqHandler - processType(): property array {} set to {}", channelName,
                                arrstr.substring(0, arrstr.length() - 2));
                        getThing().setProperty(channelName, arrstr.substring(0, arrstr.length() - 2));
                    } else {
                        logger.warn("air-Q - airqHandler - processType(): cannot handle this as an array: {}", proparr);
                    }
                    break;
                default:
                    logger.warn(
                            "air-Q - airqHandler - processType(): a setting of type {} should be changed but I don't know this type.",
                            type);
                    break;
            }
        }
    }

    private void changeSettings(JsonObject jsonchange) {
        String jsoncmd = jsonchange.toString();
        logger.trace("air-Q - airqHandler - changeSettings(): called with jsoncmd={}", jsoncmd);
        if ((!config.ipAddress.isEmpty()) && (!config.password.isEmpty())) {
            Result res = null;
            try {
                String url = "http://".concat(config.ipAddress.concat("/config"));
                String jsonbody = encrypt(jsoncmd.getBytes(), config.password);
                String fullbody = "request=".concat(jsonbody);
                logger.trace("air-Q - airqHandler - changeSettings(): doing call to url={}, method=POST, body={}", url,
                        fullbody);
                res = getData(url, "POST", fullbody);
                if (res != null) {
                    Gson gson = new Gson();
                    JsonElement ans = gson.fromJson(res.getBody(), JsonElement.class);
                    if (ans != null) {
                        JsonObject jsonObj = ans.getAsJsonObject();
                        String jsonAnswer = decrypt(jsonObj.get("content").getAsString().getBytes(), config.password);
                        logger.trace("air-Q - airqHandler - changeSettings(): call returned {}", jsonAnswer);
                    } else {
                        logger.warn("The air-Q data could not be extracted from this string: {}", ans);
                    }
                }
            } catch (Exception e) {
                logger.warn("air-Q - airqHandler - ChangeSettings(): Error while changing settings in air-Q data: {}",
                        e.toString());
            }
        }
    }
};
