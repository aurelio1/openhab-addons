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
import org.eclipse.smarthome.core.library.types.StringType;
import org.eclipse.smarthome.core.thing.ChannelUID;
import org.eclipse.smarthome.core.thing.Thing;
import org.eclipse.smarthome.core.thing.ThingStatus;
import org.eclipse.smarthome.core.thing.binding.BaseThingHandler;
import org.eclipse.smarthome.core.types.Command;
import org.eclipse.smarthome.core.types.RefreshType;
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
    private @Nullable airqConfiguration config;

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
        logger.debug("air-Q - airqHandler - initialize() called");
        config = getConfigAs(airqConfiguration.class);
        logger.debug("air-Q - airqHandler - initialize: ipaddress={}, password={}",
                getThing().getConfiguration().get("ipAddress"), getThing().getConfiguration().get("password"));
        // TODO: Initialize the handler.
        // The framework requires you to return from this method quickly. Also, before leaving this method a thing
        // status from one of ONLINE, OFFLINE or UNKNOWN must be set. This might already be the real thing status in
        // case you can decide it directly.
        // In case you can not decide the thing status directly (e.g. for long running connection handshake using WAN
        // access or similar) you should set status UNKNOWN here and then decide the real status asynchronously in the
        // background.

        // set the thing status to UNKNOWN temporarily and let the background task decide for the real status.
        // the framework is then able to reuse the resources from the thing handler initialization.
        // we set this upfront to reliably check status updates in unit tests.
        updateStatus(ThingStatus.UNKNOWN);

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

        logger.debug("air-Q - airqHandler - initialize() finished");

        // The following code will be called regularly. We only have it here to test the function
        // Gson code based on https://riptutorial.com/de/gson
        Runnable runnable = new Runnable() {

            final class ResultPair {
                private final float value;
                private final float maxdev;

                public float getvalue() {
                    return value;
                }

                public float getmaxdev() {
                    return maxdev;
                }

                public ResultPair(String input) {
                    value = new Float(input.substring(1, input.indexOf(',')));
                    int pos1 = input.indexOf(',') + 1;
                    int pos2 = input.length() - 1;
                    String substr = input.substring(input.indexOf(',') + 1, input.length() - 1);
                    maxdev = new Float(input.substring(input.indexOf(',') + 1, input.length() - 1));
                }
            }

            private void processPair(JsonObject dec, String name) {
                logger.trace("air-Q - airqHandler - processPair(): dec={}, name={}", dec, name);
                if (dec.get(name) == null) {
                    logger.trace("air-Q - airqHandler - processPair(): get({}) is null", name);
                    updateState(name, new DecimalType(-1));
                    updateState(name, new DecimalType(-1));

                } else {
                    ResultPair pair = new ResultPair(dec.get(name).toString());
                    updateState(name, new DecimalType(pair.getvalue()));
                    updateState(name + "_maxerr", new DecimalType(pair.getmaxdev()));
                }
            }

            @Override
            public void run() {
                Result res = null;
                logger.trace("air-Q - airqHandler - run(): starting polled handler");
                try {
                    res = doNetwork("http://192.168.0.68/data", "GET", null);
                } catch (Exception e) {
                    System.out.println("Error while decrypting: " + e.toString());
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
                processPair(decObj, "bat");
                processPair(decObj, "cnt0_3");
                processPair(decObj, "cnt0_5");
                processPair(decObj, "cnt1");
                processPair(decObj, "cnt2_5");
                processPair(decObj, "cnt5");
                processPair(decObj, "cnt10");
                processPair(decObj, "co2");
                processPair(decObj, "dewpt");
                processPair(decObj, "humidity");
                processPair(decObj, "humidity_abs");
                processPair(decObj, "no2");
                processPair(decObj, "o3");
                processPair(decObj, "oxygen");
                processPair(decObj, "pm1");
                processPair(decObj, "pm2_5");
                processPair(decObj, "pm10");
                processPair(decObj, "pressure");
                processPair(decObj, "so2");
                processPair(decObj, "sound");
                processPair(decObj, "temperature");
                updateState("DeviceID", new StringType(decObj.get("DeviceID").toString()));
                updateState("Status", new StringType(decObj.get("Status").toString()));
                updateState("TypPS", new DecimalType(Double.parseDouble(decObj.get("TypPS").toString())));
                updateState("dCO2dt", new DecimalType(decObj.get("dCO2dt").toString()));
                updateState("dHdt", new DecimalType(decObj.get("dHdt").toString()));
                updateState("door_event", new DecimalType(decObj.get("door_event").toString()));
                updateState("health", new DecimalType(decObj.get("health").toString()));
                updateState("measuretime", new DecimalType(decObj.get("measuretime").toString()));
                updateState("performance", new DecimalType(decObj.get("performance").toString()));
                Long timest = new Long(decObj.get("timestamp").toString());
                SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
                String timestampString = sdf.format(new Date(timest));
                updateState("timestamp", DateTimeType.valueOf(timestampString));
                updateState("uptime", new DecimalType(decObj.get("uptime").toString()));
                processPair(decObj, "tvoc");
            }

        };

        pollingJob = scheduler.scheduleAtFixedRate(runnable, 0, 15000, TimeUnit.MILLISECONDS);

        // Note: When initialization can NOT be done set the status with more details for further
        // analysis. See also class ThingStatusDetail for all available status details.
        // Add a description to give user information to understand why thing does not work as expected. E.g.
        // updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
        // "Can not access device as username and/or password are invalid");
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
            System.out.println("Error while decrypting: " + e.toString());
        }
        return content;
    }

    protected Result doNetwork(String address, String requestMethod, @Nullable String body) throws IOException {
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
        pollingJob.cancel(true);
    }

}
