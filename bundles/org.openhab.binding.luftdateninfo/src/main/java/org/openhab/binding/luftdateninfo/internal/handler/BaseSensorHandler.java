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
package org.openhab.binding.luftdateninfo.internal.handler;

import java.time.LocalDateTime;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.jdt.annotation.NonNullByDefault;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.luftdateninfo.internal.LuftdatenInfoConfiguration;
import org.openhab.binding.luftdateninfo.internal.utils.DateTimeUtils;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.thing.Thing;
import org.openhab.core.thing.ThingStatus;
import org.openhab.core.thing.ThingStatusDetail;
import org.openhab.core.thing.binding.BaseThingHandler;
import org.openhab.core.types.Command;
import org.openhab.core.types.RefreshType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@link PMHandler} is responsible for handling commands, which are
 * sent to one of the channels.
 *
 * @author Bernd Weymann - Initial contribution
 */
@NonNullByDefault
public abstract class BaseSensorHandler extends BaseThingHandler {
    private static final LuftdatenInfoConfiguration DEFAULT_CONFIG = new LuftdatenInfoConfiguration();
    private static final String EMPTY = "";

    protected static final int REFRESH_INTERVAL_MIN = 5;
    protected final Logger logger = LoggerFactory.getLogger(BaseSensorHandler.class);
    protected LuftdatenInfoConfiguration config = DEFAULT_CONFIG;
    protected ConfigStatus configStatus = ConfigStatus.UNKNOWN;
    protected ThingStatus myThingStatus = ThingStatus.UNKNOWN;
    protected UpdateStatus lastUpdateStatus = UpdateStatus.UNKNOWN;
    protected @Nullable ScheduledFuture<?> refreshJob;

    public enum ConfigStatus {
        OK,
        IS_NULL,
        SENSOR_IS_NULL,
        SENSOR_ID_NEGATIVE,
        UNKNOWN
    };

    public enum UpdateStatus {
        OK,
        CONNECTION_ERROR,
        CONNECTION_EXCEPTION,
        VALUE_ERROR,
        VALUE_EMPTY,
        UNKNOWN
    }

    protected LifecycleStatus lifecycleStatus = LifecycleStatus.UNKNOWN;

    public enum LifecycleStatus {
        UNKNOWN,
        RUNNING,
        INITIALIZING,
        DISPOSED
    }

    public BaseSensorHandler(Thing thing) {
        super(thing);
    }

    @Override
    public void handleCommand(ChannelUID channelUID, Command command) {
        if (command instanceof RefreshType) {
            updateFromCache();
        }
    }

    @Override
    public void initialize() {
        lifecycleStatus = LifecycleStatus.INITIALIZING;
        scheduler.execute(this::startUp);
    }

    private void startUp() {
        config = getConfigAs(LuftdatenInfoConfiguration.class);
        configStatus = checkConfig(config);
        if (configStatus == ConfigStatus.OK) {
            // start getting values
            dataUpdate();
        } else {
            // config error, no further actions triggered - Thing Status visible in UI
            updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                    "Configuration not valid. Sensor ID as a number is mandatory!");
        }
        lifecycleStatus = LifecycleStatus.RUNNING;
    }

    private void startSchedule() {
        ScheduledFuture<?> localRefreshJob = refreshJob;
        if (localRefreshJob != null) {
            if (localRefreshJob.isCancelled()) {
                refreshJob = scheduler.scheduleWithFixedDelay(this::dataUpdate, 5, REFRESH_INTERVAL_MIN,
                        TimeUnit.MINUTES);
            } // else - scheduler is already running!
        } else {
            refreshJob = scheduler.scheduleWithFixedDelay(this::dataUpdate, 5, REFRESH_INTERVAL_MIN, TimeUnit.MINUTES);
        }
    }

    @Override
    public void dispose() {
        ScheduledFuture<?> localRefreshJob = refreshJob;
        if (localRefreshJob != null) {
            localRefreshJob.cancel(true);
        }
        lifecycleStatus = LifecycleStatus.DISPOSED;
    }

    /**
     * Checks if config is valid - a) not null and b) sensorid is a number
     *
     * @param c
     * @return
     */
    private ConfigStatus checkConfig(@Nullable LuftdatenInfoConfiguration c) {
        if (c != null) {
            if (c.sensorid >= 0) {
                return ConfigStatus.OK;
            } else {
                return ConfigStatus.SENSOR_ID_NEGATIVE;
            }
        } else {
            return ConfigStatus.IS_NULL;
        }
    }

    public LifecycleStatus getLifecycleStatus() {
        return lifecycleStatus;
    }

    protected void dataUpdate() {
        HTTPHandler.getHandler().request(config.sensorid, this);
    }

    public void onResponse(String data) {
        lastUpdateStatus = updateChannels(data);
        statusUpdate(lastUpdateStatus, EMPTY);
    }

    public void onError(String errorReason) {
        statusUpdate(UpdateStatus.CONNECTION_EXCEPTION,
                errorReason + " / " + LocalDateTime.now().format(DateTimeUtils.DTF));
    }

    protected void statusUpdate(UpdateStatus updateStatus, String details) {
        if (updateStatus == UpdateStatus.OK) {
            updateStatus(ThingStatus.ONLINE, ThingStatusDetail.NONE, null);
            startSchedule();
        } else {
            switch (updateStatus) {
                case CONNECTION_ERROR:
                    // start job even first update delivers no data - recovery is possible
                    startSchedule();
                    updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR,
                            "Update failed due to Connection error. Trying to recover in next refresh");
                    break;
                case CONNECTION_EXCEPTION:
                    // start job even first update delivers a Connection Exception - recovery is possible
                    startSchedule();
                    updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.COMMUNICATION_ERROR, details);
                    break;
                case VALUE_EMPTY:
                    // start job even if first update delivers no values - recovery possible
                    startSchedule();
                    updateStatus(ThingStatus.ONLINE, ThingStatusDetail.NONE,
                            "No values delivered by Sensor. Trying to recover in next refresh");
                    break;
                case VALUE_ERROR:
                    // final status - values from sensor are wrong and manual check is needed
                    updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                            "Sensor values doesn't match - please check if Sensor ID is delivering the correct Thing channel values");
                    break;
                default:
                    // final status - Configuration is wrong
                    updateStatus(ThingStatus.OFFLINE, ThingStatusDetail.CONFIGURATION_ERROR,
                            "Error during update - please check your config data");
                    break;
            }
        }
    }

    @Override
    protected void updateStatus(ThingStatus status, ThingStatusDetail statusDetail, @Nullable String description) {
        myThingStatus = status;
        super.updateStatus(status, statusDetail, description);
    }

    protected abstract UpdateStatus updateChannels(@Nullable String json);

    protected abstract void updateFromCache();
}