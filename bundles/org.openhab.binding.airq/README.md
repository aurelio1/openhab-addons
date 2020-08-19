# airq Binding

The airq Binding integrates the air analyzer <a href="http://www.air-q.com">air-Q</a> device into the openHAB system. With the binding, it is possible to subscribe to all data delivered by the air-Q device.

<img src="https://uploads-ssl.webflow.com/5bd9feee2fb42232fe1d0196/5e4a8dc0e322ca33891b51e4_air-Q%20frontal-p-800.png" alt="air-Q image" width="400px" height="324px" />

## Supported Things

_Please describe the different supported things / devices within this section._
_Which different types are supported, which models were tested etc.?_
_Note that it is planned to generate some part of this based on the XML files within ```src/main/resources/ESH-INF/thing``` of your binding._

## Discovery

Auto-discovery is not possible in this version. Since the binding has to be configured at least with the password of the device, auto-discovery would be of limited value anyway.

## Binding Configuration

The binding does not need to be configured.

## Thing Configuration

In PaperUI, the air-Q thing must be configured with (both mandatory):
<ul>
<li>Network address, e.g. 192.168.0.68</li>
<li>Password of the air-Q device</li>
</ul>
<img src="src/main/resources/configuration.png" />

The corresponding configuration in the .thing file will be explained later.

## Channels

The air-Q Thing offers access to all sensor data of the air-Q, according to its version. This includes also the Maximum Error per sensor value.

| channel      | type   | description                              |
|--------------|--------|------------------------------------------|
| DeviceID     | String | Individual ID of the device              |
| Status       | String | Status of the sensors                    |
| TypPS        | Number | Average size of Fine Dust [experimental] |
| bat          | Number | Battery State                            |
| cnt0_3       | Number | Fine Dust >0,3 &mu;m                     |
| cnt0_5       | Number | Fine Dust >0,5 &mu;m                     |
| cnt1         | Number | Fine Dust >1 &mu;m                       |
| cnt2_5       | Number | Fine Dust >2,5 &mu;m                     |
| cnt5         | Number | Fine Dust >5 &mu;m                       |
| cnt10        | Number | Fine Dust >10 &mu;m                      |
| co2          | Number | CO<sub>2</sub> concentration             |
| dCO2dt       | Number | Change of CO<sub>2</sub> concentration   |
| dHdt         | Number | Change of Humidity                       |
| dewpt        | Number | Dew Point                                |
| door_event   | Switch | Door Event (experimental)                |
| health       | Number | Health Index                             |
| humidity     | Number | Humidity in percent                      |
| humidity_abs | Number | Absolute Humidity                        |
| measuretime  | Number | Milliseconds needed for measurement      |
| no2          | Number | NO<sub>2</sub> concentration             |
| o3           | Number | O<sub>3</sub> concentration              |
| oxygen       | Number | Oxygen concentration                     |
| performance  | Number | Performance index                        |
| pm1          | Number | Fine Dust concentration > 1&mu;m         |
| pm2_5        | Number | Fine Dust concentration >2.5 &mu;m       |
| pm10         | Number | Fine Dust concentration >10 &mu;m        |
| pressure     | Number | Pressure                                 |
| so2          | Number | SO<sub>2</sub> concentration             |
| sound        | Number | Noise                                    |
| temperature  | Number | Temperature                              |
| timestamp    | Time   | Timestamp of measurement                 |
| tvoc         | Number | VOC concentration                        |
| uptime       | Number | uptime in seconds                        |
