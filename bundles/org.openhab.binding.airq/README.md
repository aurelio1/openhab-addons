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
| cnt0_3       | Number | Fine Dust >0,3 &mu;-meter                |
| cnt0_5       | Number | Fine Dust >0,5 mu-meter                  |
| cnt1         | Number | Fine Dust >1 mu-meter                    |
| cnt2_5       | Number | Fine Dust >2,5 mu-meter                  |
| cnt5         | Number | Fine Dust >5 mu-meter                    |
| cnt10        | Number | Fine Dust >10 mu-meter                   |
| co2          | Number | This is the control channel              |
| dCO2dt       | Number | This is the control channel              |
| dHdt         | Number | This is the control channel              |
| dewpt        | Number | This is the control channel              |
| door_event   | Switch | This is the control channel              |
| health       | Number | This is the control channel              |
| humidity     | Number | This is the control channel              |
| humidity_abs | Number | This is the control channel              |
| measuretime  | Number | This is the control channel              |
| no2          | Number | This is the control channel              |
| o3           | Number | This is the control channel              |
| oxygen       | Number | This is the control channel              |
| performance  | Number | This is the control channel              |
| pm1          | Number | This is the control channel              |
| pm2_5        | Number | This is the control channel              |
| pm10         | Number | This is the control channel              |
| pressure     | Number | This is the control channel              |
| so2          | Number | This is the control channel              |
| sound        | Number | This is the control channel              |
| temperature  | Number | This is the control channel              |
| timestamp    | Time   | This is the control channel              |
| tvoc         | Number | This is the control channel              |
| uptime       | Number | uptime in seconds                        |

