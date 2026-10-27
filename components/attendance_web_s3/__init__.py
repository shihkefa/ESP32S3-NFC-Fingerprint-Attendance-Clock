import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import fingerprint_grow, light, output, sensor, time, uart, wifi
from esphome.const import CONF_ID

DEPENDENCIES = ["web_server_base", "time", "light", "wifi", "fingerprint_grow", "sensor", "uart", "output"]

attendance_s3_ns = cg.esphome_ns.namespace("attendance_web_s3")
AttendanceWebS3 = attendance_s3_ns.class_("AttendanceWebS3", cg.Component)
CONF_TIME_ID = "time_id"
CONF_HARDWARE_RTC_ID = "hardware_rtc_id"
CONF_STATUS_LIGHT_ID = "status_light_id"
CONF_WIFI_ID = "wifi_id"
CONF_FINGERPRINT_ID = "fingerprint_id"
CONF_FINGERPRINT_COUNT_ID = "fingerprint_count_id"
CONF_FINGERPRINT_CAPACITY_ID = "fingerprint_capacity_id"
CONF_FINGERPRINT_STATUS_ID = "fingerprint_status_id"
CONF_TTS_UART_ID = "tts_uart_id"
CONF_DOOR_RELAY_ID = "door_relay_id"
CONF_ADMIN_PASSWORD = "admin_password"

CONFIG_SCHEMA = cv.Schema({
    cv.GenerateID(): cv.declare_id(AttendanceWebS3),
    cv.Required(CONF_TIME_ID): cv.use_id(time.RealTimeClock),
    cv.Required(CONF_HARDWARE_RTC_ID): cv.use_id(time.RealTimeClock),
    cv.Required(CONF_STATUS_LIGHT_ID): cv.use_id(light.LightState),
    cv.Required(CONF_WIFI_ID): cv.use_id(wifi.WiFiComponent),
    cv.Required(CONF_FINGERPRINT_ID): cv.use_id(fingerprint_grow.FingerprintGrowComponent),
    cv.Required(CONF_FINGERPRINT_COUNT_ID): cv.use_id(sensor.Sensor),
    cv.Required(CONF_FINGERPRINT_CAPACITY_ID): cv.use_id(sensor.Sensor),
    cv.Required(CONF_FINGERPRINT_STATUS_ID): cv.use_id(sensor.Sensor),
    cv.Required(CONF_TTS_UART_ID): cv.use_id(uart.UARTComponent),
    cv.Required(CONF_DOOR_RELAY_ID): cv.use_id(output.BinaryOutput),
    cv.Required(CONF_ADMIN_PASSWORD): cv.string_strict,
}).extend(cv.COMPONENT_SCHEMA)

async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    rtc = await cg.get_variable(config[CONF_TIME_ID])
    cg.add(var.set_time(rtc))
    hardware_rtc = await cg.get_variable(config[CONF_HARDWARE_RTC_ID])
    cg.add(var.set_hardware_rtc(hardware_rtc))
    status_light = await cg.get_variable(config[CONF_STATUS_LIGHT_ID])
    cg.add(var.set_status_light(status_light))
    wifi_component = await cg.get_variable(config[CONF_WIFI_ID])
    cg.add(var.set_wifi(wifi_component))
    fingerprint = await cg.get_variable(config[CONF_FINGERPRINT_ID])
    cg.add(var.set_fingerprint(fingerprint))
    fingerprint_count = await cg.get_variable(config[CONF_FINGERPRINT_COUNT_ID])
    cg.add(var.set_fingerprint_count_sensor(fingerprint_count))
    fingerprint_capacity = await cg.get_variable(config[CONF_FINGERPRINT_CAPACITY_ID])
    cg.add(var.set_fingerprint_capacity_sensor(fingerprint_capacity))
    fingerprint_status = await cg.get_variable(config[CONF_FINGERPRINT_STATUS_ID])
    cg.add(var.set_fingerprint_status_sensor(fingerprint_status))
    tts_uart = await cg.get_variable(config[CONF_TTS_UART_ID])
    cg.add(var.set_tts_uart(tts_uart))
    door_relay = await cg.get_variable(config[CONF_DOOR_RELAY_ID])
    cg.add(var.set_door_relay(door_relay))
    cg.add(var.set_admin_password(config[CONF_ADMIN_PASSWORD]))
