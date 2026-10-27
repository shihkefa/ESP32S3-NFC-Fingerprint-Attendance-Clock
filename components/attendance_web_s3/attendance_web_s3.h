#pragma once
#include "esphome/core/component.h"
#include "esphome/core/preferences.h"
#include "esphome/components/light/light_state.h"
#include "esphome/components/ds1307/ds1307.h"
#include "esphome/components/fingerprint_grow/fingerprint_grow.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/time/real_time_clock.h"
#include "esphome/components/uart/uart.h"
#include "esphome/components/output/binary_output.h"
#include "esphome/components/web_server_base/web_server_base.h"
#include "esphome/components/wifi/wifi_component.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include <array>
#include <cstddef>
#include <ctime>
#include <deque>
#include <vector>

namespace esphome::attendance_web_s3 {
static constexpr size_t MAX_EMPLOYEES = 500;
static constexpr size_t MAX_DAILY_NOTES = 5000;
static constexpr size_t LEGACY_MAX_DAILY_NOTES = 64;
static constexpr size_t LEGACY_PARTITION_MAX_DAILY_NOTES = 256;
static constexpr uint32_t LOG_MAGIC = 0x4154544E;
static constexpr uint32_t EMPLOYEE_MAGIC = 0x454D504C;
static constexpr uint16_t LEGACY_EMPLOYEE_STORE_VERSION = 1;
static constexpr uint16_t EMBEDDED_NOTE_EMPLOYEE_STORE_VERSION = 2;
static constexpr uint16_t EMPLOYEE_STORE_VERSION = 4;
static constexpr uint32_t EMPLOYEE_SLOT_SIZE = 0x10000;
static constexpr uint8_t EMPLOYEE_SLOT_COUNT = 2;
static constexpr uint32_t NOTE_MAGIC = 0x4E4F5445;
static constexpr uint16_t LEGACY_NOTE_STORE_VERSION = 1;
static constexpr uint16_t NOTE_STORE_VERSION = 3;
static constexpr uint32_t NOTE_SLOT_SIZE = 0x90000;
static constexpr uint8_t NOTE_SLOT_COUNT = 2;
static constexpr uint32_t NOTE_BANK_DATA_OFFSET = 0x1000;
static constexpr uint32_t NOTE_RECORD_MAGIC = 0x4E524543;
static constexpr uint32_t LEGACY_ATTENDANCE_PARTITION_SIZE = 0x80000;
static constexpr uint32_t LEGACY_EMPLOYEE_STORAGE_OFFSET =
    LEGACY_ATTENDANCE_PARTITION_SIZE - EMPLOYEE_SLOT_SIZE * EMPLOYEE_SLOT_COUNT;
static constexpr uint32_t LEGACY_NOTE_PARTITION_OFFSET = 0x90000;
static constexpr uint32_t LEGACY_NOTE_SLOT_SIZE = 0x4000;
static constexpr uint8_t LOG_HIGH_WATER_PERCENT = 99;
// Flash sector erases briefly stall instruction/data access. Pace background
// maintenance so OLED, PN532 and the optional fingerprint reader still get
// enough loop time and loopTask cannot trip the task watchdog.
static constexpr uint32_t FLASH_ERASE_INTERVAL_MS = 50;
static constexpr uint32_t ADMIN_PASSWORD_MAGIC = 0x41505744;
static constexpr uint16_t ADMIN_PASSWORD_STORE_VERSION = 1;
static constexpr size_t MAX_ADMIN_PASSWORD_BYTES = 64;
static constexpr uint32_t MODE_SCHEDULE_MAGIC = 0x4D534348;
static constexpr uint16_t MODE_SCHEDULE_STORE_VERSION = 1;
enum AttendanceAction : uint8_t {
  ACTION_CLOCK_OUT = 0,
  ACTION_CLOCK_IN = 1,
  ACTION_OVERTIME_IN = 2,
  ACTION_OVERTIME_OUT = 3,
};
struct __attribute__((packed)) Employee {
  uint16_t id{0};
  uint8_t active{0};
  uint8_t can_open_door{0};
  uint8_t finger1_enrolled{0};
  uint8_t finger2_enrolled{0};
  char code[17]{};
  char name[41]{};
  char uid[25]{};
  // Reserved for Flash compatibility with v2.0.5 and earlier; no longer shown or used.
  char voice_name[33]{};
};
struct __attribute__((packed)) DailyNote {
  uint32_t date{0};
  uint16_t employee_id{0};
  uint8_t active{0};
  uint8_t reserved{0};
  char text[49]{};
};

struct __attribute__((packed)) NoteJournalRecord {
  uint32_t magic{NOTE_RECORD_MAGIC};
  uint32_t date{0};
  uint16_t employee_id{0};
  uint8_t active{0};
  uint8_t reserved{0};
  char text[48]{};
  uint32_t crc{0};
};

// Only this compact index stays in internal RAM. The note text itself always
// remains in Flash, so this firmware never initializes or allocates PSRAM.
struct __attribute__((packed)) NoteIndexEntry {
  uint32_t date{0};
  uint16_t employee_id{0};
  uint16_t record_index{0};
};
struct __attribute__((packed)) EmployeeStoreHeader {
  uint32_t magic;
  uint16_t version;
  uint16_t reserved;
  uint32_t generation;
  uint32_t payload_size;
  uint32_t payload_crc;
};
struct __attribute__((packed)) AdminPasswordStore {
  uint32_t magic;
  uint16_t version;
  uint16_t length;
  char password[MAX_ADMIN_PASSWORD_BYTES + 1];
  uint32_t crc;
};
struct __attribute__((packed)) ModeScheduleStore {
  uint32_t magic;
  uint16_t version;
  uint8_t master_enabled;
  int8_t last_mode;
  uint8_t entry_enabled[4];
  uint8_t hour[4];
  uint8_t minute[4];
  uint32_t crc;
};
// 32 bytes exactly, so each 4 KiB erase sector contains 128 complete records.
struct __attribute__((packed)) LogRecord { uint32_t magic; uint32_t timestamp; uint16_t employee_id; uint8_t action; uint8_t reserved; uint32_t uid_hash; uint8_t padding[12]; uint32_t crc; };
static_assert(sizeof(Employee) == 122, "Employee flash layout changed");
static_assert(sizeof(DailyNote) == 57, "Daily note flash layout changed");
static_assert(sizeof(NoteJournalRecord) == 64, "Note journal record must remain 64 bytes");
static_assert(sizeof(NoteIndexEntry) == 8, "Note index entry must remain 8 bytes");
static_assert(sizeof(EmployeeStoreHeader) == 20, "Employee store header layout changed");
static_assert(sizeof(ModeScheduleStore) == 24, "Mode schedule preference layout changed");
static_assert(sizeof(EmployeeStoreHeader) + sizeof(std::array<Employee, MAX_EMPLOYEES>) <= EMPLOYEE_SLOT_SIZE,
              "Employee data exceed one Flash slot");
static_assert(sizeof(EmployeeStoreHeader) + sizeof(std::array<Employee, MAX_EMPLOYEES>) +
                      sizeof(std::array<DailyNote, LEGACY_MAX_DAILY_NOTES>) <= EMPLOYEE_SLOT_SIZE,
              "Legacy embedded note layout exceeds one employee Flash slot");
static constexpr size_t NOTE_PAYLOAD_SIZE = sizeof(DailyNote) * MAX_DAILY_NOTES;
static_assert(sizeof(EmployeeStoreHeader) + NOTE_PAYLOAD_SIZE <= NOTE_SLOT_SIZE,
              "Daily note data exceed one note Flash slot");
static constexpr size_t NOTE_JOURNAL_RECORD_CAPACITY =
    (NOTE_SLOT_SIZE - NOTE_BANK_DATA_OFFSET) / sizeof(NoteJournalRecord);
static_assert(NOTE_JOURNAL_RECORD_CAPACITY > MAX_DAILY_NOTES,
              "Note journal bank must have room for all active notes plus updates");
static constexpr size_t LOG_SCAN_BLOCK_SIZE = 4096;
static_assert(LOG_SCAN_BLOCK_SIZE % sizeof(LogRecord) == 0, "Log scan block must contain complete records");

class AttendanceWebS3 : public Component, public AsyncWebHandler {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }
  void set_time(time::RealTimeClock *rtc) { rtc_ = rtc; }
  void set_hardware_rtc(ds1307::DS1307Component *rtc) { hardware_rtc_ = rtc; }
  void set_status_light(light::LightState *status_light) { status_light_ = status_light; }
  void set_wifi(wifi::WiFiComponent *wifi) { wifi_ = wifi; }
  void set_fingerprint(fingerprint_grow::FingerprintGrowComponent *fingerprint) { fingerprint_ = fingerprint; }
  void set_fingerprint_count_sensor(sensor::Sensor *value) { fingerprint_count_sensor_ = value; }
  void set_fingerprint_capacity_sensor(sensor::Sensor *value) { fingerprint_capacity_sensor_ = value; }
  void set_fingerprint_status_sensor(sensor::Sensor *value) { fingerprint_status_sensor_ = value; }
  void set_tts_uart(uart::UARTComponent *tts_uart) { tts_uart_ = tts_uart; }
  void set_door_relay(output::BinaryOutput *door_relay) { door_relay_ = door_relay; }
  void set_admin_password(const std::string &password) {
    configured_admin_password_ = password;
    admin_password_ = password;
  }
  void select_action(bool clock_in);
  void select_overtime_action(bool clock_in);
  void cycle_attendance_mode();
  void trigger_remote_unlock();
  void refresh_status_light();
  void restart_network_time_sync();
  bool network_time_write_allowed() const { return !manual_time_override_; }
  void mark_network_time_synced(const std::string &source);
  std::string last_sync_time_text() const;
  std::string time_source_text() const;
  std::string last_card_info_text() const;
  std::string last_card_employee_text() const { return last_card_employee_; }
  std::string last_card_uid_text() const { return last_card_uid_; }
  std::string last_card_result_text() const { return last_card_result_; }
  std::string attendance_mode_text() const;
  std::string display_mode_text() const;
  std::string display_time_text() const;
  std::string display_card_code() const { return last_card_code_; }
  std::string display_card_state() const { return last_card_display_state_; }
  bool time_is_valid() const { return effective_now_().is_valid(); }
  bool hardware_rtc_is_connected() const { return hardware_rtc_ != nullptr && !hardware_rtc_->is_failed(); }
  bool network_is_connected() const { return wifi_ != nullptr && wifi_->is_connected(); }
  bool handle_tag(const std::string &tag);
  bool handle_fingerprint(uint16_t finger_id, uint16_t confidence);
  bool canHandle(AsyncWebServerRequest *request) const override;
  void handleRequest(AsyncWebServerRequest *request) override;
 protected:
  void load_employees_(); bool save_employees_(); void load_notes_(); void scan_flash_();
  bool inspect_employee_slot_at_(uint32_t offset, EmployeeStoreHeader *header, bool *has_embedded_notes);
  bool validate_note_bank_header_(uint8_t bank, uint32_t *generation) const;
  bool activate_note_bank_(uint8_t bank);
  bool reset_note_journal_();
  bool compact_notes_(uint32_t cutoff_date = 0);
  bool append_note_change_(const DailyNote &note);
  bool read_note_(size_t index, DailyNote *note) const;
  int find_note_index_(uint16_t employee_id, uint32_t date) const;
  bool migrate_flat_note_slot_(const esp_partition_t *source_partition, uint32_t slot_offset,
                               uint16_t expected_version, size_t record_count, uint32_t generation,
                               uint8_t target_bank);
  uint32_t partition_crc_(const esp_partition_t *partition, uint32_t offset, size_t size, bool *ok);
  uint32_t employee_slot_offset_(uint8_t slot) const;
  uint32_t note_slot_offset_(uint8_t slot) const;
  bool erase_partition_range_safely_(const esp_partition_t *partition, uint32_t offset, uint32_t size);
  bool write_partition_range_safely_(const esp_partition_t *partition, uint32_t offset, const void *data,
                                     size_t size);
  bool read_partition_range_safely_(const esp_partition_t *partition, uint32_t offset, void *data, size_t size);
  bool verify_partition_range_safely_(const esp_partition_t *partition, uint32_t offset, const void *data,
                                      size_t size);
  bool append_log_(uint16_t employee_id, uint8_t action, uint32_t uid_hash, uint32_t timestamp,
                   bool manual = false);
  int find_uid_(const std::string &uid) const; uint32_t cutoff_timestamp_() const;
  ESPTime effective_now_() const; void update_scheduled_mode_(); void purge_expired_notes_();
  void select_action_code_(uint8_t action);
  void remember_card_result_(const std::string &uid, const std::string &employee, const std::string &result);
  void send_json_(AsyncWebServerRequest *, int, const std::string &);
  void serve_page_(AsyncWebServerRequest *); void serve_status_(AsyncWebServerRequest *);
  void serve_employees_(AsyncWebServerRequest *); void serve_logs_(AsyncWebServerRequest *);
  void serve_notes_(AsyncWebServerRequest *); void mutate_note_(AsyncWebServerRequest *);
  void serve_export_launcher_(AsyncWebServerRequest *); void serve_csv_launcher_(AsyncWebServerRequest *);
  void serve_export_data_(AsyncWebServerRequest *);
  void mutate_employee_(AsyncWebServerRequest *); void delete_employee_(AsyncWebServerRequest *);
  void bind_card_manual_(AsyncWebServerRequest *);
  void clear_logs_(AsyncWebServerRequest *); void clear_logs_status_(AsyncWebServerRequest *);
  void begin_fingerprint_enroll_(AsyncWebServerRequest *);
  void delete_fingerprint_(AsyncWebServerRequest *);
  void clear_all_fingerprints_(AsyncWebServerRequest *);
  void bind_fingerprint_(AsyncWebServerRequest *);
  void add_manual_attendance_(AsyncWebServerRequest *);
  void set_attendance_mode_(AsyncWebServerRequest *);
  void set_manual_time_(AsyncWebServerRequest *); void restore_automatic_time_(AsyncWebServerRequest *);
  void mutate_mode_schedule_(AsyncWebServerRequest *);
  void load_admin_password_(); bool save_admin_password_(const std::string &password);
  void load_mode_schedule_(); bool save_mode_schedule_();
  bool verify_admin_password_(const std::string &password) const;
  void apply_web_auth_password_(); void change_admin_password_(AsyncWebServerRequest *);
  bool check_import_token_(AsyncWebServerRequest *request) const;
  bool import_storage_ready_() const;
  bool commit_import_note_bank_();
  void reset_import_session_(bool reload_persistent_data);
  void begin_backup_import_(AsyncWebServerRequest *); void erase_backup_import_chunk_(AsyncWebServerRequest *);
  void import_employee_(AsyncWebServerRequest *);
  void import_note_(AsyncWebServerRequest *); void import_log_batch_(AsyncWebServerRequest *);
  void finish_backup_import_(AsyncWebServerRequest *); void abort_backup_import_(AsyncWebServerRequest *);
  void show_enroll_color_(); void update_enroll_rainbow_(); void restore_mode_color_();
  bool record_attendance_(size_t employee_index, const std::string &credential_label);
  int find_fingerprint_id_(uint16_t finger_id) const;
  static uint16_t fingerprint_template_id_(size_t employee_index, uint8_t finger_number) {
    return static_cast<uint16_t>(employee_index * 2U + finger_number);
  }
  static uint16_t stored_fingerprint_template_id_(const Employee &employee, size_t employee_index,
                                                   uint8_t finger_number);
  static void store_fingerprint_template_id_(Employee &employee, uint8_t finger_number, uint16_t template_id);
  void on_fingerprint_enrollment_scan_(uint8_t scan_num, uint16_t finger_id);
  void on_fingerprint_enrollment_done_(uint16_t finger_id);
  void on_fingerprint_enrollment_failed_(uint16_t finger_id);
  void unlock_door_(const char *source);
  void process_door_relay_();
  void queue_tts_phrase_(const Employee *employee, uint8_t phrase);
  void process_tts_();
  void send_tts_frame_(const std::vector<uint8_t> &payload);
  time::RealTimeClock *rtc_{nullptr}; ds1307::DS1307Component *hardware_rtc_{nullptr};
  light::LightState *status_light_{nullptr};
  wifi::WiFiComponent *wifi_{nullptr};
  fingerprint_grow::FingerprintGrowComponent *fingerprint_{nullptr};
  sensor::Sensor *fingerprint_count_sensor_{nullptr};
  sensor::Sensor *fingerprint_capacity_sensor_{nullptr};
  sensor::Sensor *fingerprint_status_sensor_{nullptr};
  uart::UARTComponent *tts_uart_{nullptr};
  output::BinaryOutput *door_relay_{nullptr};
  const esp_partition_t *partition_{nullptr};
  const esp_partition_t *notes_partition_{nullptr};
  std::array<Employee, MAX_EMPLOYEES> employees_{};
  std::array<NoteIndexEntry, MAX_DAILY_NOTES> note_index_{};
  std::array<DailyNote, LEGACY_MAX_DAILY_NOTES> embedded_notes_{};
  // Read Flash in 4 KiB batches during boot. Reading one 32-byte record per
  // esp_partition_read call would require about 160,000 calls for a 5 MiB
  // partition and can trip the startup watchdog.
  std::array<uint8_t, LOG_SCAN_BLOCK_SIZE> log_scan_buffer_{};
  uint32_t log_region_size_{0};
  uint32_t log_physical_size_{0};
  uint32_t employee_storage_offset_{0};
  uint32_t employee_generation_{0};
  int8_t employee_active_slot_{-1};
  uint32_t note_generation_{0};
  int8_t note_active_slot_{-1};
  uint16_t note_count_{0};
  uint16_t note_journal_used_{0};
  bool embedded_notes_available_{false};
  uint32_t write_offset_{0};
  uint32_t log_record_count_{0};
  uint32_t log_sequence_{0};
  int8_t pending_action_{-1};
  int16_t enroll_employee_{-1}; std::string last_result_{"等待操作"};
  int16_t fingerprint_enroll_employee_{-1};
  uint8_t fingerprint_enroll_number_{0};
  uint16_t last_unmapped_fingerprint_id_{0};
  ESPPreferenceObject admin_password_pref_;
  ESPPreferenceObject mode_schedule_pref_;
  ModeScheduleStore mode_schedule_{};
  std::string configured_admin_password_{};
  std::string admin_password_{};
  bool runtime_admin_password_loaded_{false};
  bool import_in_progress_{false};
  uint32_t import_token_{0};
  uint32_t last_import_millis_{0};
  uint32_t import_erase_offset_{0};
  uint32_t import_note_erase_offset_{0};
  int8_t import_note_staging_slot_{-1};
  uint32_t import_note_generation_{0};
  bool import_note_staging_ready_{false};
  bool import_reload_pending_{false};
  uint32_t last_import_erase_millis_{0};
  bool import_erase_failed_{false};
  bool clear_logs_in_progress_{false};
  bool clear_logs_failed_{false};
  uint32_t clear_logs_erase_offset_{0};
  uint32_t last_clear_logs_erase_millis_{0};
  uint16_t imported_employee_count_{0};
  uint16_t imported_note_count_{0};
  uint32_t imported_log_count_{0};
  uint32_t last_import_timestamp_{0};
  bool manual_time_override_{false};
  bool network_time_synced_{false};
  std::string last_sync_source_{"本次開機尚未完成校時"};
  time_t last_sync_timestamp_{0};
  std::string last_card_employee_{"尚無刷卡紀錄"};
  std::string last_card_uid_{"尚無刷卡紀錄"};
  std::string last_card_result_{"尚無刷卡紀錄"};
  std::string last_card_code_{"READY"};
  std::string last_card_display_state_{""};
  time_t last_card_timestamp_{0};
  time_t manual_time_base_{0};
  uint32_t manual_time_millis_{0};
  uint32_t last_time_check_millis_{0};
  uint32_t last_schedule_bucket_{0};
  uint32_t last_retention_cleanup_date_{0};
  uint32_t last_rainbow_millis_{0};
  uint8_t rainbow_index_{0};
  bool door_relay_active_{false};
  uint32_t door_relay_off_millis_{0};
  std::deque<std::vector<uint8_t>> tts_queue_{};
  uint32_t last_tts_query_millis_{0};
  uint32_t tts_query_sent_millis_{0};
  bool tts_waiting_status_{false};
};
}  // namespace esphome::attendance_web_s3
