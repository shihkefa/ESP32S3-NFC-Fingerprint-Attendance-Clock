#include "attendance_web_s3.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sstream>
#include <sys/time.h>
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_task_wdt.h"

namespace esphome::attendance_web_s3 {
static const char *const TAG = "attendance_web_s3";
static constexpr float STATUS_LIGHT_BRIGHTNESS = 0.65f;
static void feed_watchdog_if_registered() {
  // HTTP handlers are not registered with ESP-IDF's task watchdog. Calling
  // esp_task_wdt_reset() from them produces "task not found" and does not help
  // loopTask. Only feed when the current task is actually registered.
  if (esp_task_wdt_status(nullptr) == ESP_OK)
    esp_task_wdt_reset();
}
static const char *action_label(uint8_t action) {
  switch (action) {
    case ACTION_CLOCK_OUT:
      return "下班";
    case ACTION_CLOCK_IN:
      return "上班";
    case ACTION_OVERTIME_IN:
      return "加班上班";
    case ACTION_OVERTIME_OUT:
      return "加班下班";
    default:
      return "未知";
  }
}
static uint32_t fnv1a_update(uint32_t hash, const void *data, size_t len) {
  const auto *bytes = static_cast<const uint8_t *>(data);
  while (len--) {
    hash ^= *bytes++;
    hash *= 16777619U;
  }
  return hash;
}
static uint32_t fnv1a(const void *data, size_t len) { return fnv1a_update(2166136261U, data, len); }
static uint32_t log_sequence(const LogRecord &record) {
  uint32_t value = 0;
  memcpy(&value, record.padding, sizeof(value));
  return value;
}
static void set_log_sequence(LogRecord *record, uint32_t value) {
  memcpy(record->padding, &value, sizeof(value));
}
static std::string esc(const char *s) { std::string o; for (; *s; s++) { if (*s=='"'||*s=='\\') o+='\\'; if ((uint8_t)*s>=32) o+=*s; } return o; }
static int hex_value(char c) { if(c>='0'&&c<='9')return c-'0'; if(c>='A'&&c<='F')return c-'A'+10; if(c>='a'&&c<='f')return c-'a'+10; return -1; }
static std::string url_decode_value(const std::string &in) { std::string out; out.reserve(in.size()); for(size_t i=0;i<in.size();i++) { if(in[i]=='%'&&i+2<in.size()) { int a=hex_value(in[i+1]),b=hex_value(in[i+2]); if(a>=0&&b>=0) { out.push_back((char)((a<<4)|b)); i+=2; continue; } } out.push_back(in[i]=='+'?' ':in[i]); } return out; }
static std::string param(AsyncWebServerRequest *r, const char *name) { return r->hasParam(name) ? url_decode_value(r->getParam(name)->value().c_str()) : ""; }
static bool parse_uint32_strict(const std::string &value, uint32_t *output) {
  if (output == nullptr || value.empty())
    return false;
  uint64_t parsed = 0;
  for (const char character : value) {
    if (character < '0' || character > '9')
      return false;
    parsed = parsed * 10U + static_cast<uint8_t>(character - '0');
    if (parsed > UINT32_MAX)
      return false;
  }
  *output = static_cast<uint32_t>(parsed);
  return true;
}
static bool is_ascii_space(char value) {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}
static std::string trim_ascii_space(const std::string &value) {
  size_t begin = 0;
  size_t end = value.size();
  while (begin < end && is_ascii_space(value[begin]))
    begin++;
  while (end > begin && is_ascii_space(value[end - 1]))
    end--;
  return value.substr(begin, end - begin);
}
static char ascii_upper(char value) {
  return value >= 'a' && value <= 'z' ? static_cast<char>(value - ('a' - 'A')) : value;
}
static bool normalize_card_uid(const std::string &input, std::string *output) {
  if (output == nullptr)
    return false;
  std::string compact;
  compact.reserve(input.size());
  for (const char value : input) {
    if (is_ascii_space(value) || value == '-' || value == ':')
      continue;
    if (hex_value(value) < 0)
      return false;
    compact.push_back(ascii_upper(value));
  }
  // PN532 cards used by this project normally contain a 4-byte or 7-byte UID.
  if (compact.size() != 8U && compact.size() != 14U)
    return false;
  output->clear();
  output->reserve(compact.size() + compact.size() / 2U - 1U);
  for (size_t index = 0; index < compact.size(); index += 2U) {
    if (index != 0)
      output->push_back('-');
    output->push_back(compact[index]);
    output->push_back(compact[index + 1U]);
  }
  return output->size() < sizeof(Employee::uid);
}
static bool employee_code_equal(const std::string &left, const char *right) {
  const size_t right_size = strlen(right);
  if (left.size() != right_size)
    return false;
  for (size_t index = 0; index < left.size(); index++) {
    if (ascii_upper(left[index]) != ascii_upper(right[index]))
      return false;
  }
  return true;
}
static size_t utf8_character_count(const std::string &value) {
  size_t count = 0;
  for (const unsigned char byte : value) {
    if ((byte & 0xC0U) != 0x80U)
      count++;
  }
  return count;
}
static bool secure_equals(const std::string &left, const std::string &right) {
  const size_t compare_length = std::max(left.size(), right.size());
  size_t difference = left.size() ^ right.size();
  for (size_t i = 0; i < compare_length; i++) {
    const uint8_t left_value = i < left.size() ? static_cast<uint8_t>(left[i]) : 0;
    const uint8_t right_value = i < right.size() ? static_cast<uint8_t>(right[i]) : 0;
    difference |= left_value ^ right_value;
  }
  return difference == 0;
}
static bool valid_new_admin_password(const std::string &password) {
  if (password.size() < 8 || password.size() > MAX_ADMIN_PASSWORD_BYTES)
    return false;
  for (const unsigned char byte : password) {
    if (byte < 0x21U || byte > 0x7EU)
      return false;
  }
  return true;
}
static bool parse_date_value(const std::string &value, uint32_t *date) {
  if (date == nullptr || value.size() != 10 || value[4] != '-' || value[7] != '-')
    return false;
  for (size_t index = 0; index < value.size(); index++) {
    if (index != 4 && index != 7 && (value[index] < '0' || value[index] > '9'))
      return false;
  }
  const int year = atoi(value.substr(0, 4).c_str());
  const int month = atoi(value.substr(5, 2).c_str());
  const int day = atoi(value.substr(8, 2).c_str());
  if (year < 2020 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31)
    return false;
  struct tm candidate {};
  candidate.tm_year = year - 1900;
  candidate.tm_mon = month - 1;
  candidate.tm_mday = day;
  candidate.tm_hour = 12;
  const time_t timestamp = mktime(&candidate);
  struct tm normalized {};
  localtime_r(&timestamp, &normalized);
  if (normalized.tm_year != year - 1900 || normalized.tm_mon != month - 1 || normalized.tm_mday != day)
    return false;
  *date = static_cast<uint32_t>(year * 10000 + month * 100 + day);
  return true;
}
static void format_date_value(uint32_t date, char *output, size_t output_size) {
  snprintf(output, output_size, "%04u-%02u-%02u", static_cast<unsigned>(date / 10000U),
           static_cast<unsigned>((date / 100U) % 100U), static_cast<unsigned>(date % 100U));
}

void AttendanceWebS3::setup() {
  load_admin_password_();
  load_mode_schedule_();
  apply_web_auth_password_();
  partition_ = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t) 0x40, "attendance");
  if (!partition_) { ESP_LOGE(TAG, "attendance partition missing"); mark_failed(); return; }
  notes_partition_ =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t) 0x41, "att_notes");
  const uint32_t employee_storage_size = EMPLOYEE_SLOT_SIZE * EMPLOYEE_SLOT_COUNT;
  if (partition_->size <= employee_storage_size || EMPLOYEE_SLOT_SIZE % partition_->erase_size != 0) {
    ESP_LOGE(TAG, "attendance partition is too small or has incompatible erase geometry");
    mark_failed();
    return;
  }
  employee_storage_offset_ = partition_->size - employee_storage_size;
  log_physical_size_ = employee_storage_offset_;
  const uint32_t target_log_size = static_cast<uint32_t>(
      (static_cast<uint64_t>(log_physical_size_) * LOG_HIGH_WATER_PERCENT + 99U) / 100U);
  log_region_size_ = ((target_log_size + partition_->erase_size - 1U) / partition_->erase_size) *
                     partition_->erase_size;
  if (log_region_size_ > log_physical_size_)
    log_region_size_ = (log_physical_size_ / partition_->erase_size) * partition_->erase_size;
  if (log_region_size_ == 0) {
    ESP_LOGE(TAG, "attendance log region is unavailable");
    mark_failed();
    return;
  }
  load_employees_();
  if (notes_partition_ != nullptr && notes_partition_->size >= NOTE_SLOT_SIZE * NOTE_SLOT_COUNT &&
      NOTE_SLOT_SIZE % notes_partition_->erase_size == 0) {
    load_notes_();
  } else {
    notes_partition_ = nullptr;
    ESP_LOGE(TAG, "att_notes partition missing or incompatible; daily notes are unavailable");
  }
  ESP_LOGI(TAG, "Scanning %u bytes of attendance Flash in %u-byte blocks",
           (unsigned) log_region_size_, (unsigned) LOG_SCAN_BLOCK_SIZE);
  scan_flash_();
  if (door_relay_ != nullptr)
    door_relay_->turn_off();
  if (fingerprint_ != nullptr && !fingerprint_->is_failed()) {
    fingerprint_->add_on_finger_scan_matched_callback(
        [this](uint16_t finger_id, uint16_t confidence) { this->handle_fingerprint(finger_id, confidence); });
    fingerprint_->add_on_finger_scan_unmatched_callback([this]() {
      this->last_result_ = "未登記指紋";
      this->last_card_code_ = "UNKNOWN";
      this->last_card_display_state_ = "FAIL";
      this->queue_tts_phrase_(nullptr, 5);
    });
    fingerprint_->add_on_finger_scan_invalid_callback([this]() {
      this->last_result_ = "指紋讀取失敗，請重新按壓";
      this->last_card_display_state_ = "FAIL";
      this->queue_tts_phrase_(nullptr, 6);
    });
    fingerprint_->add_on_enrollment_scan_callback(
        [this](uint8_t scan_num, uint16_t finger_id) { this->on_fingerprint_enrollment_scan_(scan_num, finger_id); });
    fingerprint_->add_on_enrollment_done_callback(
        [this](uint16_t finger_id) { this->on_fingerprint_enrollment_done_(finger_id); });
    fingerprint_->add_on_enrollment_failed_callback(
        [this](uint16_t finger_id) { this->on_fingerprint_enrollment_failed_(finger_id); });
  }
  if (web_server_base::global_web_server_base != nullptr)
    web_server_base::global_web_server_base->add_handler(this);
}

void AttendanceWebS3::dump_config() {
  ESP_LOGCONFIG(TAG,
                "Attendance Web: /attendance, employees=%u, log capacity=%u, high-water=%u%%, "
                "log offset=%u, employee generation=%u",
                (unsigned) MAX_EMPLOYEES, (unsigned) (log_region_size_ / sizeof(LogRecord)),
                (unsigned) LOG_HIGH_WATER_PERCENT, (unsigned) write_offset_, (unsigned) employee_generation_);
  ESP_LOGCONFIG(TAG, "DS3231 hardware RTC: %s",
                hardware_rtc_ != nullptr && !hardware_rtc_->is_failed() ? "connected" : "unavailable");
  ESP_LOGCONFIG(TAG, "Optional R307-S fingerprint reader: %s",
                fingerprint_ != nullptr && !fingerprint_->is_failed() ? "connected" : "not installed/offline");
  ESP_LOGCONFIG(TAG, "Daily note storage: %s, capacity=%u, generation=%u",
                notes_partition_ != nullptr ? "available" : "unavailable", (unsigned) MAX_DAILY_NOTES,
                (unsigned) note_generation_);
  ESP_LOGCONFIG(TAG, "Shared management password: %s",
                runtime_admin_password_loaded_ ? "runtime password from Flash" : "YAML factory password");
}

void AttendanceWebS3::load_admin_password_() {
  admin_password_pref_ = global_preferences->make_preference<AdminPasswordStore>(0xA771E024, true);
  runtime_admin_password_loaded_ = false;

  AdminPasswordStore store{};
  if (!admin_password_pref_.load(&store) || store.magic != ADMIN_PASSWORD_MAGIC ||
      store.version != ADMIN_PASSWORD_STORE_VERSION || store.length < 8 ||
      store.length > MAX_ADMIN_PASSWORD_BYTES || store.password[store.length] != '\0' ||
      store.crc != fnv1a(&store, offsetof(AdminPasswordStore, crc))) {
    admin_password_ = configured_admin_password_;
    ESP_LOGI(TAG, "Using the YAML factory management password");
    return;
  }

  std::string stored_password(store.password, store.length);
  if (!valid_new_admin_password(stored_password)) {
    std::fill(stored_password.begin(), stored_password.end(), '\0');
    admin_password_ = configured_admin_password_;
    ESP_LOGW(TAG, "Stored management password is invalid; using the YAML factory password");
    return;
  }
  admin_password_ = std::move(stored_password);
  runtime_admin_password_loaded_ = true;
  ESP_LOGI(TAG, "Loaded the runtime management password from Flash");
}

void AttendanceWebS3::load_mode_schedule_() {
  mode_schedule_pref_ = global_preferences->make_preference<ModeScheduleStore>(0xA771E025, true);
  ModeScheduleStore stored{};
  bool valid = mode_schedule_pref_.load(&stored) && stored.magic == MODE_SCHEDULE_MAGIC &&
               stored.version == MODE_SCHEDULE_STORE_VERSION && stored.master_enabled <= 1 &&
               stored.last_mode >= ACTION_CLOCK_OUT && stored.last_mode <= ACTION_OVERTIME_OUT &&
               stored.crc == fnv1a(&stored, offsetof(ModeScheduleStore, crc));
  for (uint8_t action = 0; valid && action < 4; action++)
    valid = stored.entry_enabled[action] <= 1 && stored.hour[action] < 24 && stored.minute[action] < 60;
  if (valid) {
    mode_schedule_ = stored;
    pending_action_ = stored.last_mode;
    ESP_LOGI(TAG, "Loaded automatic attendance-mode schedule from Flash");
    return;
  }

  mode_schedule_ = ModeScheduleStore{};
  mode_schedule_.magic = MODE_SCHEDULE_MAGIC;
  mode_schedule_.version = MODE_SCHEDULE_STORE_VERSION;
  mode_schedule_.master_enabled = 1;
  mode_schedule_.last_mode = ACTION_CLOCK_IN;
  mode_schedule_.entry_enabled[ACTION_CLOCK_IN] = 1;
  mode_schedule_.hour[ACTION_CLOCK_IN] = 0;
  mode_schedule_.minute[ACTION_CLOCK_IN] = 0;
  mode_schedule_.entry_enabled[ACTION_CLOCK_OUT] = 1;
  mode_schedule_.hour[ACTION_CLOCK_OUT] = 14;
  mode_schedule_.minute[ACTION_CLOCK_OUT] = 0;
  pending_action_ = ACTION_CLOCK_IN;
  if (!save_mode_schedule_())
    ESP_LOGW(TAG, "Unable to save the default attendance-mode schedule");
}

bool AttendanceWebS3::save_mode_schedule_() {
  mode_schedule_.magic = MODE_SCHEDULE_MAGIC;
  mode_schedule_.version = MODE_SCHEDULE_STORE_VERSION;
  mode_schedule_.crc = fnv1a(&mode_schedule_, offsetof(ModeScheduleStore, crc));
  return mode_schedule_pref_.save(&mode_schedule_);
}

bool AttendanceWebS3::verify_admin_password_(const std::string &password) const {
  return !admin_password_.empty() && secure_equals(password, admin_password_);
}

bool AttendanceWebS3::save_admin_password_(const std::string &password) {
  if (!valid_new_admin_password(password))
    return false;
  AdminPasswordStore store{};
  store.magic = ADMIN_PASSWORD_MAGIC;
  store.version = ADMIN_PASSWORD_STORE_VERSION;
  store.length = static_cast<uint16_t>(password.size());
  memcpy(store.password, password.data(), password.size());
  store.password[password.size()] = '\0';
  store.crc = fnv1a(&store, offsetof(AdminPasswordStore, crc));
  const bool saved = admin_password_pref_.save(&store);
  memset(store.password, 0, sizeof(store.password));
  return saved;
}

void AttendanceWebS3::apply_web_auth_password_() {
#ifdef USE_WEBSERVER_AUTH
  if (web_server_base::global_web_server_base != nullptr) {
    web_server_base::global_web_server_base->set_auth_password(admin_password_.c_str());
    return;
  }
#endif
  ESP_LOGE(TAG, "Web server authentication is unavailable; shared password could not be applied");
}

ESPTime AttendanceWebS3::effective_now_() const {
  if (manual_time_override_) {
    const uint32_t elapsed_seconds = (millis() - manual_time_millis_) / 1000U;
    return ESPTime::from_epoch_local(manual_time_base_ + elapsed_seconds);
  }
  if (rtc_ == nullptr)
    return ESPTime{};
  return rtc_->now();
}

static std::string format_timestamp_text(time_t timestamp) {
  if (timestamp <= 0)
    return "尚無紀錄";
  struct tm time_info {};
  localtime_r(&timestamp, &time_info);
  char output[24]{};
  if (strftime(output, sizeof(output), "%Y-%m-%d %H:%M:%S", &time_info) == 0)
    return "時間格式錯誤";
  return output;
}

std::string AttendanceWebS3::last_sync_time_text() const {
  return last_sync_timestamp_ > 0 ? format_timestamp_text(last_sync_timestamp_) : "本次開機尚未完成校時";
}

std::string AttendanceWebS3::time_source_text() const {
  if (manual_time_override_)
    return "管理員手動校時（優先）";
  if (network_time_synced_)
    return last_sync_source_;
  if (effective_now_().is_valid() && hardware_rtc_is_connected())
    return "DS3231 硬體時鐘";
  return "等待有效時間";
}

std::string AttendanceWebS3::last_card_info_text() const {
  const std::string time_text = last_card_timestamp_ > 0 ? format_timestamp_text(last_card_timestamp_) : "時間未同步";
  return time_text + "｜姓名：" + last_card_employee_ + "｜卡號：" + last_card_uid_ + "｜結果：" +
         last_card_result_;
}

std::string AttendanceWebS3::attendance_mode_text() const {
  if (pending_action_ < ACTION_CLOCK_OUT || pending_action_ > ACTION_OVERTIME_OUT)
    return "未設定";
  return action_label(static_cast<uint8_t>(pending_action_));
}

std::string AttendanceWebS3::display_mode_text() const {
  if (fingerprint_enroll_employee_ >= 0)
    return "登記指紋";
  if (enroll_employee_ >= 0)
    return "登記新卡";
  return attendance_mode_text();
}

void AttendanceWebS3::mark_network_time_synced(const std::string &source) {
  if (manual_time_override_)
    return;
  network_time_synced_ = true;
  last_sync_source_ = source.empty() ? "網路自動校時" : source;
  const ESPTime now = effective_now_();
  if (now.is_valid())
    last_sync_timestamp_ = now.timestamp;
}

void AttendanceWebS3::remember_card_result_(const std::string &uid, const std::string &employee,
                                          const std::string &result) {
  last_card_uid_ = uid.empty() ? "未知" : uid;
  last_card_employee_ = employee.empty() ? "未登記" : employee;
  last_card_result_ = result;
  const ESPTime now = effective_now_();
  last_card_timestamp_ = now.is_valid() ? now.timestamp : 0;
}

void AttendanceWebS3::update_scheduled_mode_() {
  const ESPTime now = effective_now_();
  if (!now.is_valid() || !mode_schedule_.master_enabled)
    return;
  const uint16_t current_minute = static_cast<uint16_t>(now.hour * 60U + now.minute);
  const uint32_t schedule_bucket =
      (static_cast<uint32_t>(now.year) * 1000U + now.day_of_year) * 1440U + current_minute;
  if (schedule_bucket == last_schedule_bucket_)
    return;
  const bool first_check = last_schedule_bucket_ == 0;
  last_schedule_bucket_ = schedule_bucket;

  int selected_action = -1;
  if (first_check) {
    uint16_t smallest_elapsed = 1441;
    for (uint8_t action = 0; action < 4; action++) {
      if (!mode_schedule_.entry_enabled[action])
        continue;
      const uint16_t scheduled_minute =
          static_cast<uint16_t>(mode_schedule_.hour[action] * 60U + mode_schedule_.minute[action]);
      const uint16_t elapsed = static_cast<uint16_t>((current_minute + 1440U - scheduled_minute) % 1440U);
      if (elapsed < smallest_elapsed) {
        smallest_elapsed = elapsed;
        selected_action = action;
      }
    }
  } else {
    for (uint8_t action = 0; action < 4; action++) {
      if (mode_schedule_.entry_enabled[action] && mode_schedule_.hour[action] == now.hour &&
          mode_schedule_.minute[action] == now.minute) {
        selected_action = action;
        break;
      }
    }
  }
  if (selected_action >= 0)
    select_action_code_(static_cast<uint8_t>(selected_action));
}

void AttendanceWebS3::loop() {
  const uint32_t now_millis = millis();
  process_door_relay_();
  process_tts_();
  if (import_reload_pending_) {
    // Potentially long Flash scans must run on loopTask, where watchdog
    // feeding is valid, never inside the HTTP server task.
    import_reload_pending_ = false;
    load_employees_();
    load_notes_();
    scan_flash_();
    ESP_LOGI(TAG, "Persistent data reloaded after backup import ended");
  }
  if (clear_logs_in_progress_ && !clear_logs_failed_ && clear_logs_erase_offset_ < log_region_size_ &&
      now_millis - last_clear_logs_erase_millis_ >= FLASH_ERASE_INTERVAL_MS) {
    const uint32_t sector_size = partition_ != nullptr ? partition_->erase_size : 0;
    feed_watchdog_if_registered();
    if (sector_size == 0 || clear_logs_erase_offset_ + sector_size > log_region_size_ ||
        esp_partition_erase_range(partition_, clear_logs_erase_offset_, sector_size) != ESP_OK) {
      clear_logs_failed_ = true;
      clear_logs_in_progress_ = false;
      last_result_ = "刪除刷卡紀錄失敗，請重新操作";
      ESP_LOGE(TAG, "Attendance log erase failed at offset %u", (unsigned) clear_logs_erase_offset_);
    } else {
      clear_logs_erase_offset_ += sector_size;
      if (clear_logs_erase_offset_ >= log_region_size_) {
        write_offset_ = 0;
        log_record_count_ = 0;
        log_sequence_ = 0;
        clear_logs_in_progress_ = false;
        last_result_ = "所有刷卡紀錄已刪除";
        ESP_LOGW(TAG, "All attendance logs were erased from flash");
      }
    }
    last_clear_logs_erase_millis_ = millis();
    feed_watchdog_if_registered();
    yield();
  }
  if (import_in_progress_ && !import_erase_failed_ && !import_storage_ready_() &&
      now_millis - last_import_erase_millis_ >= FLASH_ERASE_INTERVAL_MS) {
    const bool erasing_notes = import_note_erase_offset_ < NOTE_SLOT_SIZE;
    const esp_partition_t *target_partition = erasing_notes ? notes_partition_ : partition_;
    const uint32_t target_offset = erasing_notes
        ? note_slot_offset_(static_cast<uint8_t>(import_note_staging_slot_)) + import_note_erase_offset_
        : import_erase_offset_;
    const uint32_t target_size = erasing_notes ? NOTE_SLOT_SIZE : log_region_size_;
    const uint32_t completed = erasing_notes ? import_note_erase_offset_ : import_erase_offset_;
    const uint32_t sector_size = target_partition != nullptr ? target_partition->erase_size : 0;
    feed_watchdog_if_registered();
    if (sector_size == 0 || completed + sector_size > target_size ||
        esp_partition_erase_range(target_partition, target_offset, sector_size) != ESP_OK) {
      import_erase_failed_ = true;
      last_result_ = erasing_notes ? "準備備註還原區失敗，原備註仍保留" :
                                     "清除原刷卡紀錄區失敗，請重新開始還原";
      ESP_LOGE(TAG, "Backup import Flash erase failed in %s at offset %u",
               erasing_notes ? "note staging bank" : "attendance log",
               (unsigned) completed);
    } else {
      if (erasing_notes) {
        import_note_erase_offset_ += sector_size;
        if (import_note_erase_offset_ >= NOTE_SLOT_SIZE) {
          // The inactive bank is now an uncommitted staging area. Its header
          // stays erased until import-finish, so a reset still loads the old
          // valid note bank.
          note_active_slot_ = import_note_staging_slot_;
          note_generation_ = import_note_generation_;
          note_count_ = 0;
          note_journal_used_ = 0;
          import_note_staging_ready_ = true;
          ESP_LOGI(TAG, "Backup note staging bank %d prepared", import_note_staging_slot_);
        }
      } else {
        import_erase_offset_ += sector_size;
        if (import_erase_offset_ >= log_region_size_) {
          write_offset_ = 0;
          log_record_count_ = 0;
          log_sequence_ = 0;
        }
      }
      last_import_millis_ = millis();
    }
    last_import_erase_millis_ = millis();
    feed_watchdog_if_registered();
    yield();
  }
  // The erase step updates last_import_millis_ inside this same loop pass.
  // Read millis() again so an older snapshot cannot underflow and look like a 30-minute timeout.
  const uint32_t import_timeout_now = millis();
  if (import_in_progress_ && import_timeout_now - last_import_millis_ > 1800000U) {
    reset_import_session_(true);
    last_result_ = "資料還原逾時，請重新選擇備份檔匯入";
    ESP_LOGW(TAG, "Backup import session timed out");
  }
  if ((enroll_employee_ >= 0 || fingerprint_enroll_employee_ >= 0) &&
      now_millis - last_rainbow_millis_ >= 250U) {
    last_rainbow_millis_ = now_millis;
    update_enroll_rainbow_();
  }
  if (now_millis - last_time_check_millis_ < 1000U)
    return;
  last_time_check_millis_ = now_millis;
  update_scheduled_mode_();
  const ESPTime current_time = effective_now_();
  if (current_time.is_valid()) {
    const uint32_t current_date = static_cast<uint32_t>(current_time.year) * 10000U +
                                  static_cast<uint32_t>(current_time.month) * 100U + current_time.day_of_month;
    if (current_date != last_retention_cleanup_date_) {
      last_retention_cleanup_date_ = current_date;
      purge_expired_notes_();
    }
  }
}

void AttendanceWebS3::purge_expired_notes_() {
  if (notes_partition_ == nullptr)
    return;
  uint32_t cutoff_date = 0;
  const uint32_t cutoff = cutoff_timestamp_();
  if (cutoff == 0)
    return;
  time_t timestamp = cutoff;
  struct tm time_info {};
  localtime_r(&timestamp, &time_info);
  cutoff_date = static_cast<uint32_t>((time_info.tm_year + 1900) * 10000 +
                                      (time_info.tm_mon + 1) * 100 + time_info.tm_mday);
  size_t removed = 0;
  for (size_t index = 0; index < note_count_; index++) {
    DailyNote note{};
    if (read_note_(index, &note) && note.date < cutoff_date)
      removed++;
  }
  if (removed == 0)
    return;
  if (compact_notes_(cutoff_date))
    ESP_LOGI(TAG, "Automatically removed %u daily notes older than two calendar months", (unsigned) removed);
  else
    ESP_LOGE(TAG, "Unable to compact expired daily notes in Flash");
}

uint32_t AttendanceWebS3::employee_slot_offset_(uint8_t slot) const {
  return employee_storage_offset_ + static_cast<uint32_t>(slot) * EMPLOYEE_SLOT_SIZE;
}

uint32_t AttendanceWebS3::note_slot_offset_(uint8_t slot) const {
  return static_cast<uint32_t>(slot) * NOTE_SLOT_SIZE;
}

bool AttendanceWebS3::inspect_employee_slot_at_(uint32_t offset, EmployeeStoreHeader *header,
                                                bool *has_embedded_notes) {
  if (partition_ == nullptr || header == nullptr || has_embedded_notes == nullptr ||
      offset + EMPLOYEE_SLOT_SIZE > partition_->size)
    return false;
  if (esp_partition_read(partition_, offset, header, sizeof(*header)) != ESP_OK ||
      header->magic != EMPLOYEE_MAGIC)
    return false;
  if ((header->version == LEGACY_EMPLOYEE_STORE_VERSION || header->version == EMPLOYEE_STORE_VERSION) &&
      header->payload_size == sizeof(employees_)) {
    *has_embedded_notes = false;
  } else if (header->version == EMBEDDED_NOTE_EMPLOYEE_STORE_VERSION &&
             header->payload_size == sizeof(employees_) + sizeof(embedded_notes_)) {
    *has_embedded_notes = true;
  } else {
    return false;
  }
  bool crc_ok = false;
  return partition_crc_(partition_, offset + sizeof(*header), header->payload_size, &crc_ok) ==
             header->payload_crc &&
         crc_ok;
}

void AttendanceWebS3::load_employees_() {
  EmployeeStoreHeader header_zero{};
  EmployeeStoreHeader header_one{};
  bool embedded_zero = false;
  bool embedded_one = false;
  uint32_t base_offset = employee_storage_offset_;
  bool valid_zero = inspect_employee_slot_at_(base_offset, &header_zero, &embedded_zero);
  bool valid_one = inspect_employee_slot_at_(base_offset + EMPLOYEE_SLOT_SIZE, &header_one, &embedded_one);
  bool migrate_legacy_partition = false;
  if (!valid_zero && !valid_one && employee_storage_offset_ != LEGACY_EMPLOYEE_STORAGE_OFFSET &&
      LEGACY_EMPLOYEE_STORAGE_OFFSET + EMPLOYEE_SLOT_SIZE * EMPLOYEE_SLOT_COUNT <= partition_->size) {
    base_offset = LEGACY_EMPLOYEE_STORAGE_OFFSET;
    valid_zero = inspect_employee_slot_at_(base_offset, &header_zero, &embedded_zero);
    valid_one = inspect_employee_slot_at_(base_offset + EMPLOYEE_SLOT_SIZE, &header_one, &embedded_one);
    migrate_legacy_partition = valid_zero || valid_one;
  }
  if (valid_zero || valid_one) {
    const bool use_one = valid_one &&
                         (!valid_zero || static_cast<int32_t>(header_one.generation - header_zero.generation) > 0);
    const EmployeeStoreHeader &selected_header = use_one ? header_one : header_zero;
    const uint32_t selected_offset = base_offset + (use_one ? EMPLOYEE_SLOT_SIZE : 0);
    if (!read_partition_range_safely_(partition_, selected_offset + sizeof(EmployeeStoreHeader),
                                      employees_.data(), sizeof(employees_))) {
      ESP_LOGE(TAG, "Unable to read selected employee Flash slot");
      valid_zero = valid_one = false;
    } else if ((use_one ? embedded_one : embedded_zero) &&
               !read_partition_range_safely_(partition_, selected_offset + sizeof(EmployeeStoreHeader) +
                                                               sizeof(employees_),
                                             embedded_notes_.data(), sizeof(embedded_notes_))) {
      ESP_LOGE(TAG, "Unable to read legacy embedded daily notes");
      valid_zero = valid_one = false;
    } else {
      if (!(use_one ? embedded_one : embedded_zero))
        embedded_notes_.fill(DailyNote{});
    }
    if (!valid_zero && !valid_one)
      goto initialize_employee_storage;
    employee_generation_ = selected_header.generation;
    employee_active_slot_ = migrate_legacy_partition ? -1 : (use_one ? 1 : 0);
    for (size_t i = 0; i < MAX_EMPLOYEES; i++) {
      employees_[i].id = i + 1;
      employees_[i].code[sizeof(Employee::code) - 1] = '\0';
      employees_[i].name[sizeof(Employee::name) - 1] = '\0';
      employees_[i].uid[sizeof(Employee::uid) - 1] = '\0';
      employees_[i].voice_name[sizeof(Employee::voice_name) - 1] = '\0';
      employees_[i].can_open_door = employees_[i].can_open_door ? 1 : 0;
      employees_[i].finger1_enrolled = employees_[i].finger1_enrolled ? 1 : 0;
      employees_[i].finger2_enrolled = employees_[i].finger2_enrolled ? 1 : 0;
    }
    for (auto &note : embedded_notes_) {
      note.text[sizeof(note.text) - 1] = '\0';
      if (note.employee_id < 1 || note.employee_id > MAX_EMPLOYEES || note.date < 20200101U ||
          note.date > 21001231U)
        note.active = 0;
    }
    embedded_notes_available_ = use_one ? embedded_one : embedded_zero;
    if (migrate_legacy_partition) {
      if (save_employees_())
        ESP_LOGI(TAG, "Migrated employee data to the expanded attendance partition");
      else
        ESP_LOGE(TAG, "Unable to migrate employee data to the expanded attendance partition");
    } else {
      ESP_LOGI(TAG, "Loaded employee data from Flash slot %d, generation=%u%s", employee_active_slot_,
               (unsigned) employee_generation_, embedded_notes_available_ ? " (contains legacy notes)" : "");
    }
    return;
  }

  // Migrate the v1.3.7 NVS blob if it was successfully committed before this upgrade.
initialize_employee_storage:
  employees_.fill(Employee{});
  embedded_notes_.fill(DailyNote{});
  embedded_notes_available_ = false;
  auto legacy_pref = global_preferences->make_preference<std::array<Employee, MAX_EMPLOYEES>>(0xA771E003, true);
  const bool migrated = legacy_pref.load(&employees_);
  for (size_t i=0; i<MAX_EMPLOYEES; i++)
    employees_[i].id=i+1;
  if (!save_employees_())
    ESP_LOGE(TAG, "Unable to initialize persistent employee storage");
  else if (migrated)
    ESP_LOGI(TAG, "Migrated employee data from v1.3.7 NVS storage");
}

bool AttendanceWebS3::erase_partition_range_safely_(const esp_partition_t *partition, uint32_t offset,
                                                    uint32_t size) {
  if (partition == nullptr || partition->erase_size == 0 || size == 0 ||
      offset % partition->erase_size != 0 || size % partition->erase_size != 0 ||
      offset + size > partition->size)
    return false;
  for (uint32_t erased = 0; erased < size; erased += partition->erase_size) {
    feed_watchdog_if_registered();
    if (esp_partition_erase_range(partition, offset + erased, partition->erase_size) != ESP_OK)
      return false;
    feed_watchdog_if_registered();
    yield();
  }
  return true;
}

bool AttendanceWebS3::write_partition_range_safely_(const esp_partition_t *partition, uint32_t offset,
                                                    const void *data, size_t size) {
  if (partition == nullptr || data == nullptr || size == 0 || offset + size > partition->size)
    return false;
  const auto *bytes = static_cast<const uint8_t *>(data);
  constexpr size_t WRITE_CHUNK_SIZE = 4096;
  for (size_t written = 0; written < size; written += WRITE_CHUNK_SIZE) {
    const size_t chunk_size = std::min<size_t>(WRITE_CHUNK_SIZE, size - written);
    memcpy(log_scan_buffer_.data(), bytes + written, chunk_size);
    feed_watchdog_if_registered();
    if (esp_partition_write(partition, offset + written, log_scan_buffer_.data(), chunk_size) != ESP_OK)
      return false;
    feed_watchdog_if_registered();
    yield();
  }
  return true;
}

bool AttendanceWebS3::read_partition_range_safely_(const esp_partition_t *partition, uint32_t offset,
                                                   void *data, size_t size) {
  if (partition == nullptr || data == nullptr || size == 0 || offset + size > partition->size)
    return false;
  auto *bytes = static_cast<uint8_t *>(data);
  constexpr size_t READ_CHUNK_SIZE = 4096;
  for (size_t read = 0; read < size; read += READ_CHUNK_SIZE) {
    const size_t chunk_size = std::min<size_t>(READ_CHUNK_SIZE, size - read);
    feed_watchdog_if_registered();
    if (esp_partition_read(partition, offset + read, log_scan_buffer_.data(), chunk_size) != ESP_OK)
      return false;
    memcpy(bytes + read, log_scan_buffer_.data(), chunk_size);
    feed_watchdog_if_registered();
    yield();
  }
  return true;
}

bool AttendanceWebS3::verify_partition_range_safely_(const esp_partition_t *partition, uint32_t offset,
                                                     const void *data, size_t size) {
  if (partition == nullptr || data == nullptr || size == 0 || offset + size > partition->size)
    return false;
  const auto *expected = static_cast<const uint8_t *>(data);
  constexpr size_t VERIFY_CHUNK_SIZE = 4096;
  for (size_t verified = 0; verified < size; verified += VERIFY_CHUNK_SIZE) {
    const size_t chunk_size = std::min<size_t>(VERIFY_CHUNK_SIZE, size - verified);
    feed_watchdog_if_registered();
    if (esp_partition_read(partition, offset + verified, log_scan_buffer_.data(), chunk_size) != ESP_OK ||
        memcmp(log_scan_buffer_.data(), expected + verified, chunk_size) != 0)
      return false;
    feed_watchdog_if_registered();
    yield();
  }
  return true;
}

bool AttendanceWebS3::save_employees_() {
  if (partition_ == nullptr)
    return false;
  const uint8_t next_slot = employee_active_slot_ == 0 ? 1 : 0;
  const uint32_t offset = employee_slot_offset_(next_slot);
  if (!erase_partition_range_safely_(partition_, offset, EMPLOYEE_SLOT_SIZE)) {
    ESP_LOGE(TAG, "Failed to erase employee Flash slot %u", (unsigned) next_slot);
    return false;
  }
  feed_watchdog_if_registered();
  yield();
  if (!write_partition_range_safely_(partition_, offset + sizeof(EmployeeStoreHeader), employees_.data(),
                                     sizeof(employees_))) {
    ESP_LOGE(TAG, "Failed to write employee payload to Flash slot %u", (unsigned) next_slot);
    return false;
  }
  feed_watchdog_if_registered();
  yield();
  EmployeeStoreHeader header{};
  header.magic = EMPLOYEE_MAGIC;
  header.version = EMPLOYEE_STORE_VERSION;
  header.generation = employee_generation_ + 1;
  header.payload_size = sizeof(employees_);
  header.payload_crc = fnv1a(employees_.data(), sizeof(employees_));
  // Header is written last. A power loss during payload writing leaves this slot invalid,
  // so the previous generation remains available on the next boot.
  if (esp_partition_write(partition_, offset, &header, sizeof(header)) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to commit employee Flash slot %u", (unsigned) next_slot);
    return false;
  }
  EmployeeStoreHeader verify_header{};
  if (esp_partition_read(partition_, offset, &verify_header, sizeof(verify_header)) != ESP_OK ||
      memcmp(&verify_header, &header, sizeof(header)) != 0 ||
      !verify_partition_range_safely_(partition_, offset + sizeof(EmployeeStoreHeader), employees_.data(),
                                      sizeof(employees_))) {
    ESP_LOGE(TAG, "Employee Flash verification failed for slot %u", (unsigned) next_slot);
    return false;
  }
  employee_active_slot_ = next_slot;
  employee_generation_ = header.generation;
  ESP_LOGI(TAG, "Employee data committed to Flash slot %u, generation=%u", (unsigned) next_slot,
           (unsigned) employee_generation_);
  return true;
}

uint32_t AttendanceWebS3::partition_crc_(const esp_partition_t *partition, uint32_t offset, size_t size,
                                         bool *ok) {
  uint32_t hash = 2166136261U;
  if (ok != nullptr)
    *ok = false;
  if (partition == nullptr || offset + size > partition->size)
    return hash;
  for (size_t read = 0; read < size; read += log_scan_buffer_.size()) {
    const size_t chunk = std::min<size_t>(log_scan_buffer_.size(), size - read);
    feed_watchdog_if_registered();
    if (esp_partition_read(partition, offset + read, log_scan_buffer_.data(), chunk) != ESP_OK)
      return hash;
    hash = fnv1a_update(hash, log_scan_buffer_.data(), chunk);
    yield();
  }
  if (ok != nullptr)
    *ok = true;
  return hash;
}

bool AttendanceWebS3::validate_note_bank_header_(uint8_t bank, uint32_t *generation) const {
  if (notes_partition_ == nullptr || bank >= NOTE_SLOT_COUNT || generation == nullptr)
    return false;
  EmployeeStoreHeader header{};
  if (esp_partition_read(notes_partition_, note_slot_offset_(bank), &header, sizeof(header)) != ESP_OK ||
      header.magic != NOTE_MAGIC || header.version != NOTE_STORE_VERSION ||
      header.payload_size != sizeof(NoteJournalRecord) ||
      header.payload_crc != fnv1a(&header, offsetof(EmployeeStoreHeader, payload_crc)))
    return false;
  *generation = header.generation;
  return true;
}

int AttendanceWebS3::find_note_index_(uint16_t employee_id, uint32_t date) const {
  for (size_t index = 0; index < note_count_; index++)
    if (note_index_[index].employee_id == employee_id && note_index_[index].date == date)
      return static_cast<int>(index);
  return -1;
}

bool AttendanceWebS3::read_note_(size_t index, DailyNote *note) const {
  if (notes_partition_ == nullptr || note == nullptr || note_active_slot_ < 0 || index >= note_count_)
    return false;
  const NoteIndexEntry &entry = note_index_[index];
  if (entry.record_index >= NOTE_JOURNAL_RECORD_CAPACITY)
    return false;
  NoteJournalRecord record{};
  const uint32_t offset = note_slot_offset_(static_cast<uint8_t>(note_active_slot_)) + NOTE_BANK_DATA_OFFSET +
                          static_cast<uint32_t>(entry.record_index) * sizeof(record);
  if (esp_partition_read(notes_partition_, offset, &record, sizeof(record)) != ESP_OK ||
      record.magic != NOTE_RECORD_MAGIC || record.crc != fnv1a(&record, offsetof(NoteJournalRecord, crc)) ||
      !record.active)
    return false;
  *note = DailyNote{};
  note->date = record.date;
  note->employee_id = record.employee_id;
  note->active = 1;
  strlcpy(note->text, record.text, sizeof(note->text));
  return true;
}

bool AttendanceWebS3::activate_note_bank_(uint8_t bank) {
  uint32_t generation = 0;
  if (!validate_note_bank_header_(bank, &generation))
    return false;
  note_active_slot_ = static_cast<int8_t>(bank);
  note_generation_ = generation;
  note_count_ = 0;
  note_journal_used_ = 0;
  bool damaged_tail = false;
  for (uint16_t record_index = 0; record_index < NOTE_JOURNAL_RECORD_CAPACITY; record_index++) {
    NoteJournalRecord record{};
    const uint32_t offset = note_slot_offset_(bank) + NOTE_BANK_DATA_OFFSET +
                            static_cast<uint32_t>(record_index) * sizeof(record);
    if (esp_partition_read(notes_partition_, offset, &record, sizeof(record)) != ESP_OK)
      return false;
    if (record.magic == UINT32_MAX)
      break;
    note_journal_used_ = record_index + 1;
    if (record.magic != NOTE_RECORD_MAGIC || record.crc != fnv1a(&record, offsetof(NoteJournalRecord, crc))) {
      damaged_tail = true;
      break;
    }
    if (record.employee_id < 1 || record.employee_id > MAX_EMPLOYEES || record.date < 20200101U ||
        record.date > 21001231U)
      continue;
    const int existing = find_note_index_(record.employee_id, record.date);
    if (record.active && record.text[0] != '\0') {
      const NoteIndexEntry entry{record.date, record.employee_id, record_index};
      if (existing >= 0)
        note_index_[existing] = entry;
      else if (note_count_ < MAX_DAILY_NOTES)
        note_index_[note_count_++] = entry;
    } else if (existing >= 0) {
      for (size_t index = static_cast<size_t>(existing) + 1; index < note_count_; index++)
        note_index_[index - 1] = note_index_[index];
      note_count_--;
    }
    if ((record_index & 0x7FU) == 0) {
      feed_watchdog_if_registered();
      yield();
    }
  }
  ESP_LOGI(TAG, "Loaded %u active daily notes from Flash journal bank %u (%u records used)",
           (unsigned) note_count_, (unsigned) bank, (unsigned) note_journal_used_);
  if (damaged_tail) {
    ESP_LOGW(TAG, "Daily note journal has an incomplete tail; compacting safely");
    return compact_notes_();
  }
  return true;
}

bool AttendanceWebS3::reset_note_journal_() {
  if (notes_partition_ == nullptr)
    return false;
  const uint8_t target = note_active_slot_ == 0 ? 1 : 0;
  if (!erase_partition_range_safely_(notes_partition_, note_slot_offset_(target), NOTE_SLOT_SIZE))
    return false;
  EmployeeStoreHeader header{};
  header.magic = NOTE_MAGIC;
  header.version = NOTE_STORE_VERSION;
  header.generation = note_generation_ + 1;
  header.payload_size = sizeof(NoteJournalRecord);
  header.payload_crc = fnv1a(&header, offsetof(EmployeeStoreHeader, payload_crc));
  if (esp_partition_write(notes_partition_, note_slot_offset_(target), &header, sizeof(header)) != ESP_OK)
    return false;
  note_active_slot_ = static_cast<int8_t>(target);
  note_generation_ = header.generation;
  note_count_ = 0;
  note_journal_used_ = 0;
  return true;
}

bool AttendanceWebS3::compact_notes_(uint32_t cutoff_date) {
  if (notes_partition_ == nullptr || note_active_slot_ < 0)
    return false;
  const uint8_t old_bank = static_cast<uint8_t>(note_active_slot_);
  const uint8_t target = old_bank == 0 ? 1 : 0;
  const uint16_t original_count = note_count_;
  if (!erase_partition_range_safely_(notes_partition_, note_slot_offset_(target), NOTE_SLOT_SIZE))
    return false;
  uint16_t copied = 0;
  for (uint16_t index = 0; index < original_count; index++) {
    DailyNote note{};
    if (!read_note_(index, &note)) {
      activate_note_bank_(old_bank);
      return false;
    }
    if (cutoff_date != 0 && note.date < cutoff_date)
      continue;
    NoteJournalRecord record{};
    record.date = note.date;
    record.employee_id = note.employee_id;
    record.active = 1;
    strlcpy(record.text, note.text, sizeof(record.text));
    record.crc = fnv1a(&record, offsetof(NoteJournalRecord, crc));
    const uint32_t offset = note_slot_offset_(target) + NOTE_BANK_DATA_OFFSET +
                            static_cast<uint32_t>(copied) * sizeof(record);
    if (esp_partition_write(notes_partition_, offset, &record, sizeof(record)) != ESP_OK) {
      activate_note_bank_(old_bank);
      return false;
    }
    note_index_[copied] = NoteIndexEntry{note.date, note.employee_id, copied};
    copied++;
    if ((copied & 0x3FU) == 0) {
      feed_watchdog_if_registered();
      yield();
    }
  }
  EmployeeStoreHeader header{};
  header.magic = NOTE_MAGIC;
  header.version = NOTE_STORE_VERSION;
  header.generation = note_generation_ + 1;
  header.payload_size = sizeof(NoteJournalRecord);
  header.payload_crc = fnv1a(&header, offsetof(EmployeeStoreHeader, payload_crc));
  if (esp_partition_write(notes_partition_, note_slot_offset_(target), &header, sizeof(header)) != ESP_OK) {
    activate_note_bank_(old_bank);
    return false;
  }
  note_active_slot_ = static_cast<int8_t>(target);
  note_generation_ = header.generation;
  note_count_ = copied;
  note_journal_used_ = copied;
  ESP_LOGI(TAG, "Compacted daily note journal to bank %u: %u active notes", (unsigned) target,
           (unsigned) copied);
  return true;
}

bool AttendanceWebS3::append_note_change_(const DailyNote &note) {
  if (notes_partition_ == nullptr || note_active_slot_ < 0 || note.employee_id < 1 ||
      note.employee_id > MAX_EMPLOYEES || note.date < 20200101U || note.date > 21001231U)
    return false;
  if (note_journal_used_ >= NOTE_JOURNAL_RECORD_CAPACITY && !compact_notes_())
    return false;
  if (note_journal_used_ >= NOTE_JOURNAL_RECORD_CAPACITY)
    return false;
  const int existing = find_note_index_(note.employee_id, note.date);
  if (note.active && existing < 0 && note_count_ >= MAX_DAILY_NOTES)
    return false;
  NoteJournalRecord record{};
  record.date = note.date;
  record.employee_id = note.employee_id;
  record.active = note.active ? 1 : 0;
  if (record.active)
    strlcpy(record.text, note.text, sizeof(record.text));
  record.crc = fnv1a(&record, offsetof(NoteJournalRecord, crc));
  const uint16_t record_index = note_journal_used_;
  const uint32_t offset = note_slot_offset_(static_cast<uint8_t>(note_active_slot_)) + NOTE_BANK_DATA_OFFSET +
                          static_cast<uint32_t>(record_index) * sizeof(record);
  if (esp_partition_write(notes_partition_, offset, &record, sizeof(record)) != ESP_OK)
    return false;
  note_journal_used_++;
  if (record.active) {
    const NoteIndexEntry entry{record.date, record.employee_id, record_index};
    if (existing >= 0)
      note_index_[existing] = entry;
    else
      note_index_[note_count_++] = entry;
  } else if (existing >= 0) {
    for (size_t index = static_cast<size_t>(existing) + 1; index < note_count_; index++)
      note_index_[index - 1] = note_index_[index];
    note_count_--;
  }
  return true;
}

bool AttendanceWebS3::migrate_flat_note_slot_(const esp_partition_t *source_partition, uint32_t slot_offset,
                                              uint16_t expected_version, size_t record_count,
                                              uint32_t generation, uint8_t target_bank) {
  if (source_partition == nullptr || notes_partition_ == nullptr || target_bank >= NOTE_SLOT_COUNT ||
      record_count > 10000)
    return false;
  EmployeeStoreHeader source_header{};
  if (esp_partition_read(source_partition, slot_offset, &source_header, sizeof(source_header)) != ESP_OK ||
      source_header.magic != NOTE_MAGIC || source_header.version != expected_version ||
      source_header.payload_size != record_count * sizeof(DailyNote))
    return false;
  bool crc_ok = false;
  const uint32_t crc = partition_crc_(source_partition, slot_offset + sizeof(source_header),
                                      source_header.payload_size, &crc_ok);
  if (!crc_ok || crc != source_header.payload_crc)
    return false;
  if (!erase_partition_range_safely_(notes_partition_, note_slot_offset_(target_bank), NOTE_SLOT_SIZE))
    return false;
  note_count_ = 0;
  note_journal_used_ = 0;
  for (size_t index = 0; index < record_count; index++) {
    DailyNote note{};
    if (esp_partition_read(source_partition, slot_offset + sizeof(source_header) + index * sizeof(note),
                           &note, sizeof(note)) != ESP_OK)
      return false;
    note.text[sizeof(note.text) - 1] = '\0';
    if (!note.active || note.text[0] == '\0' || note.employee_id < 1 || note.employee_id > MAX_EMPLOYEES ||
        note.date < 20200101U || note.date > 21001231U)
      continue;
    if (note_count_ >= MAX_DAILY_NOTES)
      break;
    NoteJournalRecord record{};
    record.date = note.date;
    record.employee_id = note.employee_id;
    record.active = 1;
    strlcpy(record.text, note.text, sizeof(record.text));
    record.crc = fnv1a(&record, offsetof(NoteJournalRecord, crc));
    const uint32_t target_offset = note_slot_offset_(target_bank) + NOTE_BANK_DATA_OFFSET +
                                   static_cast<uint32_t>(note_journal_used_) * sizeof(record);
    if (esp_partition_write(notes_partition_, target_offset, &record, sizeof(record)) != ESP_OK)
      return false;
    note_index_[note_count_] = NoteIndexEntry{note.date, note.employee_id, note_journal_used_};
    note_count_++;
    note_journal_used_++;
  }
  EmployeeStoreHeader header{};
  header.magic = NOTE_MAGIC;
  header.version = NOTE_STORE_VERSION;
  header.generation = generation + 1;
  header.payload_size = sizeof(NoteJournalRecord);
  header.payload_crc = fnv1a(&header, offsetof(EmployeeStoreHeader, payload_crc));
  if (esp_partition_write(notes_partition_, note_slot_offset_(target_bank), &header, sizeof(header)) != ESP_OK)
    return false;
  note_active_slot_ = static_cast<int8_t>(target_bank);
  note_generation_ = header.generation;
  ESP_LOGI(TAG, "Migrated %u daily notes into Flash journal bank %u", (unsigned) note_count_,
           (unsigned) target_bank);
  return true;
}

void AttendanceWebS3::load_notes_() {
  uint32_t generation_zero = 0;
  uint32_t generation_one = 0;
  const bool valid_zero = validate_note_bank_header_(0, &generation_zero);
  const bool valid_one = validate_note_bank_header_(1, &generation_one);
  if (valid_zero || valid_one) {
    const uint8_t selected = valid_one && (!valid_zero || static_cast<int32_t>(generation_one - generation_zero) > 0)
                                 ? 1
                                 : 0;
    if (!activate_note_bank_(selected))
      ESP_LOGE(TAG, "Unable to activate daily note Flash journal");
    return;
  }

  struct FlatCandidate {
    bool valid{false};
    uint8_t slot{0};
    uint32_t generation{0};
    size_t count{0};
  } selected;
  for (uint8_t slot = 0; slot < NOTE_SLOT_COUNT; slot++) {
    EmployeeStoreHeader header{};
    const uint32_t offset = note_slot_offset_(slot);
    if (esp_partition_read(notes_partition_, offset, &header, sizeof(header)) != ESP_OK ||
        header.magic != NOTE_MAGIC || header.version != 2 || header.payload_size % sizeof(DailyNote) != 0)
      continue;
    const size_t count = header.payload_size / sizeof(DailyNote);
    if (count == 0 || count > 10000)
      continue;
    bool crc_ok = false;
    if (partition_crc_(notes_partition_, offset + sizeof(header), header.payload_size, &crc_ok) !=
            header.payload_crc ||
        !crc_ok)
      continue;
    if (!selected.valid || static_cast<int32_t>(header.generation - selected.generation) > 0)
      selected = FlatCandidate{true, slot, header.generation, count};
  }
  if (selected.valid) {
    const uint8_t target = selected.slot == 0 ? 1 : 0;
    if (migrate_flat_note_slot_(notes_partition_, note_slot_offset_(selected.slot), 2, selected.count,
                                selected.generation, target))
      return;
  }

  if (!reset_note_journal_()) {
    ESP_LOGE(TAG, "Unable to initialize daily note Flash journal");
    notes_partition_ = nullptr;
    return;
  }
  size_t migrated = 0;
  if (embedded_notes_available_) {
    for (const auto &note : embedded_notes_) {
      if (note.active && note.text[0] != '\0' && append_note_change_(note))
        migrated++;
    }
  }
  if (migrated > 0)
    ESP_LOGI(TAG, "Migrated %u embedded daily notes into Flash journal", (unsigned) migrated);
}

void AttendanceWebS3::scan_flash_() {
  const uint32_t started_at = millis();
  uint32_t newest=0, newest_off=0, newest_sequence=0, valid_count=0;
  bool any=false, any_sequence=false;
  const uint32_t cutoff = cutoff_timestamp_();
  for (uint32_t block_offset = 0; block_offset < log_region_size_; block_offset += LOG_SCAN_BLOCK_SIZE) {
    const uint32_t bytes_to_read =
        std::min<uint32_t>(LOG_SCAN_BLOCK_SIZE, log_region_size_ - block_offset);
    if (esp_partition_read(partition_, block_offset, log_scan_buffer_.data(), bytes_to_read) != ESP_OK) {
      ESP_LOGE(TAG, "Unable to read attendance log block at offset %u", (unsigned) block_offset);
      break;
    }
    const uint32_t record_count = bytes_to_read / sizeof(LogRecord);
    for (uint32_t index = 0; index < record_count; index++) {
      LogRecord record{};
      memcpy(&record, log_scan_buffer_.data() + index * sizeof(LogRecord), sizeof(record));
      if (record.magic==LOG_MAGIC && record.crc==fnv1a(&record, sizeof(record)-4) &&
          (cutoff == 0 || record.timestamp >= cutoff)) {
        valid_count++;
        const uint32_t sequence = log_sequence(record);
        if (sequence != 0 && (!any_sequence || static_cast<int32_t>(sequence - newest_sequence) > 0)) {
          newest_sequence = sequence;
          newest_off = block_offset + index * sizeof(LogRecord);
          any_sequence = true;
          any = true;
        } else if (!any_sequence && record.timestamp>=newest) {
          newest=record.timestamp;
          newest_off=block_offset + index * sizeof(LogRecord);
          any=true;
        }
      }
    }
    feed_watchdog_if_registered();
    yield();
  }
  write_offset_ = any ? newest_off + sizeof(LogRecord) : 0;
  if (write_offset_ + sizeof(LogRecord) > log_region_size_) write_offset_=0;
  log_sequence_ = any_sequence ? newest_sequence : 0;
  log_record_count_ = std::min<uint32_t>(valid_count, log_region_size_ / sizeof(LogRecord));
  ESP_LOGI(TAG, "Attendance Flash scan finished in %u ms; records=%u, next offset=%u",
           (unsigned) (millis() - started_at), (unsigned) log_record_count_, (unsigned) write_offset_);
}

void AttendanceWebS3::show_enroll_color_() {
  rainbow_index_ = 0;
  last_rainbow_millis_ = millis();
  update_enroll_rainbow_();
}

void AttendanceWebS3::update_enroll_rainbow_() {
  if (status_light_ == nullptr)
    return;
  // One WS2812 cannot show seven colours simultaneously, so cycle through
  // red, orange, yellow, green, cyan, blue and purple while waiting for a card.
  static constexpr float RAINBOW[7][3] = {
      {1.0f, 0.0f, 0.0f}, {1.0f, 0.45f, 0.0f}, {1.0f, 0.65f, 0.0f},
      {0.0f, 1.0f, 0.0f}, {0.0f, 1.0f, 1.0f},  {0.0f, 0.0f, 1.0f},
      {0.65f, 0.0f, 1.0f},
  };
  const auto &colour = RAINBOW[rainbow_index_];
  auto call = status_light_->turn_on();
  call.set_rgb(colour[0], colour[1], colour[2]);
  call.set_brightness(STATUS_LIGHT_BRIGHTNESS);
  call.set_transition_length(180);
  call.perform();
  rainbow_index_ = (rainbow_index_ + 1U) % 7U;
}

void AttendanceWebS3::restore_mode_color_() {
  if (status_light_ == nullptr)
    return;
  if (pending_action_ < 0) {
    auto call = status_light_->turn_off();
    call.set_transition_length(0);
    call.perform();
    return;
  }
  auto call = status_light_->turn_on();
  switch (pending_action_) {
    case ACTION_CLOCK_IN:
      call.set_rgb(0.0f, 1.0f, 0.0f);  // Green
      break;
    case ACTION_CLOCK_OUT:
      call.set_rgb(1.0f, 0.0f, 0.0f);  // Red
      break;
    case ACTION_OVERTIME_IN:
      // The WS2812 green channel appears brighter than red. Reducing green
      // produces a warmer, more saturated yellow instead of yellow-green.
      call.set_rgb(1.0f, 0.65f, 0.0f);  // Warm yellow
      break;
    case ACTION_OVERTIME_OUT:
      call.set_rgb(0.0f, 0.0f, 1.0f);  // Blue
      break;
    default:
      call.set_rgb(0.0f, 0.0f, 0.0f);
      break;
  }
  call.set_brightness(STATUS_LIGHT_BRIGHTNESS);
  call.set_transition_length(0);
  call.perform();
}

void AttendanceWebS3::refresh_status_light() {
  if (enroll_employee_ >= 0 || fingerprint_enroll_employee_ >= 0)
    show_enroll_color_();
  else
    restore_mode_color_();
}

void AttendanceWebS3::restart_network_time_sync() {
  if (!network_is_connected()) {
    ESP_LOGW(TAG, "SNTP immediate sync skipped because Wi-Fi is offline");
    return;
  }
  if (!esp_sntp_enabled()) {
    ESP_LOGW(TAG, "SNTP immediate sync skipped because the SNTP service is not initialized");
    return;
  }
  esp_sntp_restart();
  ESP_LOGI(TAG, "SNTP synchronization restarted immediately");
}

void AttendanceWebS3::select_action(bool in) {
  select_action_code_(in ? ACTION_CLOCK_IN : ACTION_CLOCK_OUT);
}

void AttendanceWebS3::select_overtime_action(bool in) {
  select_action_code_(in ? ACTION_OVERTIME_IN : ACTION_OVERTIME_OUT);
}

void AttendanceWebS3::cycle_attendance_mode() {
  uint8_t next = ACTION_CLOCK_IN;
  switch (pending_action_) {
    case ACTION_CLOCK_IN: next = ACTION_CLOCK_OUT; break;
    case ACTION_CLOCK_OUT: next = ACTION_OVERTIME_IN; break;
    case ACTION_OVERTIME_IN: next = ACTION_OVERTIME_OUT; break;
    default: next = ACTION_CLOCK_IN; break;
  }
  select_action_code_(next);
}

std::string AttendanceWebS3::display_time_text() const {
  const ESPTime now = effective_now_();
  if (!now.is_valid())
    return "--:--:--";
  char value[12];
  snprintf(value, sizeof(value), "%02u:%02u:%02u", now.hour, now.minute, now.second);
  return value;
}

void AttendanceWebS3::trigger_remote_unlock() {
  unlock_door_("Home Assistant");
}

void AttendanceWebS3::select_action_code_(uint8_t action) {
  if (action > ACTION_OVERTIME_OUT)
    return;
  pending_action_ = static_cast<int8_t>(action);
  if (mode_schedule_.last_mode != static_cast<int8_t>(action)) {
    mode_schedule_.last_mode = static_cast<int8_t>(action);
    if (!save_mode_schedule_())
      ESP_LOGW(TAG, "Unable to persist the current attendance mode");
  }
  last_result_ = std::string("目前模式：") + action_label(action);
  if (enroll_employee_ < 0)
    restore_mode_color_();
}

void AttendanceWebS3::unlock_door_(const char *source) {
  if (door_relay_ == nullptr)
    return;
  door_relay_->turn_on();
  door_relay_active_ = true;
  door_relay_off_millis_ = millis() + 1000U;
  ESP_LOGI(TAG, "Door relay activated for one second by %s", source == nullptr ? "unknown" : source);
}

void AttendanceWebS3::process_door_relay_() {
  if (!door_relay_active_ || door_relay_ == nullptr)
    return;
  if (static_cast<int32_t>(millis() - door_relay_off_millis_) >= 0) {
    door_relay_->turn_off();
    door_relay_active_ = false;
  }
}

void AttendanceWebS3::send_tts_frame_(const std::vector<uint8_t> &payload) {
  if (tts_uart_ == nullptr || payload.empty())
    return;
  const uint16_t length = static_cast<uint16_t>(payload.size() + 2U);
  const uint8_t header[] = {0xFD, static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 0xFF), 0x01, 0x01};
  tts_uart_->write_array(header, sizeof(header));
  tts_uart_->write_array(payload.data(), payload.size());
  tts_uart_->flush();
}

void AttendanceWebS3::queue_tts_phrase_(const Employee *employee, uint8_t phrase) {
  // Read employee-number digits one by one, preserving leading zeroes.
  static const uint8_t DIGIT_GB2312[10][2] = {
      {0xC1, 0xE3},  // 零
      {0xD2, 0xBB},  // 一
      {0xB6, 0xFE},  // 二
      {0xC8, 0xFD},  // 三
      {0xCB, 0xC4},  // 四
      {0xCE, 0xE5},  // 五
      {0xC1, 0xF9},  // 六
      {0xC6, 0xDF},  // 七
      {0xB0, 0xCB},  // 八
      {0xBE, 0xC5},  // 九
  };
  static const uint8_t PHRASE_CLOCK_IN[] = {0xC9,0xCF,0xB0,0xE0,0xB4,0xF2,0xBF,0xA8,0xB3,0xC9,0xB9,0xA6};
  static const uint8_t PHRASE_CLOCK_OUT[] = {0xCF,0xC2,0xB0,0xE0,0xB4,0xF2,0xBF,0xA8,0xB3,0xC9,0xB9,0xA6};
  static const uint8_t PHRASE_OT_IN[] = {0xBC,0xD3,0xB0,0xE0,0xC9,0xCF,0xB0,0xE0,0xB4,0xF2,0xBF,0xA8,0xB3,0xC9,0xB9,0xA6};
  static const uint8_t PHRASE_OT_OUT[] = {0xBC,0xD3,0xB0,0xE0,0xCF,0xC2,0xB0,0xE0,0xB4,0xF2,0xBF,0xA8,0xB3,0xC9,0xB9,0xA6};
  static const uint8_t PHRASE_CARD_UNKNOWN[] = {0xCE,0xB4,0xB5,0xC7,0xBC,0xC7,0xBF,0xA8,0xC6,0xAC};
  static const uint8_t PHRASE_FINGER_UNKNOWN[] = {0xD6,0xB8,0xCE,0xC6,0xCE,0xB4,0xB5,0xC7,0xBC,0xC7};
  static const uint8_t PHRASE_FAILED[] = {0xB4,0xF2,0xBF,0xA8,0xCA,0xA7,0xB0,0xDC};
  static const uint8_t PHRASE_RESCAN[] = {0xC7,0xEB,0xD4,0xD9,0xB4,0xCE,0xB0,0xB4,0xD1,0xB9,0xD6,0xB8,0xCE,0xC6};
  static const uint8_t PHRASE_ENROLL_DONE[] = {0xD6,0xB8,0xCE,0xC6,0xB5,0xC7,0xBC,0xC7,0xCD,0xEA,0xB3,0xC9};
  static const uint8_t PHRASE_CARD_ENROLL_PROMPT[] = {0xC7,0xEB,0xBD,0xAB,0xD0,0xC2,0xBF,0xA8,0xBF,0xBF,0xBD,0xFC,0xB8,0xD0,0xD3,0xA6,0xC7,0xF8};
  static const uint8_t PHRASE_CARD_ENROLL_DONE[] = {0xBF,0xA8,0xC6,0xAC,0xD2,0xD1,0xB5,0xC7,0xBC,0xC7};
  const uint8_t *data = nullptr;
  size_t data_size = 0;
  switch (phrase) {
    case 0: data = PHRASE_CLOCK_IN; data_size = sizeof(PHRASE_CLOCK_IN); break;
    case 1: data = PHRASE_CLOCK_OUT; data_size = sizeof(PHRASE_CLOCK_OUT); break;
    case 2: data = PHRASE_OT_IN; data_size = sizeof(PHRASE_OT_IN); break;
    case 3: data = PHRASE_OT_OUT; data_size = sizeof(PHRASE_OT_OUT); break;
    case 4: data = PHRASE_CARD_UNKNOWN; data_size = sizeof(PHRASE_CARD_UNKNOWN); break;
    case 5: data = PHRASE_FINGER_UNKNOWN; data_size = sizeof(PHRASE_FINGER_UNKNOWN); break;
    case 6: data = PHRASE_FAILED; data_size = sizeof(PHRASE_FAILED); break;
    case 7: data = PHRASE_RESCAN; data_size = sizeof(PHRASE_RESCAN); break;
    case 8: data = PHRASE_ENROLL_DONE; data_size = sizeof(PHRASE_ENROLL_DONE); break;
    case 9: data = PHRASE_CARD_ENROLL_PROMPT; data_size = sizeof(PHRASE_CARD_ENROLL_PROMPT); break;
    case 10: data = PHRASE_CARD_ENROLL_DONE; data_size = sizeof(PHRASE_CARD_ENROLL_DONE); break;
    default: return;
  }
  std::vector<uint8_t> payload{'[','v','6',']','[','s','5',']'};
  if (employee != nullptr && employee->code[0] != '\0') {
    for (const unsigned char byte : std::string(employee->code)) {
      if (byte >= '0' && byte <= '9') {
        const uint8_t digit = static_cast<uint8_t>(byte - '0');
        payload.push_back(DIGIT_GB2312[digit][0]);
        payload.push_back(DIGIT_GB2312[digit][1]);
      } else if (byte >= 0x20U && byte <= 0x7EU) {
        payload.push_back(byte);
      }
    }
    payload.push_back(',');
  }
  payload.insert(payload.end(), data, data + data_size);
  if (tts_queue_.size() >= 8)
    tts_queue_.pop_front();
  tts_queue_.push_back(std::move(payload));
}

void AttendanceWebS3::process_tts_() {
  if (tts_uart_ == nullptr)
    return;
  uint8_t response = 0;
  while (tts_uart_->available() && tts_uart_->read_byte(&response)) {
    if (response == 0x4F && tts_waiting_status_ && !tts_queue_.empty()) {
      send_tts_frame_(tts_queue_.front());
      tts_queue_.pop_front();
      tts_waiting_status_ = false;
      last_tts_query_millis_ = millis();
    } else if (response == 0x4E || response == 0x41) {
      tts_waiting_status_ = false;
      last_tts_query_millis_ = millis();
    }
  }
  const uint32_t now = millis();
  if (tts_waiting_status_ && now - tts_query_sent_millis_ > 250U)
    tts_waiting_status_ = false;
  if (!tts_waiting_status_ && !tts_queue_.empty() && now - last_tts_query_millis_ >= 300U) {
    const uint8_t query[] = {0xFD, 0x00, 0x01, 0x21};
    tts_uart_->write_array(query, sizeof(query));
    tts_uart_->flush();
    tts_waiting_status_ = true;
    tts_query_sent_millis_ = now;
    last_tts_query_millis_ = now;
  }
}
int AttendanceWebS3::find_uid_(const std::string &uid) const {
  for (size_t i = 0; i < MAX_EMPLOYEES; i++) {
    if (employees_[i].active && uid == employees_[i].uid)
      return i;
  }
  return -1;
}

bool AttendanceWebS3::handle_tag(const std::string &uid) {
  if (import_in_progress_) {
    last_result_ = "資料還原中，暫停刷卡";
    remember_card_result_(uid, "", last_result_);
    ESP_LOGW(TAG, "%s", last_result_.c_str());
    return false;
  }
  if (enroll_employee_>=0 && enroll_employee_<(int)MAX_EMPLOYEES) {
    const int target_employee=enroll_employee_;
    int same_employee=-1;
    int conflicting_employee=-1;
    // Scan every active employee rather than stopping at the first match. This
    // also detects duplicate UIDs left behind by firmware versions before 1.3.22.
    for(size_t index=0;index<MAX_EMPLOYEES;index++) {
      if(!employees_[index].active||uid!=employees_[index].uid)
        continue;
      if((int)index==target_employee)
        same_employee=target_employee;
      else {
        conflicting_employee=static_cast<int>(index);
        break;
      }
    }
    if(conflicting_employee>=0) {
      last_result_="此卡已綁定其他員工："+std::string(employees_[conflicting_employee].code)+"／"+
                   std::string(employees_[conflicting_employee].name);
      remember_card_result_(uid, employees_[conflicting_employee].name, "卡片已綁定其他員工");
      ESP_LOGW(TAG,"%s",last_result_.c_str());
      queue_tts_phrase_(nullptr, 6);
      enroll_employee_=-1;
      restore_mode_color_();
      return false;
    }
    if(same_employee>=0) {
      last_result_="此卡已完成綁定："+std::string(employees_[target_employee].code)+"／"+
                   std::string(employees_[target_employee].name);
      remember_card_result_(uid, employees_[target_employee].name, "卡片已完成綁定");
      last_card_code_ = employees_[target_employee].code;
      last_card_display_state_ = "CARD OK";
      queue_tts_phrase_(nullptr, 10);
      ESP_LOGI(TAG,"%s",last_result_.c_str());
      enroll_employee_=-1;
      restore_mode_color_();
      return true;
    }
    Employee previous = employees_[enroll_employee_];
    strlcpy(employees_[enroll_employee_].uid, uid.c_str(), sizeof(Employee::uid));
    employees_[enroll_employee_].active=1;
    if (!save_employees_()) {
      employees_[enroll_employee_] = previous;
      last_result_="卡片綁定儲存失敗，請勿斷電並查看日誌";
      remember_card_result_(uid, previous.name, last_result_);
      queue_tts_phrase_(nullptr, 6);
      ESP_LOGE(TAG, "%s", last_result_.c_str());
      enroll_employee_=-1;
      restore_mode_color_();
      return false;
    }
    last_result_="卡片綁定完成："+std::string(employees_[enroll_employee_].name);
    remember_card_result_(uid, employees_[enroll_employee_].name, "卡片綁定完成");
    last_card_code_ = employees_[enroll_employee_].code;
    last_card_display_state_ = "CARD OK";
    queue_tts_phrase_(nullptr, 10);
    ESP_LOGI(TAG, "%s", last_result_.c_str());
    enroll_employee_=-1;
    restore_mode_color_();
    return true;
  }
  int i=find_uid_(uid);
  if(i<0) {
    last_result_="未登記卡片："+uid;
    remember_card_result_(uid, "", "未登記卡片");
    last_card_code_ = "UNKNOWN";
    last_card_display_state_ = "FAIL";
    queue_tts_phrase_(nullptr, 4);
    ESP_LOGW(TAG, "%s", last_result_.c_str());
    return false;
  }
  return record_attendance_(static_cast<size_t>(i), uid);
}

bool AttendanceWebS3::record_attendance_(size_t employee_index, const std::string &credential_label) {
  if (import_in_progress_ || clear_logs_in_progress_) {
    last_result_ = import_in_progress_ ? "資料還原中，暫停打卡" : "正在刪除刷卡紀錄，暫停打卡";
    return false;
  }
  if (employee_index >= employees_.size() || !employees_[employee_index].active)
    return false;
  Employee &employee = employees_[employee_index];
  const ESPTime current_time = effective_now_();
  if(!current_time.is_valid()) {
    last_result_="時間尚未同步，打卡未寫入";
    remember_card_result_(credential_label, employee.name, last_result_);
    last_card_code_ = employee.code;
    last_card_display_state_ = "FAIL";
    queue_tts_phrase_(&employee, 6);
    ESP_LOGW(TAG, "%s", last_result_.c_str());
    return false;
  }
  if (pending_action_<0) {
    select_action(current_time.hour < 14);
  }
  uint32_t uh=fnv1a(credential_label.data(),credential_label.size());
  const uint8_t action = static_cast<uint8_t>(pending_action_);
  if(append_log_(employee.id,action,uh,current_time.timestamp)) {
    last_result_=std::string(employee.name)+" "+action_label(action)+"成功";
    remember_card_result_(credential_label, employee.name, std::string(action_label(action)) + "成功");
    last_card_code_ = employee.code;
    last_card_display_state_ = "OK";
    const uint8_t phrase = action == ACTION_CLOCK_IN ? 0 : action == ACTION_CLOCK_OUT ? 1 :
                           action == ACTION_OVERTIME_IN ? 2 : 3;
    queue_tts_phrase_(&employee, phrase);
    if (employee.can_open_door)
      unlock_door_(credential_label.c_str());
    ESP_LOGI(TAG, "%s，Flash offset=%u", last_result_.c_str(), (unsigned) write_offset_);
    return true;
  }
  last_result_="資料保存失敗，本次打卡未完成";
  remember_card_result_(credential_label, employee.name, last_result_);
  last_card_code_ = employee.code;
  last_card_display_state_ = "FAIL";
  queue_tts_phrase_(&employee, 6);
  ESP_LOGE(TAG, "%s", last_result_.c_str());
  return false;
}

int AttendanceWebS3::find_fingerprint_id_(uint16_t finger_id) const {
  for (size_t index = 0; index < employees_.size(); index++) {
    const auto &employee = employees_[index];
    if (!employee.active)
      continue;
    if ((employee.finger1_enrolled && finger_id == stored_fingerprint_template_id_(employee, index, 1)) ||
        (employee.finger2_enrolled && finger_id == stored_fingerprint_template_id_(employee, index, 2)))
      return static_cast<int>(index);
  }
  return -1;
}

bool AttendanceWebS3::handle_fingerprint(uint16_t finger_id, uint16_t confidence) {
  const int employee_index = find_fingerprint_id_(finger_id);
  if (employee_index < 0) {
    last_unmapped_fingerprint_id_ = finger_id;
    last_result_ = "指紋ID未綁定員工：" + std::to_string(finger_id);
    remember_card_result_("FINGER:" + std::to_string(finger_id), "", "未登記指紋");
    last_card_code_ = "UNKNOWN";
    last_card_display_state_ = "FAIL";
    queue_tts_phrase_(nullptr, 5);
    return false;
  }
  last_unmapped_fingerprint_id_ = 0;
  ESP_LOGI(TAG, "Fingerprint %u matched employee %s, confidence=%u", finger_id,
           employees_[employee_index].code, confidence);
  return record_attendance_(static_cast<size_t>(employee_index), "FINGER:" + std::to_string(finger_id));
}

uint16_t AttendanceWebS3::stored_fingerprint_template_id_(const Employee &employee, size_t employee_index,
                                                           uint8_t finger_number) {
  const auto *bytes = reinterpret_cast<const uint8_t *>(employee.voice_name);
  if (bytes[0] == 'F' && bytes[1] == 'P' && bytes[2] == 'I' && bytes[3] == 'D') {
    const size_t offset = finger_number == 1 ? 4 : 6;
    const uint16_t value = static_cast<uint16_t>(bytes[offset]) |
                           (static_cast<uint16_t>(bytes[offset + 1]) << 8U);
    if (value >= 1 && value <= 1000)
      return value;
  }
  return fingerprint_template_id_(employee_index, finger_number);
}

void AttendanceWebS3::store_fingerprint_template_id_(Employee &employee, uint8_t finger_number,
                                                       uint16_t template_id) {
  auto *bytes = reinterpret_cast<uint8_t *>(employee.voice_name);
  if (!(bytes[0] == 'F' && bytes[1] == 'P' && bytes[2] == 'I' && bytes[3] == 'D')) {
    memset(employee.voice_name, 0, sizeof(employee.voice_name));
    bytes[0] = 'F';
    bytes[1] = 'P';
    bytes[2] = 'I';
    bytes[3] = 'D';
  }
  const size_t offset = finger_number == 1 ? 4 : 6;
  bytes[offset] = static_cast<uint8_t>(template_id & 0xFFU);
  bytes[offset + 1] = static_cast<uint8_t>(template_id >> 8U);
}

bool AttendanceWebS3::append_log_(uint16_t eid, uint8_t action, uint32_t uid_hash, uint32_t timestamp,
                                  bool manual) {
  const uint32_t sector = partition_->erase_size;
  if (write_offset_ % sector == 0 && !erase_partition_range_safely_(partition_, write_offset_, sector))
    return false;
  LogRecord record{};
  record.magic = LOG_MAGIC;
  record.timestamp = timestamp;
  record.employee_id = eid;
  record.action = action;
  record.reserved = manual ? 1 : 0;
  record.uid_hash = uid_hash;
  if (++log_sequence_ == 0)
    log_sequence_ = 1;
  set_log_sequence(&record, log_sequence_);
  record.crc = fnv1a(&record, sizeof(record) - 4);
  if (esp_partition_write(partition_, write_offset_, &record, sizeof(record)) != ESP_OK)
    return false;
  write_offset_ += sizeof(record);
  if (write_offset_ + sizeof(record) > log_region_size_)
    write_offset_ = 0;
  log_record_count_ = std::min<uint32_t>(log_record_count_ + 1U, log_region_size_ / sizeof(LogRecord));
  return true;
}

uint32_t AttendanceWebS3::cutoff_timestamp_() const {
  const ESPTime current_time = effective_now_();
  if (!current_time.is_valid())
    return 0;

  time_t timestamp = current_time.timestamp;
  struct tm time_info {};
  localtime_r(&timestamp, &time_info);
  const int original_day = time_info.tm_mday;
  time_info.tm_mday = 1;
  time_info.tm_mon -= 2;
  time_info.tm_hour = 0;
  time_info.tm_min = 0;
  time_info.tm_sec = 0;
  mktime(&time_info);
  struct tm last_day = time_info;
  last_day.tm_mon += 1;
  last_day.tm_mday = 0;
  mktime(&last_day);
  time_info.tm_mday = std::min(original_day, last_day.tm_mday);
  return static_cast<uint32_t>(mktime(&time_info));
}

bool AttendanceWebS3::canHandle(AsyncWebServerRequest *r) const {
  std::array<char, AsyncWebServerRequest::URL_BUF_SIZE> url_buffer{};
  const std::string url = r->url_to(url_buffer).str();
  return url.rfind("/attendance", 0) == 0;
}
void AttendanceWebS3::send_json_(AsyncWebServerRequest *r,int code,const std::string &body) { auto *res=r->beginResponse(code,"application/json; charset=utf-8",body.c_str()); res->addHeader("Cache-Control","no-store"); r->send(res); }

void AttendanceWebS3::on_fingerprint_enrollment_scan_(uint8_t scan_num, uint16_t finger_id) {
  if (fingerprint_enroll_employee_ < 0)
    return;
  last_result_ = "指紋第 " + std::to_string(scan_num) + " 次採集完成，請移開後再次按壓";
  if (scan_num == 1)
    queue_tts_phrase_(nullptr, 7);
}

void AttendanceWebS3::on_fingerprint_enrollment_done_(uint16_t finger_id) {
  if (fingerprint_enroll_employee_ < 0 || fingerprint_enroll_employee_ >= static_cast<int>(MAX_EMPLOYEES))
    return;
  const size_t index = static_cast<size_t>(fingerprint_enroll_employee_);
  const uint16_t expected = fingerprint_template_id_(index, fingerprint_enroll_number_);
  if (finger_id != expected) {
    last_result_ = "指紋登記回傳ID不符，資料未綁定";
  } else {
    Employee previous = employees_[index];
    if (fingerprint_enroll_number_ == 1)
      employees_[index].finger1_enrolled = 1;
    else
      employees_[index].finger2_enrolled = 1;
    store_fingerprint_template_id_(employees_[index], fingerprint_enroll_number_, finger_id);
    if (!save_employees_()) {
      employees_[index] = previous;
      last_result_ = "指紋已存入模組，但員工對應保存失敗";
    } else {
      last_result_ = std::string(employees_[index].name) + " 指紋" +
                     std::to_string(fingerprint_enroll_number_) + "登記完成";
      last_card_code_ = employees_[index].code;
      last_card_display_state_ = "FP OK";
      queue_tts_phrase_(&employees_[index], 8);
    }
  }
  fingerprint_enroll_employee_ = -1;
  fingerprint_enroll_number_ = 0;
  restore_mode_color_();
}

void AttendanceWebS3::on_fingerprint_enrollment_failed_(uint16_t finger_id) {
  last_result_ = "指紋登記失敗，請從員工管理頁重新開始";
  last_card_display_state_ = "FP FAIL";
  queue_tts_phrase_(nullptr, 6);
  fingerprint_enroll_employee_ = -1;
  fingerprint_enroll_number_ = 0;
  restore_mode_color_();
}

void AttendanceWebS3::begin_fingerprint_enroll_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  const int slot = atoi(param(request, "slot").c_str());
  const int finger = atoi(param(request, "finger").c_str());
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，未開始登記指紋\"}");
    return;
  }
  if (fingerprint_ == nullptr || fingerprint_->is_failed()) {
    send_json_(request, 503, "{\"error\":\"R307-S 尚未連線\"}");
    return;
  }
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || !employees_[slot - 1].active ||
      (finger != 1 && finger != 2)) {
    send_json_(request, 400, "{\"error\":\"員工或指紋編號不正確\"}");
    return;
  }
  fingerprint_enroll_employee_ = slot - 1;
  fingerprint_enroll_number_ = static_cast<uint8_t>(finger);
  const uint16_t template_id = fingerprint_template_id_(slot - 1, finger);
  fingerprint_->enroll_fingerprint(template_id, 2);
  last_result_ = std::string("請按壓指紋兩次：") + employees_[slot - 1].name + "／指紋" + std::to_string(finger);
  show_enroll_color_();
  send_json_(request, 200, "{\"ok\":true,\"finger_id\":" + std::to_string(template_id) + "}");
}

void AttendanceWebS3::delete_fingerprint_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  const int slot = atoi(param(request, "slot").c_str());
  const int finger = atoi(param(request, "finger").c_str());
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，指紋未刪除\"}");
    return;
  }
  if (fingerprint_ == nullptr || fingerprint_->is_failed()) {
    send_json_(request, 503, "{\"error\":\"R307-S 為選配模組，目前未連線\"}");
    return;
  }
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || !employees_[slot - 1].active ||
      (finger != 1 && finger != 2)) {
    send_json_(request, 400, "{\"error\":\"員工或指紋編號不正確\"}");
    return;
  }
  Employee previous = employees_[slot - 1];
  fingerprint_->delete_fingerprint(stored_fingerprint_template_id_(employees_[slot - 1], slot - 1, finger));
  if (finger == 1)
    employees_[slot - 1].finger1_enrolled = 0;
  else
    employees_[slot - 1].finger2_enrolled = 0;
  store_fingerprint_template_id_(employees_[slot - 1], static_cast<uint8_t>(finger), 0);
  if (!save_employees_()) {
    employees_[slot - 1] = previous;
    send_json_(request, 500, "{\"error\":\"員工指紋狀態保存失敗\"}");
    return;
  }
  last_result_ = std::string(employees_[slot - 1].name) + " 指紋" + std::to_string(finger) + "已刪除";
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::clear_all_fingerprints_(AsyncWebServerRequest *request) {
  if (import_in_progress_ || clear_logs_in_progress_ || fingerprint_enroll_employee_ >= 0) {
    send_json_(request, 409, "{\"error\":\"裝置正忙，請等待目前工作完成後再清空指紋\"}");
    return;
  }
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，指紋未清空\"}");
    return;
  }
  if (param(request, "confirmation") != "清空全部指紋") {
    send_json_(request, 400, "{\"error\":\"確認文字不正確，指紋未清空\"}");
    return;
  }
  if (fingerprint_ == nullptr || fingerprint_->is_failed() || fingerprint_count_sensor_ == nullptr) {
    send_json_(request, 503, "{\"error\":\"R307-S 為選配模組，目前未連線\"}");
    return;
  }

  fingerprint_count_sensor_->publish_state(NAN);
  fingerprint_->delete_all_fingerprints();
  const bool sensor_cleared = fingerprint_count_sensor_->has_state() &&
                              std::isfinite(fingerprint_count_sensor_->state) &&
                              fingerprint_count_sensor_->state < 0.5f;
  if (!sensor_cleared) {
    send_json_(request, 500, "{\"error\":\"R307-S 未確認清空成功，員工指紋對應尚未變更\"}");
    return;
  }

  uint16_t mapping_count = 0;
  for (auto &employee : employees_) {
    if (!employee.active)
      continue;
    mapping_count += employee.finger1_enrolled ? 1 : 0;
    mapping_count += employee.finger2_enrolled ? 1 : 0;
    employee.finger1_enrolled = 0;
    employee.finger2_enrolled = 0;
    store_fingerprint_template_id_(employee, 1, 0);
    store_fingerprint_template_id_(employee, 2, 0);
  }
  if (!save_employees_() && !save_employees_()) {
    last_result_ = "指紋已清空，但員工對應保存失敗；請勿重啟並立即重試";
    send_json_(request, 500, "{\"error\":\"R307-S 已清空，但員工指紋對應保存失敗，請立即重試\"}");
    return;
  }
  last_unmapped_fingerprint_id_ = 0;
  last_result_ = "R307-S 全部指紋與員工對應已清空";
  ESP_LOGW(TAG, "All R307-S templates and %u employee fingerprint mappings were cleared",
           static_cast<unsigned>(mapping_count));
  send_json_(request, 200, "{\"ok\":true,\"cleared_mappings\":" + std::to_string(mapping_count) + "}");
}

void AttendanceWebS3::add_manual_attendance_(AsyncWebServerRequest *request) {
  if (import_in_progress_ || clear_logs_in_progress_) {
    send_json_(request, 409, "{\"error\":\"裝置正在維護 Flash，暫時無法補打卡\"}");
    return;
  }
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，未新增補打卡紀錄\"}");
    return;
  }
  uint32_t slot = 0, action = 0, timestamp = 0;
  if (!parse_uint32_strict(param(request, "slot"), &slot) || slot < 1 || slot > MAX_EMPLOYEES ||
      !employees_[slot - 1].active || !parse_uint32_strict(param(request, "action"), &action) ||
      action > ACTION_OVERTIME_OUT || !parse_uint32_strict(param(request, "timestamp"), &timestamp)) {
    send_json_(request, 400, "{\"error\":\"員工、日期時間或打卡類型不正確\"}");
    return;
  }
  const ESPTime now = effective_now_();
  const uint32_t cutoff = cutoff_timestamp_();
  if (!now.is_valid() || cutoff == 0) {
    send_json_(request, 503, "{\"error\":\"裝置時間尚未就緒，無法核對補打卡日期\"}");
    return;
  }
  if (timestamp < cutoff || timestamp > static_cast<uint32_t>(now.timestamp)) {
    send_json_(request, 400, "{\"error\":\"只能補登目前時間以前、最近兩個日曆月內的打卡\"}");
    return;
  }
  if (!append_log_(static_cast<uint16_t>(slot), static_cast<uint8_t>(action), 0, timestamp, true)) {
    send_json_(request, 500, "{\"error\":\"補打卡紀錄寫入 Flash 失敗\"}");
    return;
  }
  last_result_ = std::string("管理員已補登：") + employees_[slot - 1].name + " " +
                 action_label(static_cast<uint8_t>(action));
  ESP_LOGI(TAG, "Manual attendance added for employee slot %u at %u, action=%u",
           static_cast<unsigned>(slot), static_cast<unsigned>(timestamp), static_cast<unsigned>(action));
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::bind_fingerprint_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  const int slot = atoi(param(request, "slot").c_str());
  const int finger = atoi(param(request, "finger").c_str());
  const int template_id = atoi(param(request, "template_id").c_str());
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，指紋ID未變更\"}");
    return;
  }
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || !employees_[slot - 1].active ||
      (finger != 1 && finger != 2) || template_id < 1 || template_id > 1000) {
    send_json_(request, 400, "{\"error\":\"員工、手指或模板ID不正確\"}");
    return;
  }
  Employee previous = employees_[slot - 1];
  if (finger == 1)
    employees_[slot - 1].finger1_enrolled = 1;
  else
    employees_[slot - 1].finger2_enrolled = 1;
  store_fingerprint_template_id_(employees_[slot - 1], static_cast<uint8_t>(finger),
                                 static_cast<uint16_t>(template_id));
  if (!save_employees_()) {
    employees_[slot - 1] = previous;
    send_json_(request, 500, "{\"error\":\"指紋ID對應保存失敗\"}");
    return;
  }
  last_unmapped_fingerprint_id_ = 0;
  last_result_ = std::string(employees_[slot - 1].name) + " 指紋" + std::to_string(finger) +
                 "已綁定模板ID " + std::to_string(template_id);
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::handleRequest(AsyncWebServerRequest *r) {
  std::array<char, AsyncWebServerRequest::URL_BUF_SIZE> url_buffer{};
  const std::string u = r->url_to(url_buffer).str();
  if(u=="/attendance"||u=="/attendance/") serve_page_(r);
  else if(u=="/attendance/api/status") serve_status_(r);
  else if(u=="/attendance/api/employees") serve_employees_(r);
  else if(u=="/attendance/api/notes") serve_notes_(r);
  else if(u=="/attendance/api/note") mutate_note_(r);
  else if(u=="/attendance/api/employee") mutate_employee_(r);
  else if(u=="/attendance/api/mode") set_attendance_mode_(r);
  else if(u=="/attendance/api/mode-schedule") mutate_mode_schedule_(r);
  else if(u=="/attendance/api/clear-logs") clear_logs_(r);
  else if(u=="/attendance/api/clear-logs-status") clear_logs_status_(r);
  else if(u=="/attendance/api/manual-time") set_manual_time_(r);
  else if(u=="/attendance/api/automatic-time") restore_automatic_time_(r);
  else if(u=="/attendance/api/admin-password") change_admin_password_(r);
  else if(u=="/attendance/api/import-begin") begin_backup_import_(r);
  else if(u=="/attendance/api/import-erase") erase_backup_import_chunk_(r);
  else if(u=="/attendance/api/import-employee") import_employee_(r);
  else if(u=="/attendance/api/import-note") import_note_(r);
  else if(u=="/attendance/api/import-logs") import_log_batch_(r);
  else if(u=="/attendance/api/import-finish") finish_backup_import_(r);
  else if(u=="/attendance/api/import-abort") abort_backup_import_(r);
  else if(u=="/attendance/api/delete") delete_employee_(r);
  else if(u=="/attendance/api/card-bind") bind_card_manual_(r);
  else if(u=="/attendance/api/fingerprint-enroll") begin_fingerprint_enroll_(r);
  else if(u=="/attendance/api/fingerprint-delete") delete_fingerprint_(r);
  else if(u=="/attendance/api/fingerprint-clear-all") clear_all_fingerprints_(r);
  else if(u=="/attendance/api/fingerprint-bind") bind_fingerprint_(r);
  else if(u=="/attendance/api/manual-attendance") add_manual_attendance_(r);
  else if(u=="/attendance/api/enroll") { if(!verify_admin_password_(param(r,"password"))) { send_json_(r,403,"{\"error\":\"管理員密碼錯誤\"}"); return; } int slot=atoi(param(r,"slot").c_str()); if(slot<1||slot>(int)MAX_EMPLOYEES||!employees_[slot-1].active) { send_json_(r,400,"{\"error\":\"找不到這位員工，請重新整理頁面\"}"); } else { enroll_employee_=slot-1; last_result_="請將要登記的新卡靠近感應區（七彩循環燈）"; show_enroll_color_(); queue_tts_phrase_(nullptr,9); send_json_(r,200,"{\"ok\":true,\"message\":\"請將新卡靠近感應區\"}"); } }
  else if(u=="/attendance/api/unlock") { if(!verify_admin_password_(param(r,"password"))) { send_json_(r,403,"{\"error\":\"管理員密碼錯誤\"}"); return; } trigger_remote_unlock(); send_json_(r,200,"{\"ok\":true}"); }
  else if(u=="/attendance/api/export-page") serve_export_data_(r);
  else if(u=="/attendance/api/logs") serve_logs_(r);
  else if(u=="/attendance/export.xlsx") serve_export_launcher_(r);
  else if(u=="/attendance/export.csv") serve_csv_launcher_(r);
  else r->send(404,"text/plain","Not found");
}

void AttendanceWebS3::serve_status_(AsyncWebServerRequest *r) {
  const std::string mode = attendance_mode_text();
  const ESPTime effective_time = effective_now_();
  const bool time_valid = effective_time.is_valid();
  const bool hardware_rtc_connected = hardware_rtc_is_connected();
  const std::string time_source = time_source_text();
  char current_time[24] = "尚未同步";
  if (time_valid) {
    time_t timestamp = effective_time.timestamp;
    struct tm time_info {};
    localtime_r(&timestamp, &time_info);
    strftime(current_time, sizeof(current_time), "%Y-%m-%d %H:%M:%S", &time_info);
  }

  const bool network_connected = network_is_connected();
  const bool fingerprint_component_ready = fingerprint_ != nullptr && !fingerprint_->is_failed();
  const bool fingerprint_count_known = fingerprint_count_sensor_ != nullptr && fingerprint_count_sensor_->has_state() &&
                                       std::isfinite(fingerprint_count_sensor_->state);
  const bool fingerprint_capacity_known =
      fingerprint_capacity_sensor_ != nullptr && fingerprint_capacity_sensor_->has_state() &&
      std::isfinite(fingerprint_capacity_sensor_->state);
  const bool fingerprint_status_known = fingerprint_status_sensor_ != nullptr &&
                                        fingerprint_status_sensor_->has_state() &&
                                        std::isfinite(fingerprint_status_sensor_->state);
  const int fingerprint_count = fingerprint_count_known ? static_cast<int>(fingerprint_count_sensor_->state) : -1;
  const int fingerprint_capacity =
      fingerprint_capacity_known ? static_cast<int>(fingerprint_capacity_sensor_->state) : -1;
  const int fingerprint_status = fingerprint_status_known ? static_cast<int>(fingerprint_status_sensor_->state) : -1;
  uint16_t fingerprint_mapped_count = 0;
  uint16_t employee_count = 0;
  for (const auto &employee : employees_) {
    if (!employee.active)
      continue;
    employee_count++;
    fingerprint_mapped_count += employee.finger1_enrolled ? 1 : 0;
    fingerprint_mapped_count += employee.finger2_enrolled ? 1 : 0;
  }
  std::array<char, wifi::SSID_BUFFER_SIZE> ssid_buffer{};
  const char *wifi_ssid = network_connected ? wifi_->wifi_ssid_to(ssid_buffer) : "";
  char ip_address[network::IP_ADDRESS_BUFFER_SIZE]{};
  if (network_connected) {
    const auto addresses = wifi_->get_ip_addresses();
    for (const auto &address : addresses) {
      if (address.is_set() && address.is_ip4()) {
        address.str_to(ip_address);
        break;
      }
    }
    if (ip_address[0] == '\0') {
      for (const auto &address : addresses) {
        if (address.is_set()) {
          address.str_to(ip_address);
          break;
        }
      }
    }
  }

  std::ostringstream o;
  auto schedule_time = [this](uint8_t action) {
    // uint8_t can theoretically format as three digits; keep enough room so
    // compiler truncation checks remain clean even though stored times are validated.
    char value[9];
    snprintf(value, sizeof(value), "%02u:%02u", static_cast<unsigned>(mode_schedule_.hour[action]),
             static_cast<unsigned>(mode_schedule_.minute[action]));
    return std::string(value);
  };
  o << "{\"result\":\"" << esc(last_result_.c_str()) << "\",\"mode\":\"" << mode
    << "\",\"enrolling\":" << (enroll_employee_ >= 0 ? "true" : "false")
    << ",\"time_valid\":" << (time_valid ? "true" : "false")
    << ",\"manual_time_override\":" << (manual_time_override_ ? "true" : "false")
    << ",\"time_source\":\"" << time_source << "\""
    << ",\"hardware_rtc_connected\":" << (hardware_rtc_connected ? "true" : "false")
    << ",\"current_time\":\"" << current_time << "\""
    << ",\"network_connected\":" << (network_connected ? "true" : "false")
    << ",\"wifi_ssid\":\"" << esc(wifi_ssid) << "\""
    << ",\"ip_address\":\"" << esc(ip_address) << "\""
    << ",\"fingerprint_connected\":"
    << (fingerprint_component_ready && fingerprint_count_known ? "true" : "false")
    << ",\"fingerprint_count\":" << fingerprint_count
    << ",\"fingerprint_capacity\":" << fingerprint_capacity
    << ",\"fingerprint_status\":" << fingerprint_status
    << ",\"fingerprint_mapped_count\":" << fingerprint_mapped_count
    << ",\"last_unmapped_fingerprint_id\":" << last_unmapped_fingerprint_id_
    << ",\"free_heap\":" << esp_get_free_heap_size()
    << ",\"free_internal_heap\":" << heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
    << ",\"employee_count\":" << employee_count
    << ",\"employee_capacity\":" << MAX_EMPLOYEES
    << ",\"note_count\":" << note_count_
    << ",\"log_count\":" << log_record_count_
    << ",\"log_capacity\":" << (log_region_size_ / sizeof(LogRecord))
    << ",\"note_capacity\":" << (notes_partition_ != nullptr ? MAX_DAILY_NOTES : 0)
    << ",\"note_journal_used\":" << note_journal_used_
    << ",\"note_journal_capacity\":" << NOTE_JOURNAL_RECORD_CAPACITY
    << ",\"log_high_water_percent\":" << static_cast<unsigned>(LOG_HIGH_WATER_PERCENT)
    << ",\"auto_mode_enabled\":" << (mode_schedule_.master_enabled ? "true" : "false")
    << ",\"mode_schedule\":{"
    << "\"in\":{\"enabled\":" << (mode_schedule_.entry_enabled[ACTION_CLOCK_IN] ? "true" : "false")
    << ",\"time\":\"" << schedule_time(ACTION_CLOCK_IN) << "\"},"
    << "\"out\":{\"enabled\":" << (mode_schedule_.entry_enabled[ACTION_CLOCK_OUT] ? "true" : "false")
    << ",\"time\":\"" << schedule_time(ACTION_CLOCK_OUT) << "\"},"
    << "\"overtime_in\":{\"enabled\":" << (mode_schedule_.entry_enabled[ACTION_OVERTIME_IN] ? "true" : "false")
    << ",\"time\":\"" << schedule_time(ACTION_OVERTIME_IN) << "\"},"
    << "\"overtime_out\":{\"enabled\":" << (mode_schedule_.entry_enabled[ACTION_OVERTIME_OUT] ? "true" : "false")
    << ",\"time\":\"" << schedule_time(ACTION_OVERTIME_OUT) << "\"}}}";
  send_json_(r, 200, o.str());
}
void AttendanceWebS3::serve_employees_(AsyncWebServerRequest *r) {
  std::ostringstream o;
  o << "[";
  bool first = true;
  for (auto &e : employees_) {
    if (!e.name[0] || !e.active)
      continue;
    if (!first)
      o << ",";
    first = false;
    o << "{\"slot\":" << e.id << ",\"id\":\"" << esc(e.code) << "\",\"name\":\"" << esc(e.name)
      << "\",\"uid\":\"" << esc(e.uid)
      << "\",\"can_open\":" << (e.can_open_door ? "true" : "false")
      << ",\"finger1\":" << (e.finger1_enrolled ? "true" : "false")
      << ",\"finger2\":" << (e.finger2_enrolled ? "true" : "false")
      << ",\"finger1_id\":" << (e.finger1_enrolled ? stored_fingerprint_template_id_(e, e.id - 1, 1) : 0)
      << ",\"finger2_id\":" << (e.finger2_enrolled ? stored_fingerprint_template_id_(e, e.id - 1, 2) : 0)
      << ",\"active\":true}";
  }
  o << "]";
  send_json_(r, 200, o.str());
}

void AttendanceWebS3::serve_notes_(AsyncWebServerRequest *request) {
  const bool include_all = param(request, "all") == "1";
  const bool paged = param(request, "paged") == "1";
  const uint32_t requested_offset = paged ? strtoul(param(request, "offset").c_str(), nullptr, 10) : 0;
  uint32_t requested_limit = paged ? strtoul(param(request, "limit").c_str(), nullptr, 10) : MAX_DAILY_NOTES;
  if (requested_limit == 0 || requested_limit > 100)
    requested_limit = 50;
  uint32_t cutoff_date = 0;
  const uint32_t cutoff_timestamp = cutoff_timestamp_();
  if (cutoff_timestamp != 0) {
    time_t timestamp = cutoff_timestamp;
    struct tm time_info {};
    localtime_r(&timestamp, &time_info);
    cutoff_date = static_cast<uint32_t>((time_info.tm_year + 1900) * 10000 +
                                        (time_info.tm_mon + 1) * 100 + time_info.tm_mday);
  }
  std::ostringstream output;
  output << (paged ? "{\"notes\":[" : "[");
  bool first = true;
  uint32_t matched = 0;
  uint32_t added = 0;
  bool has_more = false;
  for (size_t note_index = 0; note_index < note_count_; note_index++) {
    DailyNote note{};
    if (!read_note_(note_index, &note) ||
        (!include_all && cutoff_date != 0 && note.date < cutoff_date))
      continue;
    if (matched++ < requested_offset)
      continue;
    if (paged && added >= requested_limit) {
      has_more = true;
      break;
    }
    const Employee *employee = nullptr;
    for (const auto &candidate : employees_) {
      if (candidate.id == note.employee_id) {
        employee = &candidate;
        break;
      }
    }
    // Keep extra room because printf field width is a minimum, not a maximum.
    // Valid stored dates still render as the usual 10-character YYYY-MM-DD.
    char date[16];
    format_date_value(note.date, date, sizeof(date));
    if (!first)
      output << ",";
    first = false;
    const bool employee_active = employee != nullptr && employee->active && employee->name[0] != '\0';
    std::string deleted_employee_label;
    if (!employee_active)
      deleted_employee_label = "已刪除員工（槽位 " + std::to_string(note.employee_id) + "）";
    output << "{\"date\":\"" << date << "\",\"slot\":" << note.employee_id << ",\"id\":\""
           << esc(employee_active ? employee->code : "") << "\",\"name\":\""
           << esc(employee_active ? employee->name : deleted_employee_label.c_str()) << "\",\"note\":\""
           << esc(note.text) << "\"}";
    added++;
  }
  output << "]";
  if (paged)
    output << ",\"next\":" << (requested_offset + added) << ",\"done\":"
           << (has_more ? "false" : "true") << "}";
  send_json_(request, 200, output.str());
}

void AttendanceWebS3::mutate_note_(AsyncWebServerRequest *request) {
  if (import_in_progress_) {
    send_json_(request, 409, "{\"error\":\"資料還原中，暫時無法修改備註\"}");
    return;
  }
  if (notes_partition_ == nullptr) {
    send_json_(request, 503, "{\"error\":\"備註儲存空間尚未準備完成，請聯絡設備維護人員\"}");
    return;
  }
  const int slot = atoi(param(request, "slot").c_str());
  const std::string date_text = param(request, "date");
  const std::string note_text = param(request, "note");
  uint32_t date = 0;
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES)) {
    send_json_(request, 400, "{\"error\":\"員工槽位不正確\"}");
    return;
  }
  if (!parse_date_value(date_text, &date)) {
    send_json_(request, 400, "{\"error\":\"備註日期格式不正確\"}");
    return;
  }
  if (note_text == "undefined" || note_text.size() >= sizeof(DailyNote{}.text) ||
      utf8_character_count(note_text) > 15) {
    send_json_(request, 400, "{\"error\":\"備註最多 15 個字\"}");
    return;
  }

  int note_index = find_note_index_(static_cast<uint16_t>(slot), date);
  if (note_text.empty()) {
    if (note_index < 0) {
      send_json_(request, 200, "{\"ok\":true}");
      return;
    }
    DailyNote deleted{};
    deleted.date = date;
    deleted.employee_id = static_cast<uint16_t>(slot);
    if (!append_note_change_(deleted)) {
      send_json_(request, 500, "{\"error\":\"備註刪除失敗，請稍後再試\"}");
      return;
    }
    const std::string employee_label = employees_[slot - 1].active && employees_[slot - 1].name[0] != '\0'
                                           ? employees_[slot - 1].name
                                           : "已刪除員工（槽位 " + std::to_string(slot) + "）";
    last_result_ = "每日備註已刪除：" + date_text + " " + employee_label;
    send_json_(request, 200, "{\"ok\":true}");
    return;
  }

  // An orphaned note must remain deletable after its employee is removed, but
  // new notes and edits still require an active employee.
  if (!employees_[slot - 1].active) {
    send_json_(request, 400, "{\"error\":\"員工已刪除，只能刪除原有備註\"}");
    return;
  }

  if (note_index < 0 && note_count_ >= MAX_DAILY_NOTES) {
    // Capacity is bounded at 5000 active entries. Tombstone the oldest one
    // before appending the new note; both changes are committed directly to Flash.
    uint32_t oldest_date = UINT32_MAX;
    DailyNote oldest{};
    bool found_oldest = false;
    for (size_t index = 0; index < note_count_; index++) {
      DailyNote candidate{};
      if (read_note_(index, &candidate) && candidate.date < oldest_date) {
        oldest_date = candidate.date;
        oldest = candidate;
        found_oldest = true;
      }
    }
    if (!found_oldest) {
      send_json_(request, 500, "{\"error\":\"找不到可用的備註儲存位置\"}");
      return;
    }
    oldest.active = 0;
    oldest.text[0] = '\0';
    if (!append_note_change_(oldest)) {
      send_json_(request, 500, "{\"error\":\"無法覆蓋最舊備註，請稍後再試\"}");
      return;
    }
    ESP_LOGW(TAG, "Daily note capacity reached; overwriting oldest date %u", (unsigned) oldest_date);
  }

  DailyNote updated{};
  updated.date = date;
  updated.employee_id = static_cast<uint16_t>(slot);
  updated.active = 1;
  strlcpy(updated.text, note_text.c_str(), sizeof(updated.text));
  if (!append_note_change_(updated)) {
    send_json_(request, 500, "{\"error\":\"備註保存失敗，請稍後再試\"}");
    return;
  }
  last_result_ = "每日備註已儲存：" + date_text + " " + employees_[slot - 1].name;
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::mutate_employee_(AsyncWebServerRequest *r) {
  if (import_in_progress_) {
    send_json_(r,409,"{\"error\":\"資料還原中，暫時無法修改員工\"}");
    return;
  }
  std::string password=param(r,"password");
  const bool password_valid=!admin_password_.empty()&&secure_equals(password,admin_password_);
  std::fill(password.begin(),password.end(),'\0');
  if(!password_valid) {
    ESP_LOGW(TAG,"Rejected employee add/update request: invalid password");
    send_json_(r,403,"{\"error\":\"管理密碼錯誤，員工資料未變更\"}");
    return;
  }
  int slot=atoi(param(r,"slot").c_str()); std::string code=trim_ascii_space(param(r,"code")), name=param(r,"name"), active=param(r,"active");
  const bool can_open=param(r,"can_open")=="1";
  if(code.empty()||code.size()>16||name.empty()||name.size()>40||employee_code_equal(code,"undefined")||name=="undefined") { send_json_(r,400,"{\"error\":\"請輸入有效的員工編號與姓名\"}"); return; }
  if(slot<1||slot>(int)MAX_EMPLOYEES) { slot=0; for(size_t i=0;i<MAX_EMPLOYEES;i++) if(employee_code_equal(code,employees_[i].code)) { slot=i+1; break; } if(slot==0) for(size_t i=0;i<MAX_EMPLOYEES;i++) if(!employees_[i].name[0]) { slot=i+1; break; } }
  if(slot<1) { send_json_(r,409,"{\"error\":\"員工人數已達 500 人上限\"}"); return; }
  for(size_t i=0;i<MAX_EMPLOYEES;i++) if((int)i!=slot-1 && employee_code_equal(code,employees_[i].code)) { send_json_(r,409,"{\"error\":\"員工工號已存在\"}"); return; }
  auto &e=employees_[slot-1];
  Employee previous=e;
  e.id=slot;
  strlcpy(e.code,code.c_str(),sizeof(e.code));
  strlcpy(e.name,name.c_str(),sizeof(e.name));
  // 保留 voice_name 內的 R307-S 實際模板 ID，修改姓名或權限時不可清除。
  e.can_open_door=can_open ? 1 : 0;
  e.active=active!="0";
  if(!save_employees_()) {
    e=previous;
    send_json_(r,500,"{\"error\":\"員工資料保存失敗，請稍後再試\"}");
    return;
  }
  last_result_="員工資料已儲存："+name;
  send_json_(r,200,"{\"ok\":true}");
}

void AttendanceWebS3::bind_card_manual_(AsyncWebServerRequest *request) {
  if (import_in_progress_ || clear_logs_in_progress_) {
    send_json_(request, 409, "{\"error\":\"裝置正在維護 Flash，暫時無法登記卡片\"}");
    return;
  }
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，卡號未登記\"}");
    return;
  }
  const int slot = atoi(param(request, "slot").c_str());
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || !employees_[slot - 1].active) {
    send_json_(request, 400, "{\"error\":\"找不到這位員工，請重新整理頁面\"}");
    return;
  }
  std::string uid;
  if (!normalize_card_uid(trim_ascii_space(param(request, "uid")), &uid)) {
    send_json_(request, 400, "{\"error\":\"卡號格式不正確，請輸入 4-byte 或 7-byte 十六進位 UID\"}");
    return;
  }
  for (size_t index = 0; index < MAX_EMPLOYEES; index++) {
    if (static_cast<int>(index) != slot - 1 && employees_[index].active && uid == employees_[index].uid) {
      send_json_(request, 409,
                 "{\"error\":\"此卡號已綁定員工 " + esc(employees_[index].code) + "／" +
                     esc(employees_[index].name) + "\"}");
      return;
    }
  }
  const Employee previous = employees_[slot - 1];
  strlcpy(employees_[slot - 1].uid, uid.c_str(), sizeof(Employee::uid));
  if (!save_employees_()) {
    employees_[slot - 1] = previous;
    send_json_(request, 500, "{\"error\":\"卡號寫入 Flash 失敗，原卡號未變更\"}");
    return;
  }
  enroll_employee_ = -1;
  last_result_ = "卡號已手動登記：" + std::string(employees_[slot - 1].name);
  remember_card_result_(uid, employees_[slot - 1].name, "卡片已完成綁定");
  last_card_code_ = employees_[slot - 1].code;
  last_card_display_state_ = "CARD OK";
  queue_tts_phrase_(nullptr, 10);
  restore_mode_color_();
  send_json_(request, 200, "{\"ok\":true,\"uid\":\"" + esc(uid.c_str()) + "\"}");
}

void AttendanceWebS3::delete_employee_(AsyncWebServerRequest *r) {
  if (import_in_progress_) {
    send_json_(r,409,"{\"error\":\"資料還原中，暫時無法刪除員工\"}");
    return;
  }
  std::string password=param(r,"password");
  const bool password_valid=!admin_password_.empty()&&secure_equals(password,admin_password_);
  std::fill(password.begin(),password.end(),'\0');
  if(!password_valid) {
    ESP_LOGW(TAG,"Rejected employee delete request: invalid password");
    send_json_(r,403,"{\"error\":\"管理密碼錯誤，員工未刪除\"}");
    return;
  }
  const int slot=atoi(param(r,"slot").c_str());
  if(slot<1||slot>(int)MAX_EMPLOYEES||!employees_[slot-1].active) {
    send_json_(r,400,"{\"error\":\"員工不存在或已刪除\"}");
    return;
  }
  const Employee previous=employees_[slot-1];
  if (fingerprint_ != nullptr && !fingerprint_->is_failed()) {
    if (previous.finger1_enrolled)
      fingerprint_->delete_fingerprint(stored_fingerprint_template_id_(previous, slot - 1, 1));
    if (previous.finger2_enrolled)
      fingerprint_->delete_fingerprint(stored_fingerprint_template_id_(previous, slot - 1, 2));
  }
  employees_[slot-1]=Employee{};
  employees_[slot-1].id=slot;
  if(!save_employees_()) {
    employees_[slot-1]=previous;
    send_json_(r,500,"{\"error\":\"員工刪除失敗，請稍後再試\"}");
    return;
  }
  last_result_="員工已刪除，原卡片已失效";
  send_json_(r,200,"{\"ok\":true}");
}

void AttendanceWebS3::clear_logs_(AsyncWebServerRequest *request) {
  if (import_in_progress_) {
    send_json_(request, 409, "{\"error\":\"資料還原中，暫時無法清除刷卡紀錄\"}");
    return;
  }
  if (clear_logs_in_progress_) {
    send_json_(request, 409, "{\"error\":\"已有刪除刷卡紀錄工作正在進行\"}");
    return;
  }
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    ESP_LOGW(TAG, "Rejected request to erase attendance logs: invalid password");
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，刷卡紀錄未刪除\"}");
    return;
  }
  if (partition_ == nullptr) {
    send_json_(request, 503, "{\"error\":\"找不到刷卡紀錄分割區\"}");
    return;
  }
  if (log_region_size_ == 0 || log_region_size_ % partition_->erase_size != 0) {
    ESP_LOGE(TAG, "Invalid attendance partition geometry");
    send_json_(request, 500, "{\"error\":\"刷卡紀錄分割區格式錯誤\"}");
    return;
  }
  clear_logs_failed_ = false;
  clear_logs_erase_offset_ = 0;
  last_clear_logs_erase_millis_ = 0;
  clear_logs_in_progress_ = true;
  last_result_ = "正在分批刪除刷卡紀錄";
  ESP_LOGW(TAG, "Attendance log background erase started");
  send_json_(request, 200, "{\"ok\":true,\"started\":true}");
}

void AttendanceWebS3::clear_logs_status_(AsyncWebServerRequest *request) {
  const bool done = !clear_logs_in_progress_ && !clear_logs_failed_ &&
                    clear_logs_erase_offset_ >= log_region_size_ && log_region_size_ > 0;
  std::ostringstream output;
  output << "{\"ok\":true,\"running\":" << (clear_logs_in_progress_ ? "true" : "false")
         << ",\"failed\":" << (clear_logs_failed_ ? "true" : "false")
         << ",\"erased\":" << clear_logs_erase_offset_ << ",\"total\":" << log_region_size_
         << ",\"done\":" << (done ? "true" : "false") << "}";
  send_json_(request, 200, output.str());
}

void AttendanceWebS3::set_attendance_mode_(AsyncWebServerRequest *request) {
  const std::string mode = param(request, "mode");
  if (mode == "in") {
    select_action(true);
  } else if (mode == "out") {
    select_action(false);
  } else if (mode == "overtime_in") {
    select_overtime_action(true);
  } else if (mode == "overtime_out") {
    select_overtime_action(false);
  } else {
    send_json_(request, 400, "{\"error\":\"上下班模式參數不正確\"}");
    return;
  }
  ESP_LOGI(TAG, "Attendance mode remotely changed to %s", mode.c_str());
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::mutate_mode_schedule_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，定時切換設定未變更\"}");
    return;
  }

  const char *keys[4] = {"out", "in", "overtime_in", "overtime_out"};
  ModeScheduleStore updated = mode_schedule_;
  updated.master_enabled = param(request, "enabled") == "1" ? 1 : 0;
  for (uint8_t action = 0; action < 4; action++) {
    const std::string key(keys[action]);
    const std::string enabled_key = key + "_enabled";
    const std::string time_key = key + "_time";
    updated.entry_enabled[action] = param(request, enabled_key.c_str()) == "1" ? 1 : 0;
    const std::string value = param(request, time_key.c_str());
    if (value.size() != 5 || value[2] != ':' || value[0] < '0' || value[0] > '9' ||
        value[1] < '0' || value[1] > '9' || value[3] < '0' || value[3] > '9' ||
        value[4] < '0' || value[4] > '9') {
      send_json_(request, 400, "{\"error\":\"定時切換時間格式不正確\"}");
      return;
    }
    const uint8_t hour = static_cast<uint8_t>((value[0] - '0') * 10 + value[1] - '0');
    const uint8_t minute = static_cast<uint8_t>((value[3] - '0') * 10 + value[4] - '0');
    if (hour >= 24 || minute >= 60) {
      send_json_(request, 400, "{\"error\":\"定時切換時間超出有效範圍\"}");
      return;
    }
    updated.hour[action] = hour;
    updated.minute[action] = minute;
    if (updated.master_enabled && updated.entry_enabled[action]) {
      for (uint8_t previous_action = 0; previous_action < action; previous_action++) {
        if (updated.entry_enabled[previous_action] && updated.hour[previous_action] == hour &&
            updated.minute[previous_action] == minute) {
          send_json_(request, 409, "{\"error\":\"兩個已啟用的模式不能設定在相同時間\"}");
          return;
        }
      }
    }
  }

  const ModeScheduleStore previous = mode_schedule_;
  mode_schedule_ = updated;
  if (!save_mode_schedule_()) {
    mode_schedule_ = previous;
    send_json_(request, 500, "{\"error\":\"定時切換設定保存失敗，原設定未變更\"}");
    return;
  }
  last_schedule_bucket_ = 0;
  update_scheduled_mode_();
  last_result_ = mode_schedule_.master_enabled ? "自動定時切換設定已保存" : "自動定時切換已關閉";
  ESP_LOGI(TAG, "%s", last_result_.c_str());
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::set_manual_time_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，時間未變更\"}");
    return;
  }
  const std::string timestamp_value = param(request, "timestamp");
  char *end = nullptr;
  const int64_t requested_timestamp = strtoll(timestamp_value.c_str(), &end, 10);
  const ESPTime requested_time = ESPTime::from_epoch_local(static_cast<time_t>(requested_timestamp));
  if (timestamp_value.empty() || end == timestamp_value.c_str() || *end != '\0' || requested_timestamp < 1704067200LL ||
      requested_timestamp > 4102444799LL || !requested_time.is_valid()) {
    send_json_(request, 400, "{\"error\":\"手動日期時間格式不正確\"}");
    return;
  }
  struct timeval system_time {};
  system_time.tv_sec = static_cast<time_t>(requested_timestamp);
  if (settimeofday(&system_time, nullptr) != 0) {
    ESP_LOGE(TAG, "Failed to set the ESP32 system clock from the management page");
    send_json_(request, 500, "{\"error\":\"ESP32 系統時間設定失敗\"}");
    return;
  }
  manual_time_base_ = static_cast<time_t>(requested_timestamp);
  manual_time_millis_ = millis();
  manual_time_override_ = true;
  network_time_synced_ = false;
  last_sync_source_ = "管理員手動校時（優先）";
  last_sync_timestamp_ = manual_time_base_;
  const bool hardware_rtc_connected = hardware_rtc_ != nullptr && !hardware_rtc_->is_failed();
  if (hardware_rtc_connected) {
    hardware_rtc_->write_time();
    ESP_LOGI(TAG, "Manual time written to DS3231");
  } else {
    ESP_LOGW(TAG, "Manual time active, but DS3231 is unavailable and could not be updated");
  }
  last_schedule_bucket_ = 0;
  update_scheduled_mode_();
  last_result_ = hardware_rtc_connected ? "手動時間已啟用並保存到備用時鐘"
                                        : "手動時間已啟用，但備用時鐘未連線";
  ESP_LOGW(TAG, "Manual attendance time override enabled");
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::restore_automatic_time_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，校時模式未變更\"}");
    return;
  }
  manual_time_override_ = false;
  last_schedule_bucket_ = 0;
  update_scheduled_mode_();
  last_result_ = "已恢復網路自動校時；完成更新前會沿用目前時間";
  ESP_LOGI(TAG, "Automatic network time restored");
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::change_admin_password_(AsyncWebServerRequest *request) {
#ifndef USE_WEBSERVER_AUTH
  send_json_(request, 503, "{\"error\":\"YAML 尚未啟用 web_server.auth，無法同步修改登入密碼\"}");
  return;
#else
  std::string current_password = param(request, "current_password");
  std::string new_password = param(request, "new_password");
  std::string confirm_password = param(request, "confirm_password");
  const bool current_password_valid =
      !admin_password_.empty() && secure_equals(current_password, admin_password_);
  if (!current_password_valid) {
    std::fill(current_password.begin(), current_password.end(), '\0');
    std::fill(new_password.begin(), new_password.end(), '\0');
    std::fill(confirm_password.begin(), confirm_password.end(), '\0');
    ESP_LOGW(TAG, "Rejected management password change: current password is invalid");
    send_json_(request, 403, "{\"error\":\"目前管理密碼錯誤，密碼未變更\"}");
    return;
  }
  if (!secure_equals(new_password, confirm_password)) {
    std::fill(current_password.begin(), current_password.end(), '\0');
    std::fill(new_password.begin(), new_password.end(), '\0');
    std::fill(confirm_password.begin(), confirm_password.end(), '\0');
    send_json_(request, 400, "{\"error\":\"兩次輸入的新密碼不一致\"}");
    return;
  }
  if (!valid_new_admin_password(new_password)) {
    std::fill(current_password.begin(), current_password.end(), '\0');
    std::fill(new_password.begin(), new_password.end(), '\0');
    std::fill(confirm_password.begin(), confirm_password.end(), '\0');
    send_json_(request, 400,
               "{\"error\":\"新密碼必須為 8～64 個半形英文字母、數字或符號，且不可包含空白\"}");
    return;
  }
  if (secure_equals(new_password, admin_password_)) {
    std::fill(current_password.begin(), current_password.end(), '\0');
    std::fill(new_password.begin(), new_password.end(), '\0');
    std::fill(confirm_password.begin(), confirm_password.end(), '\0');
    send_json_(request, 409, "{\"error\":\"新密碼與目前密碼相同，無需變更\"}");
    return;
  }
  if (!save_admin_password_(new_password)) {
    std::fill(current_password.begin(), current_password.end(), '\0');
    std::fill(new_password.begin(), new_password.end(), '\0');
    std::fill(confirm_password.begin(), confirm_password.end(), '\0');
    ESP_LOGE(TAG, "Unable to save the new management password to preferences");
    send_json_(request, 500, "{\"error\":\"新密碼未能寫入 Flash，原密碼仍然有效\"}");
    return;
  }

  admin_password_ = new_password;
  runtime_admin_password_loaded_ = true;
  apply_web_auth_password_();
  last_result_ = "管理員密碼已修改；請使用新密碼重新登入";
  std::fill(current_password.begin(), current_password.end(), '\0');
  std::fill(new_password.begin(), new_password.end(), '\0');
  std::fill(confirm_password.begin(), confirm_password.end(), '\0');
  ESP_LOGW(TAG, "Management login and operation password changed together");
  send_json_(request, 200, "{\"ok\":true,\"reauthenticate\":true}");
#endif
}

bool AttendanceWebS3::check_import_token_(AsyncWebServerRequest *request) const {
  uint32_t token = 0;
  return import_in_progress_ && parse_uint32_strict(param(request, "token"), &token) && token != 0 &&
         token == import_token_;
}

bool AttendanceWebS3::import_storage_ready_() const {
  return import_note_staging_ready_ && import_note_erase_offset_ >= NOTE_SLOT_SIZE &&
         import_erase_offset_ >= log_region_size_;
}

bool AttendanceWebS3::commit_import_note_bank_() {
  if (!import_note_staging_ready_ || import_note_staging_slot_ < 0 || notes_partition_ == nullptr)
    return false;
  EmployeeStoreHeader header{};
  header.magic = NOTE_MAGIC;
  header.version = NOTE_STORE_VERSION;
  header.generation = import_note_generation_ + 1U;
  header.payload_size = sizeof(NoteJournalRecord);
  header.payload_crc = fnv1a(&header, offsetof(EmployeeStoreHeader, payload_crc));
  const uint32_t offset = note_slot_offset_(static_cast<uint8_t>(import_note_staging_slot_));
  if (esp_partition_write(notes_partition_, offset, &header, sizeof(header)) != ESP_OK)
    return false;
  uint32_t verified_generation = 0;
  if (!validate_note_bank_header_(static_cast<uint8_t>(import_note_staging_slot_), &verified_generation) ||
      verified_generation != header.generation)
    return false;
  note_active_slot_ = import_note_staging_slot_;
  note_generation_ = header.generation;
  return true;
}

void AttendanceWebS3::reset_import_session_(bool reload_persistent_data) {
  import_in_progress_ = false;
  import_token_ = 0;
  import_erase_offset_ = 0;
  import_note_erase_offset_ = 0;
  import_note_staging_slot_ = -1;
  import_note_generation_ = 0;
  import_note_staging_ready_ = false;
  last_import_erase_millis_ = 0;
  import_erase_failed_ = false;
  // An uncommitted note bank has no valid header, and the employee slot was
  // never touched at import-begin. Reloading on loopTask therefore restores
  // the last complete data set after abort, timeout or a browser disconnect.
  if (reload_persistent_data)
    import_reload_pending_ = true;
}

void AttendanceWebS3::begin_backup_import_(AsyncWebServerRequest *request) {
  std::string password = param(request, "password");
  const bool password_valid = !admin_password_.empty() && secure_equals(password, admin_password_);
  std::fill(password.begin(), password.end(), '\0');
  if (!password_valid) {
    ESP_LOGW(TAG, "Rejected backup import: invalid management password");
    send_json_(request, 403, "{\"error\":\"管理密碼錯誤，現有資料未變更\"}");
    return;
  }
  if (partition_ == nullptr || notes_partition_ == nullptr) {
    send_json_(request, 503, "{\"error\":\"資料分割區不完整，無法開始還原\"}");
    return;
  }
  if (clear_logs_in_progress_) {
    send_json_(request, 409, "{\"error\":\"正在刪除刷卡紀錄，完成後才能還原資料\"}");
    return;
  }
  if (import_in_progress_ || import_reload_pending_) {
    send_json_(request, 409, "{\"error\":\"已有資料還原工作正在進行，請稍後重試\"}");
    return;
  }

  import_in_progress_ = true;
  import_token_ = 0;
  enroll_employee_ = -1;
  fingerprint_enroll_employee_ = -1;
  fingerprint_enroll_number_ = 0;
  import_note_staging_slot_ = note_active_slot_ == 0 ? 1 : 0;
  import_note_generation_ = note_generation_;
  import_note_erase_offset_ = 0;
  import_note_staging_ready_ = false;
  employees_.fill(Employee{});
  for (size_t index = 0; index < employees_.size(); index++)
    employees_[index].id = static_cast<uint16_t>(index + 1);
  // Do not commit an empty employee table here. The previous firmware did so,
  // which made all employees disappear if the watchdog reset mid-restore.
  // Employees and the note-bank header are committed only by import-finish.
  import_erase_offset_ = 0;
  last_import_erase_millis_ = 0;
  import_erase_failed_ = false;
  imported_employee_count_ = 0;
  imported_note_count_ = 0;
  imported_log_count_ = 0;
  last_import_timestamp_ = 0;
  import_token_ = esp_random();
  if (import_token_ == 0)
    import_token_ = 1;
  last_import_millis_ = millis();
  last_result_ = "正在準備安全還原區；原員工資料尚未覆蓋";
  ESP_LOGW(TAG, "Transactional backup import started; employee data remain committed until finish");
  send_json_(request, 200, "{\"ok\":true,\"token\":" + std::to_string(import_token_) + "}");
}

void AttendanceWebS3::erase_backup_import_chunk_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  if (import_erase_failed_) {
    send_json_(request, 500, "{\"error\":\"清除原刷卡紀錄區失敗，請查看裝置日誌\"}");
    return;
  }
  last_import_millis_ = millis();
  const uint32_t erased = import_note_erase_offset_ + import_erase_offset_;
  const uint32_t total = NOTE_SLOT_SIZE + log_region_size_;
  const bool done = import_storage_ready_();
  std::ostringstream output;
  output << "{\"ok\":true,\"erased\":" << erased << ",\"total\":" << total
         << ",\"done\":" << (done ? "true" : "false") << "}";
  send_json_(request, 200, output.str());
}

void AttendanceWebS3::import_employee_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  if (!import_storage_ready_()) {
    send_json_(request, 409, "{\"error\":\"Flash 還原區尚未準備完成\"}");
    return;
  }
  const int slot = atoi(param(request, "slot").c_str());
  const std::string code = trim_ascii_space(param(request, "code"));
  const std::string name = param(request, "name");
  const std::string uid = param(request, "uid");
  const bool can_open = param(request, "can_open") == "1";
  // Early backup formats did not carry the two mapping flags. R307-S templates
  // survive independently in the sensor, and their IDs are deterministic from
  // the employee slot, so retain both possible mappings for those old backups.
  // A nonexistent template can never produce a match; current backups continue
  // to restore their exact per-finger flags.
  const bool has_fingerprint_metadata = param(request, "fingerprint_metadata") == "1";
  const bool finger1 = has_fingerprint_metadata ? param(request, "finger1") == "1" : true;
  const bool finger2 = has_fingerprint_metadata ? param(request, "finger2") == "1" : true;
  const int finger1_id = atoi(param(request, "finger1_id").c_str());
  const int finger2_id = atoi(param(request, "finger2_id").c_str());
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || code.empty() || code.size() > 16 ||
      name.empty() || name.size() > 40 || uid.size() > 24 || employee_code_equal(code, "undefined") ||
      name == "undefined") {
    send_json_(request, 400, "{\"error\":\"備份中的員工資料格式不正確\"}");
    return;
  }
  for (size_t index = 0; index < employees_.size(); index++) {
    if (static_cast<int>(index) == slot - 1 || !employees_[index].active)
      continue;
    if (employee_code_equal(code, employees_[index].code)) {
      send_json_(request, 409, "{\"error\":\"備份內含重複工號\"}");
      return;
    }
    if (!uid.empty() && uid == employees_[index].uid) {
      send_json_(request, 409, "{\"error\":\"備份內含重複卡號\"}");
      return;
    }
  }
  Employee &employee = employees_[slot - 1];
  const bool was_active = employee.active;
  employee = Employee{};
  employee.id = static_cast<uint16_t>(slot);
  employee.active = 1;
  strlcpy(employee.code, code.c_str(), sizeof(employee.code));
  strlcpy(employee.name, name.c_str(), sizeof(employee.name));
  strlcpy(employee.uid, uid.c_str(), sizeof(employee.uid));
  employee.can_open_door = can_open ? 1 : 0;
  employee.finger1_enrolled = finger1 ? 1 : 0;
  employee.finger2_enrolled = finger2 ? 1 : 0;
  store_fingerprint_template_id_(employee, 1,
      finger1_id >= 1 && finger1_id <= 1000 ? static_cast<uint16_t>(finger1_id) :
                                               fingerprint_template_id_(slot - 1, 1));
  store_fingerprint_template_id_(employee, 2,
      finger2_id >= 1 && finger2_id <= 1000 ? static_cast<uint16_t>(finger2_id) :
                                               fingerprint_template_id_(slot - 1, 2));
  if (!was_active)
    imported_employee_count_++;
  last_import_millis_ = millis();
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::import_note_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  if (!import_storage_ready_()) {
    send_json_(request, 409, "{\"error\":\"Flash 還原區尚未準備完成\"}");
    return;
  }
  const int slot = atoi(param(request, "slot").c_str());
  const std::string date_text = param(request, "date");
  const std::string note_text = param(request, "note");
  uint32_t date = 0;
  if (slot < 1 || slot > static_cast<int>(MAX_EMPLOYEES) || !parse_date_value(date_text, &date) ||
      note_text.empty() || note_text.size() >= sizeof(DailyNote{}.text) || utf8_character_count(note_text) > 15) {
    send_json_(request, 400, "{\"error\":\"備份中的每日備註格式不正確\"}");
    return;
  }
  const bool was_active = find_note_index_(static_cast<uint16_t>(slot), date) >= 0;
  if (!was_active && note_count_ >= MAX_DAILY_NOTES) {
    send_json_(request, 409, "{\"error\":\"備份中的每日備註超過 5000 筆\"}");
    return;
  }
  DailyNote note{};
  note.date = date;
  note.employee_id = static_cast<uint16_t>(slot);
  note.active = 1;
  strlcpy(note.text, note_text.c_str(), sizeof(note.text));
  if (!append_note_change_(note)) {
    send_json_(request, 500, "{\"error\":\"每日備註寫入 Flash 失敗，請重新開始匯入\"}");
    return;
  }
  if (!was_active)
    imported_note_count_++;
  last_import_millis_ = millis();
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::import_log_batch_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  if (!import_storage_ready_()) {
    send_json_(request, 409, "{\"error\":\"Flash 還原區尚未準備完成\"}");
    return;
  }
  const std::string records = param(request, "records");
  if (records.empty() || records.size() > 8192) {
    send_json_(request, 400, "{\"error\":\"刷卡紀錄批次大小不正確\"}");
    return;
  }
  struct ImportLogValue {
    uint32_t timestamp;
    uint16_t employee_id;
    uint8_t action;
    uint32_t uid_hash;
    bool manual;
  };
  std::array<ImportLogValue, 64> values{};
  size_t value_count = 0;
  size_t cursor = 0;
  uint32_t previous_timestamp = last_import_timestamp_;
  while (cursor < records.size()) {
    const size_t line_end = records.find(';', cursor);
    const size_t end = line_end == std::string::npos ? records.size() : line_end;
    const std::string line = records.substr(cursor, end - cursor);
    cursor = line_end == std::string::npos ? records.size() : line_end + 1;
    if (line.empty())
      continue;
    if (value_count >= values.size()) {
      send_json_(request, 400, "{\"error\":\"每批最多匯入 64 筆刷卡紀錄\"}");
      return;
    }
    std::array<std::string, 5> fields{};
    size_t field_start = 0;
    bool field_error = false;
    for (size_t field = 0; field < fields.size(); field++) {
      const size_t separator = line.find(',', field_start);
      if (field < fields.size() - 1 && separator == std::string::npos) {
        field_error = true;
        break;
      }
      if (field == fields.size() - 1 && separator != std::string::npos) {
        field_error = true;
        break;
      }
      const size_t field_end = separator == std::string::npos ? line.size() : separator;
      fields[field] = line.substr(field_start, field_end - field_start);
      field_start = field_end + 1;
    }
    uint32_t timestamp = 0;
    uint32_t employee_id = 0;
    uint32_t action = 0;
    uint32_t uid_hash = 0;
    uint32_t manual = 0;
    if (field_error || !parse_uint32_strict(fields[0], &timestamp) ||
        !parse_uint32_strict(fields[1], &employee_id) || !parse_uint32_strict(fields[2], &action) ||
        !parse_uint32_strict(fields[3], &uid_hash) || !parse_uint32_strict(fields[4], &manual) || manual > 1 ||
        timestamp < 1577836800U || timestamp > 4102444799U ||
        employee_id < 1 || employee_id > MAX_EMPLOYEES || action > ACTION_OVERTIME_OUT ||
        timestamp < previous_timestamp) {
      send_json_(request, 400, "{\"error\":\"備份中的刷卡紀錄格式或時間順序不正確\"}");
      return;
    }
    values[value_count++] = ImportLogValue{timestamp, static_cast<uint16_t>(employee_id),
                                           static_cast<uint8_t>(action), uid_hash, manual != 0};
    previous_timestamp = timestamp;
  }
  const uint32_t capacity = log_region_size_ / sizeof(LogRecord);
  if (value_count == 0 || imported_log_count_ + value_count > capacity) {
    send_json_(request, 409, "{\"error\":\"備份中的刷卡紀錄超過裝置容量\"}");
    return;
  }
  for (size_t index = 0; index < value_count; index++) {
    const auto &value = values[index];
    if (!append_log_(value.employee_id, value.action, value.uid_hash, value.timestamp, value.manual)) {
      send_json_(request, 500, "{\"error\":\"刷卡紀錄寫入 Flash 失敗，請重新開始匯入\"}");
      return;
    }
    imported_log_count_++;
    last_import_timestamp_ = value.timestamp;
  }
  last_import_millis_ = millis();
  send_json_(request, 200, "{\"ok\":true,\"imported\":" + std::to_string(imported_log_count_) + "}");
}

void AttendanceWebS3::finish_backup_import_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  if (!import_storage_ready_()) {
    send_json_(request, 409, "{\"error\":\"Flash 還原區尚未準備完成\"}");
    return;
  }
  if (!save_employees_()) {
    send_json_(request, 500, "{\"error\":\"員工資料未能完成寫入，請再次按匯入重試\"}");
    return;
  }
  if (!commit_import_note_bank_()) {
    send_json_(request, 500, "{\"error\":\"備註資料未能完成提交；員工資料已安全保存，請保留備份檔後重試\"}");
    return;
  }
  last_result_ = "備份還原完成：" + std::to_string(imported_employee_count_) + " 位員工、" +
                 std::to_string(imported_note_count_) + " 筆備註、" + std::to_string(imported_log_count_) +
                 " 筆刷卡紀錄";
  ESP_LOGW(TAG, "%s", last_result_.c_str());
  std::ostringstream output;
  output << "{\"ok\":true,\"employees\":" << imported_employee_count_ << ",\"notes\":"
         << imported_note_count_ << ",\"logs\":" << imported_log_count_ << "}";
  reset_import_session_(false);
  send_json_(request, 200, output.str());
}

void AttendanceWebS3::abort_backup_import_(AsyncWebServerRequest *request) {
  if (!check_import_token_(request)) {
    send_json_(request, 403, "{\"error\":\"資料還原工作階段無效或已逾時\"}");
    return;
  }
  reset_import_session_(true);
  last_result_ = "資料還原已中止；可重新選擇備份檔匯入";
  ESP_LOGW(TAG, "Backup import aborted");
  send_json_(request, 200, "{\"ok\":true}");
}

void AttendanceWebS3::serve_export_data_(AsyncWebServerRequest *req) {
  constexpr uint16_t PAGE_SIZE = 100;
  const uint32_t offset = strtoul(param(req, "offset").c_str(), nullptr, 10);
  const uint32_t cutoff = cutoff_timestamp_();
  const uint32_t slots = std::min<uint32_t>(log_record_count_, log_region_size_ / sizeof(LogRecord));
  uint32_t scanned = std::min(offset, slots);
  uint16_t added = 0;
  bool has_more = false;
  bool first = true;
  LogRecord record{};
  std::ostringstream output;
  output << "{\"logs\":[";

  for (uint32_t n = scanned; n < slots; n++) {
    if ((n & 127U) == 0U) {
      feed_watchdog_if_registered();
      yield();
    }
    const uint32_t distance = (n + 1) * sizeof(record);
    const uint32_t record_offset =
        (write_offset_ + log_region_size_ - (distance % log_region_size_)) % log_region_size_;
    if (esp_partition_read(partition_, record_offset, &record, sizeof(record)) != ESP_OK)
      break;
    scanned = n + 1;
    if (record.magic != LOG_MAGIC || record.crc != fnv1a(&record, sizeof(record) - 4) || record.timestamp < cutoff)
      continue;

    const Employee *employee = nullptr;
    for (auto &candidate : employees_) {
      if (candidate.id == record.employee_id) {
        employee = &candidate;
        break;
      }
    }
    time_t timestamp = record.timestamp;
    struct tm time_info {};
    localtime_r(&timestamp, &time_info);
    char formatted_time[24];
    strftime(formatted_time, sizeof(formatted_time), "%Y-%m-%d %H:%M:%S", &time_info);
    if (!first)
      output << ",";
    first = false;
    output << "{\"time\":\"" << formatted_time << "\",\"timestamp\":" << record.timestamp
           << ",\"employee_id\":" << record.employee_id
           << ",\"id\":\"" << esc(employee ? employee->code : "") << "\",\"name\":\""
           << esc(employee ? employee->name : "") << "\",\"action\":\"" << action_label(record.action)
           << "\",\"action_code\":" << static_cast<unsigned>(record.action)
           << ",\"uid_hash\":" << record.uid_hash
           << ",\"manual\":" << (record.reserved == 1 ? "true" : "false") << "}";
    added++;
    if (added >= PAGE_SIZE) {
      has_more = scanned < slots;
      break;
    }
  }

  output << "],\"next\":" << scanned << ",\"total\":" << slots
         << ",\"done\":" << (has_more ? "false" : "true") << "}";
  send_json_(req, 200, output.str());
}

void AttendanceWebS3::serve_export_launcher_(AsyncWebServerRequest *request) {
  static const char EXPORT_PAGE[] PROGMEM = R"HTML(
<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>產生 Excel 出勤彙總表</title>
<style>body{font:16px system-ui;background:#f3f5f7;color:#17202a;max-width:680px;margin:60px auto;padding:20px}.box{background:#fff;border-radius:14px;padding:24px;box-shadow:0 2px 12px #0001}a{color:#1769e0}</style>
<div class="box"><h2>正在產生 Excel 出勤彙總表</h2><p id="state">正在讀取刷卡資料，請不要關閉此頁面……</p><p><a href="/attendance/">返回管理頁</a></p></div>
<script>
const te=new TextEncoder();
const xmlEscape=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const le=(n,b)=>{const a=new Uint8Array(b);for(let i=0;i<b;i++)a[i]=(n>>>8*i)&255;return a};
const concat=a=>{let n=a.reduce((s,x)=>s+x.length,0),o=new Uint8Array(n),p=0;for(const x of a){o.set(x,p);p+=x.length}return o};
const crcTable=(()=>{let t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?0xedb88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
const crc32=d=>{let c=0xffffffff;for(const b of d)c=crcTable[(c^b)&255]^(c>>>8);return(c^0xffffffff)>>>0};
function makeZip(files){
  const local=[],central=[];let offset=0;
  for(const f of files){const name=te.encode(f.name),data=typeof f.data==='string'?te.encode(f.data):f.data,crc=crc32(data),flag=0x0800;
    const lh=concat([le(0x04034b50,4),le(20,2),le(flag,2),le(0,2),le(0,2),le(0x21,2),le(crc,4),le(data.length,4),le(data.length,4),le(name.length,2),le(0,2),name]);
    local.push(lh,data);
    central.push(concat([le(0x02014b50,4),le(20,2),le(20,2),le(flag,2),le(0,2),le(0,2),le(0x21,2),le(crc,4),le(data.length,4),le(data.length,4),le(name.length,2),le(0,2),le(0,2),le(0,2),le(0,2),le(0,4),le(offset,4),name]));
    offset+=lh.length+data.length;
  }
  const cd=concat(central),end=concat([le(0x06054b50,4),le(0,2),le(0,2),le(files.length,2),le(files.length,2),le(cd.length,4),le(offset,4),le(0,2)]);
  return new Blob([...local,cd,end],{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
}
const columns=['A','B','C','D','E','F','G','H','I','J','K'];
const headers=['日期','工號','姓名','上班打卡時間','下班打卡時間','加班上班時間','加班下班時間','備註','當日出勤工時','當日加班工時','補登來源'];
const cell=(ref,value,style='')=>`<c r="${ref}" t="inlineStr"${style}><is><t xml:space="preserve">${xmlEscape(value)}</t></is></c>`;
const durationCell=(ref,value)=>value===null?cell(ref,''):`<c r="${ref}" s="2"><v>${value}</v></c>`;
const durationValue=(start,end)=>{if(!start||!end)return null;const parse=value=>{const parts=String(value).split(':').map(Number);return parts.length>=2&&parts.every(Number.isFinite)?parts[0]*60+parts[1]+(parts[2]||0)/60:null},from=parse(start),to=parse(end);if(from===null||to===null)return null;let minutes=to-from;if(minutes<0)minutes+=24*60;return minutes/(24*60)};
function worksheet(rows){let x=['<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="13" customWidth="1"/><col min="2" max="3" width="18" customWidth="1"/><col min="4" max="7" width="20" customWidth="1"/><col min="8" max="8" width="24" customWidth="1"/><col min="9" max="10" width="18" customWidth="1"/><col min="11" max="11" width="24" customWidth="1"/></cols><sheetData><row r="1">'];
  headers.forEach((v,i)=>x.push(cell(columns[i]+'1',v,' s="1"')));x.push('</row>');let rn=2;
  for(const r of rows){x.push(`<row r="${rn}">`);[r.date,r.id,r.name,r.clockIn,r.clockOut,r.overtimeIn,r.overtimeOut,r.note].forEach((v,i)=>x.push(cell(columns[i]+rn,v)));x.push(durationCell('I'+rn,durationValue(r.clockIn,r.clockOut)),durationCell('J'+rn,durationValue(r.overtimeIn,r.overtimeOut)),cell('K'+rn,r.manualActions||''),'</row>');rn++}
  x.push('</sheetData></worksheet>');return x.join('');
}
function uniqueSheetName(code,employeeName,used){let base=((code||'未設定')+'_'+(employeeName||'未命名')).replace(/[\\\/?*:[\]]/g,'_').replace(/^'+|'+$/g,'').slice(0,31)||'員工',name=base,n=2,key=name.toLowerCase();while(used.has(key)){const s='_'+n++;name=base.slice(0,31-s.length)+s;key=name.toLowerCase()}used.add(key);return name}
async function getJson(url){const r=await fetch(url,{cache:'no-store'});if(!r.ok)throw Error('讀取失敗：HTTP '+r.status);return r.json()}
async function getAllNotes(){const notes=[];let offset=0;while(true){const batch=await getJson('/attendance/api/notes?paged=1&limit=50&offset='+offset);notes.push(...batch.notes);if(batch.done)break;if(batch.next<=offset)throw Error('備註分頁資料異常');offset=batch.next}return notes}
async function run(){try{
  const active=await getJson('/attendance/api/employees'),notes=await getAllNotes(),logs=[];let offset=0,page=0;
  while(true){state.textContent=`正在讀取第 ${++page} 批刷卡資料……`;const p=await getJson('/attendance/api/export-page?offset='+offset);logs.push(...p.logs);if(p.done)break;if(p.next<=offset)throw Error('分頁資料異常');offset=p.next}
  state.textContent='正在彙整每日上下班與加班時間……';
  const employees=new Map();for(const e of active)employees.set(e.id||('未設定-'+e.slot),{id:e.id||('未設定-'+e.slot),name:e.name,days:new Map()});
  for(const l of logs){const id=l.id||('未設定-'+l.employee_id),date=l.time.slice(0,10),time=l.time.slice(11,19);if(!employees.has(id))employees.set(id,{id,name:l.name||'',days:new Map()});const e=employees.get(id);if(!e.name&&l.name)e.name=l.name;let d=e.days.get(date);if(!d){d={date,id:e.id,name:e.name,clockIn:'',clockOut:'',overtimeIn:'',overtimeOut:'',note:'',manualActions:''};e.days.set(date,d)}d.name=e.name;if(l.action==='上班'&&(!d.clockIn||time<d.clockIn))d.clockIn=time;if(l.action==='下班'&&(!d.clockOut||time>d.clockOut))d.clockOut=time;if(l.action==='加班上班'&&(!d.overtimeIn||time<d.overtimeIn))d.overtimeIn=time;if(l.action==='加班下班'&&(!d.overtimeOut||time>d.overtimeOut))d.overtimeOut=time;if(l.manual&&!d.manualActions.includes(l.action))d.manualActions+=(d.manualActions?'、':'')+l.action}
  for(const n of notes){const id=n.id||('未設定-'+n.slot);if(!employees.has(id))employees.set(id,{id,name:n.name||'',days:new Map()});const e=employees.get(id);if(!e.name&&n.name)e.name=n.name;let d=e.days.get(n.date);if(!d){d={date:n.date,id:e.id,name:e.name,clockIn:'',clockOut:'',overtimeIn:'',overtimeOut:'',note:'',manualActions:''};e.days.set(n.date,d)}d.name=e.name;d.note=n.note||''}
  const list=[...employees.values()].sort((a,b)=>a.id.localeCompare(b.id,'zh-Hant',{numeric:true}));const summary=[];for(const e of list)summary.push(...e.days.values());summary.sort((a,b)=>a.date.localeCompare(b.date)||a.id.localeCompare(b.id,'zh-Hant',{numeric:true}));
  const used=new Set(['出勤彙總'.toLowerCase()]),sheets=[{name:'出勤彙總',rows:summary}];for(const e of list)sheets.push({name:uniqueSheetName(e.id,e.name,used),rows:[...e.days.values()].sort((a,b)=>a.date.localeCompare(b.date))});
  state.textContent=`正在建立 ${sheets.length} 個 Excel 分頁……`;
  const files=[],sheetOverrides=[];sheets.forEach((s,i)=>{files.push({name:`xl/worksheets/sheet${i+1}.xml`,data:worksheet(s.rows)});sheetOverrides.push(`<Override PartName="/xl/worksheets/sheet${i+1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`)});
  files.push({name:'[Content_Types].xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>${sheetOverrides.join('')}</Types>`});
  files.push({name:'_rels/.rels',data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'});
  files.push({name:'xl/workbook.xml',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>${sheets.map((s,i)=>`<sheet name="${xmlEscape(s.name)}" sheetId="${i+1}" r:id="rId${i+1}"/>`).join('')}</sheets></workbook>`});
  files.push({name:'xl/_rels/workbook.xml.rels',data:`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">${sheets.map((s,i)=>`<Relationship Id="rId${i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i+1}.xml"/>`).join('')}<Relationship Id="rId${sheets.length+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>`});
  files.push({name:'xl/styles.xml',data:'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="[h]:mm"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="3"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'});
  const blob=makeZip(files),url=URL.createObjectURL(blob),now=new Date(),date=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`,a=document.createElement('a');a.href=url;a.download=`nfc-attendance-s3-summary-${date}.xlsx`;a.click();setTimeout(()=>URL.revokeObjectURL(url),30000);state.textContent=`完成：共 ${summary.length} 筆每日彙總、${sheets.length} 個分頁。若未自動下載，請返回後再按一次。`;
}catch(e){state.textContent='產生失敗：'+e.message}}
run();
</script></html>
)HTML";
  auto *response = request->beginResponse(200, "text/html; charset=utf-8",
                                          reinterpret_cast<const uint8_t *>(EXPORT_PAGE), sizeof(EXPORT_PAGE) - 1);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

void AttendanceWebS3::serve_csv_launcher_(AsyncWebServerRequest *request) {
  static const char CSV_PAGE[] PROGMEM = R"CSVHTML(
<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>建立刷卡紀錄 CSV</title><style>body{font:16px system-ui;margin:32px;background:#f5f7fa;color:#1f2937}.card{max-width:720px;margin:auto;background:white;padding:24px;border-radius:14px;box-shadow:0 4px 18px #0001}a{color:#1463d6}</style>
<div class="card"><h2>正在建立 CSV</h2><p id="state">正在分批讀取刷卡紀錄……</p><p><a href="/attendance/">返回管理後台</a></p></div>
<script>
const state=document.getElementById('state');
const quote=value=>'"'+String(value??'').replaceAll('"','""')+'"';
async function getJson(url){const response=await fetch(url,{cache:'no-store'}),text=await response.text();let data;try{data=JSON.parse(text)}catch(e){throw Error(`裝置回傳非 JSON（HTTP ${response.status}）：${text.slice(0,80)}`)}if(!response.ok)throw Error(data.error||`HTTP ${response.status}`);return data}
async function run(){try{
  const notes=new Map();let noteOffset=0;while(true){const batch=await getJson('/attendance/api/notes?paged=1&limit=100&offset='+noteOffset);for(const note of batch.notes)notes.set(`${note.slot}|${note.date}`,note.note||'');if(batch.done)break;if(batch.next<=noteOffset)throw Error('備註分頁資料異常');noteOffset=batch.next}
  const rows=['時間,員工編號,姓名,狀態,來源,備註\r\n'];let offset=0,page=0;
  while(true){state.textContent=`正在讀取第 ${++page} 批刷卡紀錄……`;const batch=await getJson('/attendance/api/export-page?offset='+offset);for(const log of batch.logs){const date=String(log.time||'').slice(0,10),note=notes.get(`${log.employee_id}|${date}`)||'';rows.push([log.time,log.id,log.name,log.action,log.manual?'管理員補登':'裝置打卡',note].map(quote).join(',')+'\r\n')}if(batch.done)break;if(batch.next<=offset)throw Error('刷卡紀錄分頁資料異常');offset=batch.next}
  const blob=new Blob(['\ufeff',...rows],{type:'text/csv;charset=utf-8'}),url=URL.createObjectURL(blob),now=new Date(),date=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`,link=document.createElement('a');link.href=url;link.download=`nfc-attendance-s3-records-${date}.csv`;link.click();setTimeout(()=>URL.revokeObjectURL(url),30000);state.textContent=`完成：共 ${rows.length-1} 筆刷卡紀錄。若未自動下載，請返回後再按一次。`;
}catch(error){state.textContent='產生失敗：'+error.message}}
run();
</script></html>
)CSVHTML";
  auto *response = request->beginResponse(200, "text/html; charset=utf-8",
                                          reinterpret_cast<const uint8_t *>(CSV_PAGE), sizeof(CSV_PAGE) - 1);
  response->addHeader("Cache-Control", "no-store");
  request->send(response);
}

void AttendanceWebS3::serve_logs_(AsyncWebServerRequest *req) {
  uint32_t cutoff=cutoff_timestamp_(); std::ostringstream o; LogRecord x{};
  const uint32_t slots=std::min<uint32_t>(log_record_count_,log_region_size_/sizeof(x));
  o<<"["; bool first=true; uint16_t found=0;
  for(uint32_t n=0;n<slots && found<100;n++) {
    if ((n & 127U) == 0U) { feed_watchdog_if_registered(); yield(); }
    uint32_t distance=(n+1)*sizeof(x);
    uint32_t off=(write_offset_+log_region_size_-(distance%log_region_size_))%log_region_size_;
    if(esp_partition_read(partition_,off,&x,sizeof(x))!=ESP_OK) break;
    if(x.magic!=LOG_MAGIC||x.crc!=fnv1a(&x,sizeof(x)-4)||x.timestamp<cutoff) continue;
    const Employee *e=nullptr; for(auto &q:employees_) if(q.id==x.employee_id){e=&q;break;}
    time_t tt=x.timestamp; struct tm tmv{}; localtime_r(&tt,&tmv); char ts[24]; strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",&tmv);
    if (!first)
      o << ",";
    first = false;
    found++;
    o<<"{\"time\":\""<<ts<<"\",\"slot\":"<<x.employee_id<<",\"id\":\""<<esc(e?e->code:"")<<"\",\"name\":\""<<esc(e?e->name:"")<<"\",\"action\":\""<<action_label(x.action)<<"\",\"manual\":"<<(x.reserved==1?"true":"false")<<"}";
  }
  o<<"]"; send_json_(req,200,o.str());
}

void AttendanceWebS3::serve_page_(AsyncWebServerRequest *r) {
  static const char PAGE[] PROGMEM = R"HTML(
<!doctype html><html lang="zh-Hant"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NFC 打卡鐘管理中心</title>
<style>.stat-filters{display:flex;gap:8px;flex-wrap:wrap;align-items:end}.stat-filters label{display:grid;gap:4px;color:#687386;font-size:13px}.stat-grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin:14px 0}.stat-box{background:#f6f8fb;border:1px solid #e3e8ee;border-radius:10px;padding:12px}.stat-box span{display:block;color:#687386;font-size:12px}.stat-box b{display:block;font-size:22px;margin-top:5px}.mini{padding:6px 8px;font-size:12px}.finger-actions{display:flex;gap:5px;flex-wrap:wrap}@media(max-width:780px){.stat-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}@media(max-width:520px){.stat-filters label,.stat-filters input,.stat-filters select{width:100%;max-width:none}.stat-grid{grid-template-columns:1fr 1fr}}</style>
<style>.schedule-master{display:flex;gap:8px;align-items:center;margin:8px 0 14px}.schedule-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.schedule-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:center;border:1px solid #e3e8ee;border-radius:10px;padding:10px}.schedule-row label{display:flex;gap:7px;align-items:center}.schedule-row input[type=time]{max-width:125px}@media(max-width:600px){.schedule-grid{grid-template-columns:1fr}.schedule-row input[type=time]{width:125px}}</style>
<style>body{font:15px system-ui;background:#f3f5f7;margin:auto;max-width:1080px;padding:18px;color:#17202a}h1{margin:4px 0 6px}h2{margin-top:0}.subtitle{color:#687386;margin-bottom:14px}.tabs{position:sticky;top:0;z-index:5;display:flex;gap:7px;overflow:auto;padding:9px;background:#f3f5f7;border-bottom:1px solid #dfe4ea}.tab-button{white-space:nowrap;background:white;color:#314154;border:1px solid #dce2e8}.tab-button.active{background:#1769e0;color:white;border-color:#1769e0}.tab-page{display:none}.tab-page.active{display:block}.card{background:white;border-radius:14px;padding:16px;margin:12px 0;box-shadow:0 2px 12px #0001}.device-status{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-top:14px}.device-status>div{min-width:0;background:#f6f8fb;border:1px solid #e3e8ee;border-radius:10px;padding:11px}.device-status span{display:block;color:#687386;font-size:13px;margin-bottom:5px}.device-status b{display:block;overflow-wrap:anywhere}.device-status .mode-panel{grid-column:span 2}.mode-actions,.employee-form,.password-form,.backup-form,.toolbar{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.mode-actions{margin-top:8px}.mode-actions button{padding:7px 10px}.mode-help{margin-top:8px;color:#687386;font-size:12px}.online{color:#138a45}.offline{color:#c62828}.manual{color:#1769e0}.overtime-in-text{color:#b77900}.overtime-out-text{color:#1769e0}button,a.btn{border:0;border-radius:8px;padding:9px 13px;background:#1769e0;color:white;text-decoration:none;cursor:pointer}.clock-in{background:#138a45}.clock-out,.danger{background:#c62828}.overtime-in{background:#d99200}.overtime-out{background:#1769e0}.secondary{background:#687386}button:disabled{opacity:.55;cursor:wait}input,select{padding:9px;border:1px solid #ccd2da;border-radius:8px;max-width:230px;background:white}.search{min-width:260px}.employee-form,.password-form,.backup-form{margin-bottom:8px}.backup-form input[type=file]{max-width:300px}.note-form{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.note-form input[type=text]{min-width:230px}dialog{border:0;border-radius:14px;padding:22px;max-width:390px;color:#17202a;box-shadow:0 10px 40px #0005}dialog::backdrop{background:#0008}dialog h3{margin-top:0}dialog input{box-sizing:border-box;width:100%;max-width:none;margin:7px 0 14px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #eee}.muted{color:#687386}.scroll{overflow:auto}.pager{display:flex;justify-content:center;align-items:center;gap:10px;margin-top:13px}.guide{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.guide>div{min-width:0;border:1px solid #e3e8ee;border-radius:10px;padding:12px}.guide h3{margin:0 0 9px}.guide p{margin:7px 0}.compact-form{display:grid;gap:8px;min-width:0}.compact-form input,.compact-form select{box-sizing:border-box;width:100%;max-width:none;min-width:0}.compact-actions{display:flex;gap:7px;flex-wrap:wrap}.dot{display:inline-block;width:12px;height:12px;border-radius:50%;margin-right:7px;vertical-align:-1px}.green{background:#18a558}.red{background:#e53935}.blue{background:#1769e0}.yellow{background:#fbc02d}.orange{background:#ff7a00}.rainbow{background:conic-gradient(#f00,#ff7a00,#ff0,#0b0,#0cc,#06f,#a0f,#f00)}.off{background:#777}code{background:#eef2f6;border-radius:5px;padding:2px 5px;word-break:break-all}details{border:1px solid #e3e8ee;border-radius:10px;padding:12px;margin-top:12px}summary{cursor:pointer;font-weight:700}@media(max-width:780px){.device-status{grid-template-columns:repeat(2,minmax(0,1fr))}.device-status .mode-panel{grid-column:span 2}.guide{grid-template-columns:1fr}}@media(max-width:520px){body{padding:10px}.tabs{margin:0 -10px}.device-status{grid-template-columns:1fr}.device-status .mode-panel{grid-column:span 1}.employee-form input,.password-form input,.backup-form input,.search{box-sizing:border-box;width:100%;max-width:none;min-width:0}}</style>
<h1>NFC 打卡鐘管理中心</h1><div class="subtitle">員工、打卡紀錄與系統設定</div>
<nav class="tabs" aria-label="管理功能"><button class="tab-button active" data-tab="dashboard" onclick="showTab('dashboard')">總覽</button><button class="tab-button" data-tab="records" onclick="showTab('records')">打卡紀錄</button><button class="tab-button" data-tab="statistics" onclick="showTab('statistics')">統計分析</button><button class="tab-button" data-tab="employees" onclick="showTab('employees')">員工管理</button><button class="tab-button" data-tab="notes" onclick="showTab('notes')">請假／備註</button><button class="tab-button" data-tab="settings" onclick="showTab('settings')">系統設定</button><button class="tab-button" data-tab="help" onclick="showTab('help')">使用說明</button></nav>
<main>
<section id="tab-dashboard" class="tab-page active"><div class="card"><b id="status">正在讀取打卡鐘狀態…</b><div class="muted">最多可管理 500 位員工（每人兩枚指紋），打卡資料保存最近兩個日曆月。</div><div class="device-status"><div><span>打卡鐘時間</span><b id="current_time">讀取中…</b></div><div><span>時間設定方式</span><b id="time_source">讀取中…</b></div><div><span>備用時鐘</span><b id="hardware_rtc_status">讀取中…</b></div><div><span>網路狀態</span><b id="network_status">讀取中…</b></div><div><span>Wi-Fi 名稱</span><b id="wifi_ssid">讀取中…</b></div><div><span>IP 位址</span><b id="ip_address">讀取中…</b></div><div><span>指紋感測器</span><b id="fingerprint_status">讀取中…</b></div><div><span>感測器內指紋</span><b id="fingerprint_count">讀取中…</b></div><div><span>員工對應指紋</span><b id="fingerprint_mapped_count">讀取中…</b></div><div><span>內部 RAM 剩餘</span><b id="internal_heap">讀取中…</b></div><div><span>備註 Flash 日誌</span><b id="note_journal">讀取中…</b></div><div><span>員工容量</span><b id="employee_storage">讀取中…</b></div><div><span>備註容量</span><b id="note_storage">讀取中…</b></div><div><span>打卡紀錄容量</span><b id="log_storage">讀取中…</b></div><div class="mode-panel"><span>目前打卡模式</span><b id="mode_display">讀取中…</b><div class="mode-actions"><button id="clock_in_mode_button" class="clock-in" onclick="setAttendanceMode('in')">上班</button><button id="clock_out_mode_button" class="clock-out" onclick="setAttendanceMode('out')">下班</button><button id="overtime_in_mode_button" class="overtime-in" onclick="setAttendanceMode('overtime_in')">加班上班</button><button id="overtime_out_mode_button" class="overtime-out" onclick="setAttendanceMode('overtime_out')">加班下班</button></div><div class="mode-help">可隨時手動切換；自動切換時間可在「系統設定」中啟用、停用及修改。</div></div></div><p><button onclick="remoteUnlock()">遠端開門 1 秒</button></p></div><div class="card"><h2>近期打卡</h2><p class="muted">顯示最近 10 筆成功保存的紀錄；完整資料請前往「打卡紀錄」。</p><div class="scroll"><table><thead><tr><th>時間</th><th>員工編號</th><th>姓名</th><th>打卡類型</th></tr></thead><tbody id="dashboard_logs"><tr><td colspan="4">讀取中…</td></tr></tbody></table></div></div></section>
<section id="tab-records" class="tab-page"><div class="card"><h2>打卡紀錄</h2><div class="toolbar"><input id="records_search" class="search" placeholder="搜尋日期、工號、姓名或打卡類型" oninput="logPage=1;renderLogs()"><a class="btn" href="/attendance/export.xlsx">下載兩個月 Excel 彙總表</a><a class="btn secondary" href="/attendance/export.csv">下載兩個月 CSV 紀錄</a></div><p class="muted">近期 100 筆紀錄以每頁 20 筆顯示；Excel 與 CSV 均包含裝置內保存的完整兩個月資料。</p><div class="scroll"><table><thead><tr><th>時間</th><th>員工編號</th><th>姓名</th><th>打卡類型</th><th>當日備註</th></tr></thead><tbody id="logs"><tr><td colspan="5">切換到本頁後自動讀取…</td></tr></tbody></table></div><div class="pager"><button class="secondary" onclick="changeLogPage(-1)">上一頁</button><span id="logs_page_info">第 1 頁</span><button class="secondary" onclick="changeLogPage(1)">下一頁</button></div></div></section>
<section id="tab-statistics" class="tab-page"><div class="card"><h2>出勤統計</h2><div class="stat-filters"><label>開始日期<input id="stats_from" type="date"></label><label>結束日期<input id="stats_to" type="date"></label><label>員工<select id="stats_employee"><option value="">全部員工</option></select></label><button id="stats_button" onclick="loadStatistics()">重新彙整</button></div><div class="stat-grid"><div class="stat-box"><span>有出勤員工</span><b id="stat_people">—</b></div><div class="stat-box"><span>出勤人日</span><b id="stat_days">—</b></div><div class="stat-box"><span>正常工時</span><b id="stat_regular">—</b></div><div class="stat-box"><span>加班工時</span><b id="stat_overtime">—</b></div><div class="stat-box"><span>缺少成對打卡</span><b id="stat_missing">—</b></div><div class="stat-box"><span>備註筆數</span><b id="stat_notes">—</b></div></div><p id="stats_status" class="muted">選擇日期後按「重新彙整」，資料直接由打卡鐘完整兩個月紀錄統計。</p><div class="scroll"><table><thead><tr><th>員工編號</th><th>姓名</th><th>出勤日</th><th>正常工時</th><th>加班工時</th><th>缺少打卡</th><th>備註</th></tr></thead><tbody id="stats_rows"><tr><td colspan="7">尚未彙整</td></tr></tbody></table></div></div></section>
<section id="tab-employees" class="tab-page"><div class="card"><h2>員工管理</h2><div class="employee-form"><input id="employee_code" maxlength="16" placeholder="員工編號，例如 JFE-001"><input id="employee_name" maxlength="40" placeholder="員工姓名"><label><input id="employee_can_open" type="checkbox" checked> 允許開門</label><input id="employee_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><button onclick="saveEmployee()">新增／更新員工</button></div><p class="muted">每位員工可登記 NFC 卡與兩枚指紋；語音會直接播報員工編號。新增、刪除、卡片及指紋操作均需管理員密碼。</p><div class="toolbar"><input id="employee_search" class="search" placeholder="搜尋工號、姓名或卡號" oninput="employeePage=1;renderEmployees()"><span id="employee_count" class="muted"></span></div><div class="scroll"><table><thead><tr><th>員工編號</th><th>姓名</th><th>NFC 卡</th><th>指紋</th><th>開門</th><th></th></tr></thead><tbody id="employees"><tr><td colspan="6">切換到本頁後自動讀取…</td></tr></tbody></table></div><div class="pager"><button class="secondary" onclick="changeEmployeePage(-1)">上一頁</button><span id="employees_page_info">第 1 頁</span><button class="secondary" onclick="changeEmployeePage(1)">下一頁</button></div></div></section>
<section id="tab-notes" class="tab-page"><div class="card"><h2>每日請假／備註</h2><p class="muted">由管理員手動記錄事假、病假或其他說明；每筆最多 15 個字，最多保存 5000 筆。</p><div class="note-form"><input id="note_date" type="date"><select id="note_employee"><option value="">選擇員工</option></select><input id="note_text" type="text" maxlength="15" placeholder="例如：事假、病假、特休"><button id="save_note_button" onclick="saveDailyNote()">儲存備註</button></div><div class="toolbar"><input id="notes_search" class="search" placeholder="搜尋日期、工號、姓名或備註" oninput="notePage=1;renderNotes()"><span id="notes_count" class="muted"></span></div><div class="scroll"><table><thead><tr><th>日期</th><th>員工編號</th><th>姓名</th><th>備註</th><th></th></tr></thead><tbody id="notes"><tr><td colspan="5">切換到本頁後自動讀取…</td></tr></tbody></table></div><div class="pager"><button class="secondary" onclick="changeNotePage(-1)">上一頁</button><span id="notes_page_info">第 1 頁</span><button class="secondary" onclick="changeNotePage(1)">下一頁</button></div></div></section>
<section id="tab-settings" class="tab-page"><div class="card"><h2>時間設定</h2><div class="guide"><div><h3>自動校時方式</h3><p>開機時先使用備用時鐘，網路恢復後會自動校正時間。</p><p>管理員手動設定後，本次開機期間會以手動時間為準；重新開機後恢復網路自動校時。</p></div><div><h3>管理員手動校時</h3><div class="compact-form"><input id="manual_time" type="datetime-local" step="1"><input id="time_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><div class="compact-actions"><button id="set_manual_time_button" onclick="setManualTime()">使用手動時間</button><button id="restore_auto_time_button" class="secondary" onclick="restoreAutomaticTime()">恢復網路校時</button></div></div><p class="muted">手動時間會同步保存到備用時鐘，斷電期間仍能繼續走時。</p></div></div></div><div class="card"><h2>打卡模式定時切換</h2><label class="schedule-master"><input id="auto_mode_enabled" type="checkbox" onchange="updateScheduleControls()"> 啟用自動定時切換</label><div class="schedule-grid"><div class="schedule-row"><label><input id="schedule_in_enabled" type="checkbox" onchange="updateScheduleControls()"> 上班</label><input id="schedule_in_time" type="time" value="00:00"></div><div class="schedule-row"><label><input id="schedule_out_enabled" type="checkbox" onchange="updateScheduleControls()"> 下班</label><input id="schedule_out_time" type="time" value="14:00"></div><div class="schedule-row"><label><input id="schedule_overtime_in_enabled" type="checkbox" onchange="updateScheduleControls()"> 加班上班</label><input id="schedule_overtime_in_time" type="time" value="17:30"></div><div class="schedule-row"><label><input id="schedule_overtime_out_enabled" type="checkbox" onchange="updateScheduleControls()"> 加班下班</label><input id="schedule_overtime_out_time" type="time" value="20:00"></div></div><div class="password-form" style="margin-top:12px"><input id="schedule_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><button id="save_schedule_button" onclick="saveModeSchedule()">儲存定時設定</button></div><p id="schedule_status" class="muted">關閉總開關後不會自動切換；四種模式也可個別停用。手動切換永遠可用。</p></div><div class="card"><h2>管理員補打卡</h2><p>可補登目前時間以前、最近兩個日曆月內的上班、下班與加班紀錄。</p><div class="compact-form"><select id="manual_attendance_employee"><option value="">選擇員工</option></select><input id="manual_attendance_time" type="datetime-local" step="1"><select id="manual_attendance_action"><option value="1">上班</option><option value="0">下班</option><option value="2">加班上班</option><option value="3">加班下班</option></select><input id="manual_attendance_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><div><button id="manual_attendance_button" onclick="addManualAttendance()">新增補打卡</button></div></div><p class="muted">補登會標記為「管理員補登」，只新增 Flash 出勤紀錄，不會播報語音、亮成功燈或開門。</p></div><div class="card"><h2>管理員密碼</h2><div class="password-form"><input id="current_admin_password" type="password" autocomplete="current-password" placeholder="目前管理員密碼"><input id="new_admin_password" type="password" autocomplete="new-password" minlength="8" maxlength="64" placeholder="新密碼（8～64 字元）"><input id="confirm_admin_password" type="password" autocomplete="new-password" minlength="8" maxlength="64" placeholder="再次輸入新密碼"><button id="change_admin_password_button" onclick="changeAdminPassword()">修改管理員密碼</button></div><p class="muted">管理頁登入與所有需要核實身分的操作使用同一組密碼；帳號固定為 <code>admin</code>。</p></div><div class="card"><h2>資料備份與還原</h2><p><button id="export_backup_button" onclick="exportBackup()">匯出完整備份</button></p><div class="backup-form"><input id="backup_file" type="file" accept="application/json,.json"><input id="backup_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><button id="import_backup_button" class="danger" onclick="importBackup()">匯入並取代現有資料</button></div><p id="backup_status" class="muted">備份包含員工、卡片、指紋模板 ID 對應、每日備註及刷卡紀錄；不包含 R307-S 內的模板本體、管理員密碼或 Wi-Fi 密碼。</p><p class="muted">匯入會分批清除 Flash 並顯示進度，再以備份內容取代現有資料；進度完成前請勿關閉頁面或斷電。</p></div><div class="card"><h2>指紋傳感器維護</h2><p>永久清空 R307-S 傳感器內的全部指紋模板，並同步清除所有員工的指紋 ID 對應。</p><button id="clear_fingerprints_button" class="danger" onclick="clearAllFingerprints()">清空全部指紋</button><p class="muted">不會刪除員工、NFC 卡號、打卡紀錄或備註。JSON 備份只有 ID 對應，無法還原指紋模板本體。</p></div><div class="card"><h2>清除刷卡紀錄</h2><p>永久刪除裝置內所有刷卡紀錄，不會刪除員工與每日備註。</p><button id="clear_logs_button" class="danger" onclick="clearAllLogs()">刪除所有刷卡紀錄</button><p class="muted">建議先下載 Excel 或匯出完整備份。刪除前必須再次輸入管理員密碼。</p></div></section>
<section id="tab-help" class="tab-page"><div class="card"><h2>燈號、畫面與語音</h2><div class="guide"><div><h3>燈號</h3><p><span class="dot green"></span><b>綠燈：</b>上班模式。</p><p><span class="dot red"></span><b>紅燈：</b>下班模式。</p><p><span class="dot yellow"></span><b>黃燈：</b>加班上班模式。</p><p><span class="dot blue"></span><b>藍燈：</b>加班下班模式。</p><p><span class="dot rainbow"></span><b>七彩循環：</b>正在登記卡片或指紋。</p><p><span class="dot orange"></span><b>橘燈閃爍：</b>Wi-Fi 離線；備用時鐘正常時仍可打卡。</p></div><div><h3>單片 OLED</h3><p>SSD1315 顯示目前時間、打卡模式、員工編號與成功／失敗狀態。</p><p>本版固定一片螢幕：GPIO8 SDA、GPIO9 SCL、位址 <code>0x3C</code>，與 DS3231 共用 I²C。</p></div><div><h3>NFC 與指紋</h3><p>PN532 為主要打卡方式；R307-S 為選配指紋模組，未安裝時不影響其他功能。</p><p>總覽會顯示感測器內實際模板數量與員工對應數量；兩者不同時請檢查最近的備份還原或指紋刪除操作。</p><p>登記指紋時依 OLED 提示，將同一根手指完整按壓兩次。</p></div><div><h3>後台網址</h3><p><a href="http://nfc-attendance-clock.local/attendance/"><code>http://nfc-attendance-clock.local/attendance/</code></a></p><p>電腦或手機需與打卡鐘位於同一網路；固定名稱無法開啟時改用總覽顯示的 IP。</p></div></div><details><summary>進階設備資訊</summary><p>軟體版本：v2.1.8｜主控：XTJ ESP32-S3 N16R8｜PSRAM 完全停用。</p><p>5000 筆每日備註採 Flash 雙區日誌保存；RAM 僅保留小型索引，新增、刪除與還原均不配置 PSRAM。</p></details></div></section>
</main>
<dialog id="clear_logs_dialog" onclose="document.getElementById('clear_logs_password').value=''"><h3>確認刪除紀錄</h3><p>請重新輸入管理員密碼。核實成功後，裝置會分批永久刪除所有刷卡紀錄。</p><input id="clear_logs_password" type="password" autocomplete="current-password" placeholder="管理員密碼" onkeydown="if(event.key==='Enter'){event.preventDefault();confirmClearLogs()}"><p id="clear_logs_status" class="muted"></p><div><button id="confirm_clear_logs_button" class="danger" onclick="confirmClearLogs()">確認永久刪除</button> <button id="cancel_clear_logs_button" class="secondary" onclick="closeClearLogsDialog()">取消</button></div></dialog>
<dialog id="clear_fingerprints_dialog" onclose="document.getElementById('clear_fingerprints_password').value='';document.getElementById('clear_fingerprints_confirmation').value=''"><h3>確認清空全部指紋</h3><p>此操作無法復原。請輸入管理員密碼，並在下方完整輸入「清空全部指紋」。</p><input id="clear_fingerprints_password" type="password" autocomplete="current-password" placeholder="管理員密碼"><input id="clear_fingerprints_confirmation" autocomplete="off" placeholder="輸入：清空全部指紋"><p id="clear_fingerprints_status" class="muted"></p><div><button id="confirm_clear_fingerprints_button" class="danger" onclick="confirmClearAllFingerprints()">確認永久清空</button> <button id="cancel_clear_fingerprints_button" class="secondary" onclick="closeClearFingerprintsDialog()">取消</button></div></dialog>
<script>
const element=id=>document.getElementById(id);
const html=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const storageSize=value=>{const bytes=Math.max(0,Number(value)||0);return bytes>=1048576?(bytes/1048576).toFixed(2)+' MB':Math.round(bytes/1024)+' KB'};
const json=async(url,options)=>{
  const response=await fetch(url,{cache:'no-store',...options}),text=await response.text();let value={};
  if(text){try{value=JSON.parse(text)}catch(error){throw Error(`${url} 回傳 HTTP ${response.status}：${text.slice(0,160)}`)}}
  if(!response.ok)throw Error(value.error||`${url} 回傳 HTTP ${response.status}`);return value;
};
const PAGE_SIZE=20;
let currentTab='dashboard',employeesCache=[],notesCache=[],logsCache=[],scheduleLoaded=false,lastUnmappedFingerprintId=0,liveRefreshBusy=false;
let employeePage=1,notePage=1,logPage=1;
const pageCount=items=>Math.max(1,Math.ceil(items.length/PAGE_SIZE));
const pageSlice=(items,page)=>items.slice((page-1)*PAGE_SIZE,page*PAGE_SIZE);
function consumerTimeSource(value){
  const text=String(value||'');
  if(text.includes('手動'))return '管理員手動設定';
  if(text.includes('SNTP')||text.includes('網路'))return '網路自動校正';
  if(text.includes('DS3231'))return '備用時鐘';
  return text||'等待時間準備完成';
}
function showTab(tab){
  if(!element('tab-'+tab))tab='dashboard';
  currentTab=tab;
  document.querySelectorAll('.tab-page').forEach(page=>page.classList.toggle('active',page.id==='tab-'+tab));
  document.querySelectorAll('.tab-button').forEach(button=>button.classList.toggle('active',button.dataset.tab===tab));
  history.replaceState(null,'','#'+tab);
  load();
}
async function loadStatus(){
  const status=await json('/attendance/api/status');
  element('status').textContent=status.result+'｜目前模式：'+status.mode+(status.enrolling?'｜請將新卡靠近感應區':'')+(status.time_valid?'':'｜時間尚未準備完成');
  const modeDisplay=element('mode_display');
  modeDisplay.textContent=status.mode||'未設定';
  modeDisplay.className=status.mode==='上班'?'online':(status.mode==='下班'?'offline':(status.mode==='加班上班'?'overtime-in-text':(status.mode==='加班下班'?'overtime-out-text':'')));
  element('current_time').textContent=status.current_time||'尚未準備完成';
  element('time_source').textContent=consumerTimeSource(status.time_source);
  element('time_source').className=status.manual_time_override?'manual':(status.time_valid?'online':'offline');
  const hardwareRtcStatus=element('hardware_rtc_status');
  hardwareRtcStatus.textContent=status.hardware_rtc_connected?'運作正常':'未偵測到';
  hardwareRtcStatus.className=status.hardware_rtc_connected?'online':'offline';
  const manualTimeInput=element('manual_time');
  if(status.time_valid&&document.activeElement!==manualTimeInput)manualTimeInput.value=(status.current_time||'').replace(' ','T');
  const attendanceTimeInput=element('manual_attendance_time');
  if(status.time_valid&&attendanceTimeInput){
    const current=(status.current_time||'').replace(' ','T');
    attendanceTimeInput.max=current;
    const cutoff=new Date(current),day=cutoff.getDate();cutoff.setDate(1);cutoff.setMonth(cutoff.getMonth()-2);cutoff.setDate(Math.min(day,new Date(cutoff.getFullYear(),cutoff.getMonth()+1,0).getDate()));cutoff.setHours(0,0,0,0);
    const local=new Date(cutoff.getTime()-cutoff.getTimezoneOffset()*60000).toISOString().slice(0,19);
    attendanceTimeInput.min=local;
    if(!attendanceTimeInput.value)attendanceTimeInput.value=current;
  }
  const noteDateInput=element('note_date');
  if(status.time_valid&&!noteDateInput.value)noteDateInput.value=(status.current_time||'').slice(0,10);
  if(status.time_valid&&!element('stats_to').value){const today=(status.current_time||'').slice(0,10);element('stats_to').value=today;element('stats_from').value=today.slice(0,8)+'01'}
  const networkStatus=element('network_status');
  networkStatus.textContent=status.network_connected?'連線正常':'目前離線';
  networkStatus.className=status.network_connected?'online':'offline';
  element('wifi_ssid').textContent=status.wifi_ssid||'未連線';
  element('ip_address').textContent=status.ip_address||'尚未取得';
  const fingerprintStatus=element('fingerprint_status');fingerprintStatus.textContent=status.fingerprint_connected?'連線正常（狀態碼 '+status.fingerprint_status+'）':'未連線或尚未回報';fingerprintStatus.className=status.fingerprint_connected?'online':'offline';
  element('fingerprint_count').textContent=status.fingerprint_count>=0?`${status.fingerprint_count}／${status.fingerprint_capacity>=0?status.fingerprint_capacity:'未知'}`:'尚未回報';
  const mapped=Number(status.fingerprint_mapped_count||0),actual=Number(status.fingerprint_count);element('fingerprint_mapped_count').textContent=String(mapped)+(actual>=0&&actual!==mapped?'（與感測器不同）':'');
  lastUnmappedFingerprintId=Number(status.last_unmapped_fingerprint_id||0);
  element('internal_heap').textContent=storageSize(status.free_internal_heap);
  element('note_journal').textContent=`${status.note_journal_used||0}／${status.note_journal_capacity||0} 筆寫入`; 
  element('employee_storage').textContent=`${status.employee_count||0}／${status.employee_capacity||500}（剩 ${Math.max(0,(status.employee_capacity||500)-(status.employee_count||0))}）`;
  element('note_storage').textContent=status.note_capacity>0?`${status.note_count||0}／${status.note_capacity}（剩 ${Math.max(0,status.note_capacity-(status.note_count||0))}）`:'備註 Flash 尚未準備完成';
  element('log_storage').textContent=`${status.log_count||0}／${status.log_capacity||0}（剩 ${Math.max(0,(status.log_capacity||0)-(status.log_count||0))}）`;
  if(!scheduleLoaded&&status.mode_schedule){
    element('auto_mode_enabled').checked=Boolean(status.auto_mode_enabled);
    for(const key of ['in','out','overtime_in','overtime_out']){
      const setting=status.mode_schedule[key]||{};
      element(`schedule_${key}_enabled`).checked=Boolean(setting.enabled);
      element(`schedule_${key}_time`).value=setting.time||'00:00';
    }
    scheduleLoaded=true;updateScheduleControls();
  }
  return status;
}
function updateNoteEmployeeOptions(){
  const noteEmployee=element('note_employee'),selectedEmployee=noteEmployee.value,statsEmployee=element('stats_employee'),selectedStats=statsEmployee.value,manualEmployee=element('manual_attendance_employee'),selectedManual=manualEmployee?manualEmployee.value:'';
  noteEmployee.innerHTML='<option value="">選擇員工</option>'+employeesCache.map(employee=>`<option value="${employee.slot}">${html(employee.id)}｜${html(employee.name)}</option>`).join('');
  if(employeesCache.some(employee=>String(employee.slot)===selectedEmployee))noteEmployee.value=selectedEmployee;
  statsEmployee.innerHTML='<option value="">全部員工</option>'+employeesCache.map(employee=>`<option value="${employee.slot}">${html(employee.id)}｜${html(employee.name)}</option>`).join('');
  if(employeesCache.some(employee=>String(employee.slot)===selectedStats))statsEmployee.value=selectedStats;
  if(manualEmployee){manualEmployee.innerHTML='<option value="">選擇員工</option>'+employeesCache.map(employee=>`<option value="${employee.slot}">${html(employee.id)}｜${html(employee.name)}</option>`).join('');if(employeesCache.some(employee=>String(employee.slot)===selectedManual))manualEmployee.value=selectedManual}
}
async function loadEmployees(){
  employeesCache=await json('/attendance/api/employees');
  employeesCache.sort((a,b)=>String(a.id).localeCompare(String(b.id),'zh-Hant',{numeric:true}));
  updateNoteEmployeeOptions();
  renderEmployees();
}
async function readAllNotes(includeAll=false,progress=null){
  const notes=[];let offset=0,page=0;
  while(true){
    if(progress)progress.textContent=`正在讀取第 ${++page} 批每日備註……`;
    const batch=await json(`/attendance/api/notes?paged=1&limit=50&offset=${offset}${includeAll?'&all=1':''}`);
    notes.push(...batch.notes);
    if(batch.done)break;
    if(batch.next<=offset)throw Error('備註分頁資料異常');
    offset=batch.next;
  }
  return notes;
}
async function loadNotes(){
  notesCache=await readAllNotes(false);
  notesCache.sort((a,b)=>b.date.localeCompare(a.date)||String(a.id).localeCompare(String(b.id),'zh-Hant',{numeric:true}));
  renderNotes();
}
async function loadLogs(){
  logsCache=await json('/attendance/api/logs');
  logsCache.sort((a,b)=>b.time.localeCompare(a.time));
  renderDashboardLogs();
  renderLogs();
}
function renderDashboardLogs(){
  const rows=logsCache.slice(0,10);
  element('dashboard_logs').innerHTML=rows.length?rows.map(log=>`<tr><td>${html(log.time)}</td><td>${html(log.id||'未設定')}</td><td>${html(log.name||'未知員工')}</td><td>${html(log.action)}${log.manual?'（管理員補登）':''}</td></tr>`).join(''):'<tr><td colspan="4">尚無成功保存的刷卡紀錄</td></tr>';
}
function renderEmployees(){
  const query=element('employee_search').value.trim().toLocaleLowerCase(),filtered=employeesCache.filter(employee=>[employee.id,employee.name,employee.uid].some(value=>String(value||'').toLocaleLowerCase().includes(query))),pages=pageCount(filtered);
  employeePage=Math.min(employeePage,pages);const rows=pageSlice(filtered,employeePage);
  element('employee_count').textContent=`共 ${filtered.length} 位員工`;
  element('employees_page_info').textContent=`第 ${employeePage}／${pages} 頁`;
  element('employees').innerHTML=rows.length?rows.map(employee=>`<tr><td>${html(employee.id)}</td><td>${html(employee.name)}</td><td>${html(employee.uid||'尚未登記')}<br><button class="mini" onclick="enroll(${employee.slot},this)">感應登記</button> <button class="mini secondary" onclick="manualBindCard(${employee.slot})">手動輸入</button></td><td><div class="finger-actions"><button class="mini ${employee.finger1?'secondary':''}" onclick="enrollFingerprint(${employee.slot},1)">指紋1 ${employee.finger1?'ID '+employee.finger1_id:'登記'}</button>${employee.finger1?`<button class="mini danger" onclick="deleteFingerprint(${employee.slot},1)">刪1</button>`:''}<button class="mini secondary" onclick="bindFingerprint(${employee.slot},1)">綁ID</button><button class="mini ${employee.finger2?'secondary':''}" onclick="enrollFingerprint(${employee.slot},2)">指紋2 ${employee.finger2?'ID '+employee.finger2_id:'登記'}</button>${employee.finger2?`<button class="mini danger" onclick="deleteFingerprint(${employee.slot},2)">刪2</button>`:''}<button class="mini secondary" onclick="bindFingerprint(${employee.slot},2)">綁ID</button></div></td><td>${employee.can_open?'允許':'不允許'}</td><td><button class="danger" onclick="removeEmployee(${employee.slot})">刪除</button></td></tr>`).join(''):'<tr><td colspan="6">沒有符合條件的員工</td></tr>';
}
function renderNotes(){
  const query=element('notes_search').value.trim().toLocaleLowerCase(),filtered=notesCache.filter(note=>[note.date,note.id,note.name,note.note].some(value=>String(value||'').toLocaleLowerCase().includes(query))),pages=pageCount(filtered);
  notePage=Math.min(notePage,pages);const rows=pageSlice(filtered,notePage);
  element('notes_count').textContent=`共 ${filtered.length} 筆備註`;
  element('notes_page_info').textContent=`第 ${notePage}／${pages} 頁`;
  element('notes').innerHTML=rows.length?rows.map(note=>`<tr><td>${html(note.date)}</td><td>${html(note.id||'—')}</td><td>${html(note.name)}</td><td>${html(note.note)}</td><td><button class="secondary" onclick="editDailyNote(${note.slot},'${note.date}','${encodeURIComponent(note.note)}')">修改</button> <button class="danger" onclick="deleteDailyNote(${note.slot},'${note.date}')">刪除</button></td></tr>`).join(''):'<tr><td colspan="5">沒有符合條件的備註</td></tr>';
}
function renderLogs(){
  const searchElement=element('records_search');
  if(!searchElement)return;
  const query=searchElement.value.trim().toLocaleLowerCase(),filtered=logsCache.filter(log=>[log.time,log.id,log.name,log.action].some(value=>String(value||'').toLocaleLowerCase().includes(query))),pages=pageCount(filtered),noteMap=new Map(notesCache.map(note=>[note.date+'|'+note.slot,note.note]));
  logPage=Math.min(logPage,pages);const rows=pageSlice(filtered,logPage);
  element('logs_page_info').textContent=`第 ${logPage}／${pages} 頁，共 ${filtered.length} 筆`;
  element('logs').innerHTML=rows.length?rows.map(log=>`<tr><td>${html(log.time)}</td><td>${html(log.id||'未設定')}</td><td>${html(log.name||'未知員工')}</td><td>${html(log.action)}${log.manual?'（管理員補登）':''}</td><td>${html(noteMap.get(log.time.slice(0,10)+'|'+log.slot)||'')}</td></tr>`).join(''):'<tr><td colspan="5">沒有符合條件的刷卡紀錄</td></tr>';
}
function changeEmployeePage(step){employeePage=Math.max(1,employeePage+step);renderEmployees()}
function changeNotePage(step){notePage=Math.max(1,notePage+step);renderNotes()}
function changeLogPage(step){logPage=Math.max(1,logPage+step);renderLogs()}
async function loadActiveTab(){
  if(currentTab==='dashboard')await loadLogs();
  else if(currentTab==='records'){await Promise.all([loadLogs(),loadNotes()]);renderLogs()}
  else if(currentTab==='statistics')await loadStatistics();
  else if(currentTab==='employees')await loadEmployees();
  else if(currentTab==='notes')await Promise.all([loadEmployees(),loadNotes()]);
  else if(currentTab==='settings')await loadEmployees();
}
async function load(){
  try{await loadStatus();await loadActiveTab()}
  catch(error){element('status').textContent='資料讀取失敗，請確認打卡鐘連線後重試：'+error.message}
}
async function setAttendanceMode(mode){
  const modes={in:{label:'上班',button:'clock_in_mode_button'},out:{label:'下班',button:'clock_out_mode_button'},overtime_in:{label:'加班上班',button:'overtime_in_mode_button'},overtime_out:{label:'加班下班',button:'overtime_out_mode_button'}};
  const selected=modes[mode];if(!selected)return;
  if(!confirm(`確定切換為${selected.label}模式？接下來所有員工都會刷${selected.label}卡。`))return;
  const button=element(selected.button);button.disabled=true;
  try{
    const body=new URLSearchParams({mode});
    await json('/attendance/api/mode',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    await load();
  }catch(error){alert(error.message)}finally{button.disabled=false}
}
async function remoteUnlock(){
  const password=prompt('請輸入管理員密碼以開門 1 秒：');if(password===null||!password)return;
  try{await postForm('/attendance/api/unlock',{password});alert('已送出開門指令。')}catch(error){alert(error.message)}
}
async function saveEmployee(){
  const codeInput=element('employee_code'),nameInput=element('employee_name'),passwordInput=element('employee_password');
  const codeValue=codeInput.value.trim(),nameValue=nameInput.value.trim(),password=passwordInput.value;
  if(!codeValue||!nameValue){alert('請輸入員工編號與姓名');return}
  if(!password){alert('請輸入管理頁密碼');passwordInput.focus();return}
  try{
    const body=new URLSearchParams({slot:'0',code:codeValue,name:nameValue,can_open:element('employee_can_open').checked?'1':'0',active:'1',password});
    await json('/attendance/api/employee',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    codeInput.value='';nameInput.value='';passwordInput.value='';await load();
  }catch(error){passwordInput.value='';alert(error.message);passwordInput.focus()}
}
async function enroll(slot,button){
  const password=element('employee_password').value;if(!password){alert('請先輸入管理員密碼');return}
  const originalText=button?button.textContent:'登記卡片';if(button){button.disabled=true;button.textContent='等待刷卡…'}
  try{
    await json('/attendance/api/enroll?slot='+slot+'&password='+encodeURIComponent(password));
    let status=await loadStatus();
    while(status.enrolling){await new Promise(resolve=>setTimeout(resolve,600));status=await loadStatus()}
    await loadEmployees();
    alert(status.result||'卡片已登記');
  }catch(error){alert(error.message)}
  finally{if(button&&button.isConnected){button.disabled=false;button.textContent=originalText}}
}
async function manualBindCard(slot){
  const password=element('employee_password').value;if(!password){alert('請先輸入管理員密碼');element('employee_password').focus();return}
  const employee=employeesCache.find(item=>Number(item.slot)===Number(slot));if(!employee){alert('找不到這位員工，請重新整理頁面');return}
  const value=prompt(`請輸入 ${employee.id}／${employee.name} 的 NFC 卡號：\n可使用連字號、冒號、空格或連續十六進位格式。`,employee.uid||'');
  if(value===null)return;const uid=value.trim();if(!uid){alert('卡號不可空白');return}
  if(employee.uid&&uid.toUpperCase()!==String(employee.uid).toUpperCase()&&!confirm(`這會將原卡號 ${employee.uid} 改為 ${uid}，確定繼續？`))return;
  try{
    const result=await postForm('/attendance/api/card-bind',{slot:String(slot),uid,password});
    await loadEmployees();await loadStatus();
    alert(`卡片已登記：${result.uid}`);
  }catch(error){alert(error.message)}
}
async function enrollFingerprint(slot,finger){
  const password=element('employee_password').value;if(!password){alert('請先輸入管理員密碼');return}
  if(!confirm(`即將登記指紋${finger}，請依 OLED 提示將同一根手指按壓兩次。`))return;
  try{const body=new URLSearchParams({slot:String(slot),finger:String(finger),password});const result=await json('/attendance/api/fingerprint-enroll',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});alert(result.message||'指紋登記已開始');await load()}catch(error){alert(error.message)}
}
async function deleteFingerprint(slot,finger){
  const password=element('employee_password').value;if(!password){alert('請先輸入管理員密碼');return}if(!confirm(`確定刪除指紋${finger}？`))return;
  try{const body=new URLSearchParams({slot:String(slot),finger:String(finger),password});await json('/attendance/api/fingerprint-delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});await load()}catch(error){alert(error.message)}
}
async function bindFingerprint(slot,finger){
  const password=element('employee_password').value;if(!password){alert('請先輸入管理員密碼');return}
  const suggested=lastUnmappedFingerprintId>0?String(lastUnmappedFingerprintId):'';
  const value=prompt('先用舊指紋按壓感測器一次，再輸入畫面顯示的未綁定模板 ID：',suggested);if(value===null)return;
  const templateId=Number(value);if(!Number.isInteger(templateId)||templateId<1||templateId>1000){alert('模板 ID 必須是 1～1000');return}
  try{await postForm('/attendance/api/fingerprint-bind',{slot:String(slot),finger:String(finger),template_id:String(templateId),password});await load();alert('指紋模板 ID 已重新綁定。')}
  catch(error){alert(error.message)}
}
async function removeEmployee(slot){
  const passwordInput=element('employee_password'),password=passwordInput.value;
  if(!password){alert('請先在員工管理區輸入管理頁密碼');passwordInput.focus();return}
  if(!confirm('確定刪除這位員工？原卡片將立即失效。'))return;
  try{
    const body=new URLSearchParams({slot:String(slot),password});
    await json('/attendance/api/delete',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    passwordInput.value='';await load();
  }catch(error){passwordInput.value='';alert(error.message);passwordInput.focus()}
}
async function saveDailyNote(){
  const date=element('note_date').value,slot=element('note_employee').value,note=element('note_text').value.trim();
  if(!date||!slot){alert('請選擇日期與員工');return}if(!note){alert('請輸入備註內容');return}if([...note].length>15){alert('備註最多 15 個字');return}
  const button=element('save_note_button');button.disabled=true;
  try{const body=new URLSearchParams({date,slot,note});await json('/attendance/api/note',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});element('note_text').value='';await load()}catch(error){alert(error.message)}finally{button.disabled=false}
}
function editDailyNote(slot,date,note){element('note_date').value=date;element('note_employee').value=String(slot);element('note_text').value=decodeURIComponent(note);element('note_text').focus();scrollTo({top:element('note_date').getBoundingClientRect().top+scrollY-100,behavior:'smooth'})}
async function deleteDailyNote(slot,date){if(!confirm('確定刪除這筆每日備註？'))return;try{const body=new URLSearchParams({date,slot,note:''});await json('/attendance/api/note',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});await load()}catch(error){alert(error.message)}}
function updateScheduleControls(){
  const master=element('auto_mode_enabled').checked;
  for(const key of ['in','out','overtime_in','overtime_out']){
    const enabled=element(`schedule_${key}_enabled`),time=element(`schedule_${key}_time`);
    enabled.disabled=!master;time.disabled=!master||!enabled.checked;
  }
}
async function saveModeSchedule(){
  const passwordInput=element('schedule_password'),password=passwordInput.value,master=element('auto_mode_enabled').checked;
  if(!password){alert('請輸入管理員密碼');passwordInput.focus();return}
  const values={enabled:master?'1':'0',password},used=new Set();
  for(const key of ['in','out','overtime_in','overtime_out']){
    const enabled=element(`schedule_${key}_enabled`).checked,time=element(`schedule_${key}_time`).value;
    if(!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)){alert('請為每個模式選擇有效時間');return}
    if(master&&enabled&&used.has(time)){alert('兩個已啟用的模式不能設定在相同時間');return}
    if(master&&enabled)used.add(time);
    values[`${key}_enabled`]=enabled?'1':'0';values[`${key}_time`]=time;
  }
  const button=element('save_schedule_button');button.disabled=true;
  try{
    await postForm('/attendance/api/mode-schedule',values);passwordInput.value='';scheduleLoaded=false;await loadStatus();
    element('schedule_status').textContent=master?'定時切換設定已保存；到達指定時間會自動切換。':'自動定時切換已關閉；目前模式只能手動變更。';
  }catch(error){passwordInput.value='';alert(error.message);passwordInput.focus()}finally{button.disabled=false}
}
async function setManualTime(){
  const timeInput=element('manual_time'),passwordInput=element('time_password'),value=timeInput.value,password=passwordInput.value;
  if(!value){alert('請選擇要設定的日期與時間');return}
  if(!password){alert('請輸入管理頁密碼');return}
  const timestamp=Math.floor(new Date(value).getTime()/1000);
  if(!Number.isFinite(timestamp)){alert('日期時間格式不正確');return}
  const button=element('set_manual_time_button');button.disabled=true;
  try{
    const body=new URLSearchParams({timestamp:String(timestamp),password});
    await json('/attendance/api/manual-time',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    passwordInput.value='';alert('手動時間已設定並保存到備用時鐘；本次重新開機前會以手動時間為準。');await load();
  }catch(error){passwordInput.value='';alert(error.message)}finally{button.disabled=false}
}
async function restoreAutomaticTime(){
  const passwordInput=element('time_password'),password=passwordInput.value;
  if(!password){alert('請輸入管理頁密碼');return}
  if(!confirm('確定恢復網路自動校時？'))return;
  const button=element('restore_auto_time_button');button.disabled=true;
  try{
    const body=new URLSearchParams({password});
    await json('/attendance/api/automatic-time',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    passwordInput.value='';alert('已恢復網路自動校時。');await load();
  }catch(error){passwordInput.value='';alert(error.message)}finally{button.disabled=false}
}
async function addManualAttendance(){
  const employeeInput=element('manual_attendance_employee'),timeInput=element('manual_attendance_time'),actionInput=element('manual_attendance_action'),passwordInput=element('manual_attendance_password');
  const slot=employeeInput.value,value=timeInput.value,action=actionInput.value,password=passwordInput.value;
  if(!slot){alert('請選擇員工');employeeInput.focus();return}
  if(!value){alert('請選擇補打卡日期與時間');timeInput.focus();return}
  if(!password){alert('請輸入管理員密碼');passwordInput.focus();return}
  const timestamp=Math.floor(new Date(value).getTime()/1000),employee=employeesCache.find(item=>String(item.slot)===slot),label=actionInput.options[actionInput.selectedIndex].text;
  if(!Number.isFinite(timestamp)){alert('補打卡日期時間格式不正確');return}
  if(!confirm(`確定為 ${employee?.id||''}｜${employee?.name||''} 補登 ${value.replace('T',' ')} ${label}？`))return;
  const button=element('manual_attendance_button');button.disabled=true;
  try{await postForm('/attendance/api/manual-attendance',{slot,action,timestamp:String(timestamp),password});passwordInput.value='';alert('補打卡已保存，紀錄已標記為管理員補登。');await load()}
  catch(error){passwordInput.value='';alert(error.message);passwordInput.focus()}
  finally{button.disabled=false}
}
function clearAllFingerprints(){
  const dialog=element('clear_fingerprints_dialog');element('clear_fingerprints_password').value='';element('clear_fingerprints_confirmation').value='';element('clear_fingerprints_status').textContent='';dialog.showModal();setTimeout(()=>element('clear_fingerprints_password').focus(),0);
}
function closeClearFingerprintsDialog(){element('clear_fingerprints_dialog').close()}
async function confirmClearAllFingerprints(){
  const passwordInput=element('clear_fingerprints_password'),confirmationInput=element('clear_fingerprints_confirmation'),password=passwordInput.value,confirmation=confirmationInput.value;
  if(!password){alert('請輸入管理員密碼');passwordInput.focus();return}
  if(confirmation!=='清空全部指紋'){alert('請完整輸入「清空全部指紋」');confirmationInput.focus();return}
  const button=element('confirm_clear_fingerprints_button'),cancel=element('cancel_clear_fingerprints_button'),status=element('clear_fingerprints_status');button.disabled=true;cancel.disabled=true;passwordInput.disabled=true;confirmationInput.disabled=true;status.textContent='正在清空 R307-S，請勿斷電……';
  try{const result=await postForm('/attendance/api/fingerprint-clear-all',{password,confirmation});closeClearFingerprintsDialog();alert(`R307-S 已清空，並移除 ${result.cleared_mappings||0} 個員工指紋對應。`);await load()}
  catch(error){status.textContent='清空失敗：'+error.message;alert(error.message)}
  finally{button.disabled=false;cancel.disabled=false;passwordInput.disabled=false;confirmationInput.disabled=false;passwordInput.value=''}
}
function clearAllLogs(){
  if(!confirm('警告：這會永久刪除所有刷卡紀錄，而且無法復原。確定要繼續嗎？'))return;
  const input=element('clear_logs_password');input.value='';element('clear_logs_status').textContent='';element('clear_logs_dialog').showModal();setTimeout(()=>input.focus(),0);
}
function closeClearLogsDialog(){element('clear_logs_password').value='';element('clear_logs_status').textContent='';element('clear_logs_dialog').close()}
async function confirmClearLogs(){
  const input=element('clear_logs_password'),password=input.value;
  if(!password){alert('未輸入密碼，刷卡紀錄未刪除。');return}
  const button=element('confirm_clear_logs_button'),cancel=element('cancel_clear_logs_button'),statusText=element('clear_logs_status');button.disabled=true;cancel.disabled=true;input.disabled=true;
  try{
    const body=new URLSearchParams({password});
    await json('/attendance/api/clear-logs',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    while(true){
      await new Promise(resolve=>setTimeout(resolve,200));
      const status=await json('/attendance/api/clear-logs-status');
      const percent=status.total?Math.min(100,Math.floor(status.erased*100/status.total)):0;
      statusText.textContent=`正在分批刪除刷卡紀錄 ${percent}%`;
      if(status.failed)throw Error('裝置清除 Flash 失敗，請查看裝置日誌後重試');
      if(status.done)break;
      if(!status.running)throw Error('刪除工作意外中止，裝置可能已重新啟動，請重新操作');
    }
    closeClearLogsDialog();alert('所有刷卡紀錄已成功刪除。');await load();
  }catch(error){input.value='';statusText.textContent='';alert(error.message);input.focus()}finally{button.disabled=false;cancel.disabled=false;input.disabled=false}
}
async function readAllBackupLogs(progress){
  const logs=[];let offset=0,page=0;
  while(true){
    progress.textContent=`正在讀取第 ${++page} 批刷卡紀錄……`;
    const batch=await json('/attendance/api/export-page?offset='+offset);
    logs.push(...batch.logs);
    if(batch.total)progress.textContent=`正在讀取刷卡紀錄 ${Math.min(100,Math.floor(Number(batch.next||0)*100/Number(batch.total)))}%（${logs.length} 筆）……`;
    if(batch.done)break;
    if(batch.next<=offset)throw Error('刷卡紀錄分頁資料異常');
    offset=batch.next;
  }
  return logs;
}
const timeMinutes=value=>{const p=String(value||'').split(':').map(Number);return p.length>=2&&p.every(Number.isFinite)?p[0]*60+p[1]+(p[2]||0)/60:null};
const durationMinutes=(start,end)=>{const a=timeMinutes(start),b=timeMinutes(end);if(a===null||b===null)return 0;let value=b-a;if(value<0)value+=1440;return value};
const durationLabel=minutes=>`${Math.floor(minutes/60)}:${String(Math.round(minutes%60)).padStart(2,'0')}`;
async function loadStatistics(){
  const button=element('stats_button'),progress=element('stats_status'),from=element('stats_from').value,to=element('stats_to').value,slotFilter=element('stats_employee').value;
  if(!from||!to||from>to){alert('請選擇正確的開始與結束日期');return}button.disabled=true;
  try{
    progress.textContent='正在讀取完整兩個月資料……';
    if(!employeesCache.length)await loadEmployees();
    const [logs,notes]=await Promise.all([readAllBackupLogs(progress),readAllNotes(false)]),days=new Map(),summary=new Map();
    for(const employee of employeesCache){if(!slotFilter||String(employee.slot)===slotFilter)summary.set(Number(employee.slot),{id:employee.id,name:employee.name,days:0,regular:0,overtime:0,missing:0,notes:0})}
    for(const log of logs){const date=String(log.time||'').slice(0,10),slot=Number(log.employee_id);if(date<from||date>to||(slotFilter&&String(slot)!==slotFilter))continue;const key=slot+'|'+date;let day=days.get(key);if(!day){day={slot,date,clockIn:'',clockOut:'',overtimeIn:'',overtimeOut:''};days.set(key,day)}const value=String(log.time||'').slice(11,19),action=Number(log.action_code);if(action===1&&(!day.clockIn||value<day.clockIn))day.clockIn=value;if(action===0&&(!day.clockOut||value>day.clockOut))day.clockOut=value;if(action===2&&(!day.overtimeIn||value<day.overtimeIn))day.overtimeIn=value;if(action===3&&(!day.overtimeOut||value>day.overtimeOut))day.overtimeOut=value}
    for(const day of days.values()){let row=summary.get(day.slot);if(!row){row={id:'未設定-'+day.slot,name:'未知員工',days:0,regular:0,overtime:0,missing:0,notes:0};summary.set(day.slot,row)}row.days++;if(day.clockIn&&day.clockOut)row.regular+=durationMinutes(day.clockIn,day.clockOut);else if(day.clockIn||day.clockOut)row.missing++;if(day.overtimeIn&&day.overtimeOut)row.overtime+=durationMinutes(day.overtimeIn,day.overtimeOut);else if(day.overtimeIn||day.overtimeOut)row.missing++}
    for(const note of notes){const slot=Number(note.slot),date=String(note.date||'');if(date<from||date>to||(slotFilter&&String(slot)!==slotFilter))continue;const row=summary.get(slot);if(row)row.notes++}
    const rows=[...summary.values()].sort((a,b)=>String(a.id).localeCompare(String(b.id),'zh-Hant',{numeric:true})),active=rows.filter(row=>row.days>0),regular=rows.reduce((sum,row)=>sum+row.regular,0),overtime=rows.reduce((sum,row)=>sum+row.overtime,0),missing=rows.reduce((sum,row)=>sum+row.missing,0),noteCount=rows.reduce((sum,row)=>sum+row.notes,0);
    element('stat_people').textContent=String(active.length);element('stat_days').textContent=String(rows.reduce((sum,row)=>sum+row.days,0));element('stat_regular').textContent=durationLabel(regular);element('stat_overtime').textContent=durationLabel(overtime);element('stat_missing').textContent=String(missing);element('stat_notes').textContent=String(noteCount);
    element('stats_rows').innerHTML=rows.length?rows.map(row=>`<tr><td>${html(row.id)}</td><td>${html(row.name)}</td><td>${row.days}</td><td>${durationLabel(row.regular)}</td><td>${durationLabel(row.overtime)}</td><td>${row.missing}</td><td>${row.notes}</td></tr>`).join(''):'<tr><td colspan="7">此範圍沒有員工資料</td></tr>';
    progress.textContent=`統計範圍：${from} 至 ${to}；正常工時採最早上班與最晚下班，加班同理。`;
  }catch(error){progress.textContent='統計失敗：'+error.message;alert(error.message)}finally{button.disabled=false}
}
async function exportBackup(){
  const button=element('export_backup_button'),progress=element('backup_status');button.disabled=true;
  try{
    progress.textContent='正在讀取員工與每日備註……';
    const employees=await json('/attendance/api/employees'),notes=await readAllNotes(true,progress);
    const logs=await readAllBackupLogs(progress);logs.sort((a,b)=>Number(a.timestamp)-Number(b.timestamp));
    const backup={format:'nfc-attendance-clock-backup',version:5,exported_at:new Date().toISOString(),employees:employees.map(e=>({slot:Number(e.slot),code:String(e.id??''),name:String(e.name??''),uid:String(e.uid??''),can_open:Boolean(e.can_open),finger1:Boolean(e.finger1),finger2:Boolean(e.finger2),finger1_id:Number(e.finger1_id||0),finger2_id:Number(e.finger2_id||0)})),notes:notes.map(n=>({date:String(n.date??''),slot:Number(n.slot),note:String(n.note??'')})),logs:logs.map(l=>({timestamp:Number(l.timestamp),employee_id:Number(l.employee_id),action:Number(l.action_code),uid_hash:Number(l.uid_hash),manual:Boolean(l.manual)}))};
    const blob=new Blob([JSON.stringify(backup)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),now=new Date(),stamp=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`,link=document.createElement('a');
    link.href=url;link.download=`nfc-attendance-backup-${stamp}.json`;link.click();setTimeout(()=>URL.revokeObjectURL(url),30000);
    progress.textContent=`備份完成：${backup.employees.length} 位員工、${backup.notes.length} 筆備註、${backup.logs.length} 筆刷卡紀錄。請妥善保存 JSON 檔。`;
  }catch(error){progress.textContent='備份失敗：'+error.message;alert(error.message)}finally{button.disabled=false}
}
const postForm=(url,values)=>json(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body:new URLSearchParams(values)});
async function importBackup(){
  const fileInput=element('backup_file'),passwordInput=element('backup_password'),button=element('import_backup_button'),progress=element('backup_status'),file=fileInput.files[0],password=passwordInput.value;
  if(!file){alert('請先選擇先前匯出的 JSON 備份檔');fileInput.focus();return}
  if(file.size>10*1024*1024){alert('備份檔超過 10 MB，請確認是否選錯檔案');return}
  if(!password){alert('請輸入目前管理密碼');passwordInput.focus();return}
  let backup;
  try{backup=JSON.parse(await file.text())}catch(error){alert('備份檔不是有效的 JSON 格式');return}
  if(!backup||backup.format!=='nfc-attendance-clock-backup'||![1,2,3,4,5].includes(Number(backup.version))||!Array.isArray(backup.employees)||!Array.isArray(backup.notes)||!Array.isArray(backup.logs)){alert('備份檔格式或版本不相容');return}
  const encoder=new TextEncoder(),employeeSlots=new Set(),employeeCodes=new Set(),cardUids=new Set(),noteKeys=new Set();let contentValid=true;
  for(const employee of backup.employees){
    const slot=Number(employee?.slot),code=String(employee?.code??'').trim(),name=String(employee?.name??''),uid=String(employee?.uid??''),codeKey=code.toUpperCase();
    if(!Number.isInteger(slot)||slot<1||slot>500||!code||encoder.encode(code).length>16||!name||encoder.encode(name).length>40||encoder.encode(uid).length>24||employeeSlots.has(slot)||employeeCodes.has(codeKey)||(uid&&cardUids.has(uid))){contentValid=false;break}
    employeeSlots.add(slot);employeeCodes.add(codeKey);if(uid)cardUids.add(uid);
  }
  for(const note of backup.notes){
    const slot=Number(note?.slot),date=String(note?.date??''),text=String(note?.note??''),key=slot+'|'+date,parsed=new Date(date+'T12:00:00');
    if(!Number.isInteger(slot)||slot<1||slot>500||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(date)||Number.isNaN(parsed.getTime())||parsed.toISOString().slice(0,10)!==date||!text||[...text].length>15||encoder.encode(text).length>48||noteKeys.has(key)){contentValid=false;break}
    noteKeys.add(key);
  }
  for(const log of backup.logs){
    const timestamp=Number(log?.timestamp),employeeId=Number(log?.employee_id),action=Number(log?.action),uidHash=Number(log?.uid_hash);
    if(!Number.isInteger(timestamp)||timestamp<1577836800||timestamp>4102444799||!Number.isInteger(employeeId)||employeeId<1||employeeId>500||!Number.isInteger(action)||action<0||action>3||!Number.isInteger(uidHash)||uidHash<0||uidHash>4294967295||(Object.prototype.hasOwnProperty.call(log,'manual')&&typeof log.manual!=='boolean')){contentValid=false;break}
  }
  if(!contentValid){alert('備份內容損壞或含有重複工號、卡號、槽位或備註，尚未變更裝置資料');return}
  let status;
  try{status=await json('/attendance/api/status')}catch(error){alert('無法讀取裝置容量：'+error.message);return}
  if(backup.employees.length>500||backup.notes.length>Number(status.note_capacity??0)||backup.logs.length>Number(status.log_capacity||0)){alert('備份內容超過這台打卡鐘的 Flash 儲存容量');return}
  if(!confirm(`確定匯入 ${backup.employees.length} 位員工、${backup.notes.length} 筆備註及 ${backup.logs.length} 筆刷卡紀錄？\n\n員工與備註會先寫入安全暫存區，完成最後提交前不覆蓋原員工資料。刷卡紀錄區會重新建立。`))return;
  button.disabled=true;element('export_backup_button').disabled=true;let token=0;
  try{
    progress.textContent='正在核實密碼並清除現有資料……';
    const begin=await postForm('/attendance/api/import-begin',{password});token=Number(begin.token);passwordInput.value='';
    let eraseDone=false;
    while(!eraseDone){
      const erase=await postForm('/attendance/api/import-erase',{token:String(token)}),erased=Number(erase.erased||0),total=Number(erase.total||1),percent=Math.min(100,Math.floor(erased*100/total));
      progress.textContent=`正在分批準備 Flash 還原區 ${percent}%……`;
      eraseDone=Boolean(erase.done);
      if(!eraseDone)await new Promise(resolve=>setTimeout(resolve,200));
    }
    for(let index=0;index<backup.employees.length;index++){
      const employee=backup.employees[index];progress.textContent=`正在還原員工 ${index+1}/${backup.employees.length}……`;
      const fingerprintMetadata=Object.prototype.hasOwnProperty.call(employee,'finger1')&&Object.prototype.hasOwnProperty.call(employee,'finger2');
      await postForm('/attendance/api/import-employee',{token:String(token),slot:String(employee.slot),code:String(employee.code??''),name:String(employee.name??''),uid:String(employee.uid??''),can_open:employee.can_open===false?'0':'1',fingerprint_metadata:fingerprintMetadata?'1':'0',finger1:employee.finger1?'1':'0',finger2:employee.finger2?'1':'0',finger1_id:String(employee.finger1_id??0),finger2_id:String(employee.finger2_id??0)});
    }
    for(let index=0;index<backup.notes.length;index++){
      const note=backup.notes[index];progress.textContent=`正在還原備註 ${index+1}/${backup.notes.length}……`;
      await postForm('/attendance/api/import-note',{token:String(token),date:String(note.date??''),slot:String(note.slot),note:String(note.note??'')});
    }
    const logs=[...backup.logs].sort((a,b)=>Number(a.timestamp)-Number(b.timestamp)),batchSize=50;
    for(let offset=0;offset<logs.length;offset+=batchSize){
      const batch=logs.slice(offset,offset+batchSize),records=batch.map(log=>`${Number(log.timestamp)},${Number(log.employee_id)},${Number(log.action)},${Number(log.uid_hash)},${log.manual?1:0}`).join(';');
      progress.textContent=`正在還原刷卡紀錄 ${Math.min(offset+batch.length,logs.length)}/${logs.length}……`;
      await postForm('/attendance/api/import-logs',{token:String(token),records});
    }
    progress.textContent='正在提交員工與備註資料……';
    const result=await postForm('/attendance/api/import-finish',{token:String(token)});token=0;
    fileInput.value='';passwordInput.value='';progress.textContent=`還原完成：${result.employees} 位員工、${result.notes} 筆備註、${result.logs} 筆刷卡紀錄。`;alert('資料備份已成功還原。');await load();
  }catch(error){
    if(token){try{await postForm('/attendance/api/import-abort',{token:String(token)})}catch(ignore){}}
    passwordInput.value='';progress.textContent='還原失敗：'+error.message+'。請保留備份檔並重新匯入。';alert('還原失敗：'+error.message);
  }finally{button.disabled=false;element('export_backup_button').disabled=false}
}
async function changeAdminPassword(){
  const currentInput=element('current_admin_password'),newInput=element('new_admin_password'),confirmInput=element('confirm_admin_password');
  const current_password=currentInput.value,new_password=newInput.value,confirm_password=confirmInput.value;
  if(!current_password){alert('請輸入目前管理密碼');currentInput.focus();return}
  if(new_password.length<8||new_password.length>64||!/^[!-~]+$/.test(new_password)){alert('新密碼必須為 8～64 個半形英文字母、數字或符號，且不可包含空白');newInput.focus();return}
  if(new_password!==confirm_password){alert('兩次輸入的新密碼不一致');confirmInput.focus();return}
  if(!confirm('確定同步修改管理頁登入密碼及所有敏感操作的核實密碼？'))return;
  const button=element('change_admin_password_button');button.disabled=true;
  try{
    const body=new URLSearchParams({current_password,new_password,confirm_password});
    await json('/attendance/api/admin-password',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8'},body});
    currentInput.value='';newInput.value='';confirmInput.value='';
    alert('管理員密碼已同步修改並保存。接下來請使用帳號 admin 與新密碼重新登入。');
    location.replace('/attendance/');
  }catch(error){currentInput.value='';newInput.value='';confirmInput.value='';alert(error.message);currentInput.focus();button.disabled=false}
}
async function liveRefresh(){
  if(liveRefreshBusy)return;liveRefreshBusy=true;
  try{await loadStatus();if(currentTab==='dashboard'||currentTab==='records')await loadLogs()}
  catch(error){const statusElement=element('status');if(statusElement)statusElement.textContent='即時更新暫時中斷：'+error.message}
  finally{liveRefreshBusy=false}
}
showTab(location.hash.slice(1)||'dashboard');setInterval(liveRefresh,1000);
</script></html>
)HTML";
  auto *response = r->beginResponse(
      200,
      "text/html; charset=utf-8",
      reinterpret_cast<const uint8_t *>(PAGE),
      sizeof(PAGE) - 1);
  response->addHeader("Cache-Control", "no-store");
  r->send(response);
}
}  // namespace esphome::attendance_web_s3
