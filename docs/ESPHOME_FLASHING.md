# 單按鍵指紋打卡鐘 v2.1.8：ESPHome 燒錄教學

適用 ESP32-S3 N16R8、16MB Flash、PN532 SPI、SSD1315、DS3231、UART TTS、GPIO4 單按鍵與選配 R307-S。本版不啟用 PSRAM。

## 1. 準備原始碼與 ESPHome

下載 [v2.1.8 原始碼 ZIP](https://github.com/shihkefa/ESP32S3-NFC-Fingerprint-Attendance-Clock/blob/main/releases/v2.1.8/nfc-attendance-clock-s3-v2.1.8.zip?raw=true)，解壓後開啟 `nfc-attendance-clock-s3-v2.1.8/`。也可從 GitHub 的 `Code → Download ZIP` 取得整個倉庫。

使用 ESPHome Device Builder；Home Assistant 使用者通常從應用程式／附加元件商店安裝，亦可使用獨立 ESPHome 環境，參考 [ESPHome 官方安裝說明](https://esphome.io/install/)。

專案記載的編譯環境是 **ESPHome 2026.8.2／ESP-IDF 5.5.5**。本次為原始碼整理上傳，沒有重新編譯；更換 ESPHome 版本時需另行確認相容性。

## 2. 複製哪些檔案？

找到放置裝置 YAML 的 ESPHome 設定資料夾。Home Assistant 通常為 `/config/esphome/`，可使用 File editor、Studio Code Server 或既有的檔案分享方式存取。

| 要複製的內容 | 放置位置 | 檔案數 |
| --- | --- | --- |
| `nfc-attendance-clock.yaml` | 設定資料夾根目錄 | 1 |
| `attendance_partitions_s3.csv` | 與 YAML 同層 | 1 |
| 完整 `components/attendance_web_s3/` | 同層的 `components/` 下 | 3 |
| 完整 `components/web_server_idf/` | 同層的 `components/` 下 | 7 |

合計 **12 個程式及設定檔**，再加上自己的 `secrets.yaml`。最方便的方式是複製 YAML、CSV，以及完整 `components` 資料夾。已有其他元件時，保留它們，只加入本專案的兩個元件資料夾。

```text
/config/esphome/
├── nfc-attendance-clock.yaml
├── attendance_partitions_s3.csv
├── secrets.yaml
└── components/
    ├── attendance_web_s3/
    │   ├── __init__.py
    │   ├── attendance_web_s3.cpp
    │   └── attendance_web_s3.h
    └── web_server_idf/
        ├── __init__.py
        ├── web_server_idf.cpp
        ├── web_server_idf.h
        ├── multipart.cpp
        ├── multipart.h
        ├── utils.cpp
        └── utils.h
```

`README.md`、`INSTALL-v2.1.8.txt`、`docs/` 與接線圖是閱讀資料，不必複製到 ESPHome。只貼 YAML 或只複製 `attendance_web_s3` 都不足以編譯。

本機元件的路徑以 YAML 所在位置為基準，保持上述目錄層級，參考 [External Components 官方文件](https://esphome.io/components/external_components/#local)。

## 3. 填寫自己的密碼

首次使用且沒有 `secrets.yaml`：將 `secrets.example.yaml` 複製並改名為 `secrets.yaml`，放在 YAML 同層。已有此檔時保留原檔，只新增缺少的鍵值。

```yaml
wifi_ssid: "YOUR_2_4_GHZ_WIFI_NAME"
wifi_password: "YOUR_WIFI_PASSWORD"
fallback_ap_password: "YOUR_FALLBACK_AP_PASSWORD"
attendance_web_s3_password: "YOUR_ADMIN_PASSWORD"
```

- `wifi_ssid`、`wifi_password`：裝置要連接的 2.4 GHz Wi-Fi。
- `fallback_ap_password`：備用熱點 `NFC-Clock-Fallback` 的密碼，至少 8 個字元。
- `attendance_web_s3_password`：管理頁初始登入密碼，帳號固定 `admin`。

請將示例文字換成自己的值。`secrets.yaml` 不要上傳至公開倉庫；倉庫已將它加入忽略清單。曾在網頁修改過管理員密碼時，保留 NVS 的更新會沿用已保存的密碼。

## 4. 驗證與編譯

在 ESPHome Device Builder 重新整理，找到 `nfc-attendance-clock.yaml` 對應裝置，先執行 `Validate`／驗證設定。確認設定仍使用：

```yaml
esp32:
  board: esp32-s3-devkitc-1
  variant: esp32s3
  flash_size: 16MB
  partitions: attendance_partitions_s3.csv
  framework:
    type: esp-idf

external_components:
  - source: {type: local, path: components}
    components: [attendance_web_s3, web_server_idf]
```

上方只是核對用節錄，請使用倉庫內的完整 YAML。`web_server_idf` 是必要元件，配合 8 KiB HTTP 請求標頭設定；不要刪除。驗證通過後按 `Install` 編譯。初次建置會下載工具與 Google Fonts 字型，需要網路；請等到顯示編譯成功再燒錄。

## 5. 新裝置第一次 USB 燒錄

1. 在 Device Builder 的 `Install` 選擇手動下載（`Manual download`）。
2. 編譯成功後選擇 Factory 格式，下載 `firmware.factory.bin` 或對應裝置名稱的 `.factory.bin`。
3. 使用可傳輸資料的 USB 線連接 ESP32-S3；若板上有兩個 USB 埠，確認所接埠可提供燒錄用序列連線。
4. 在 Chrome／Edge 開啟 [ESPHome Web](https://web.esphome.io/)，按 `Connect` 選擇裝置序列埠，再按 `Install` 選取剛才的 Factory BIN。
5. 完成後等待裝置重新啟動，確認 Wi-Fi、時間、管理頁及單按鍵功能。

若裝置未進入下載模式，可按住 BOOT、按一下 RESET／EN，再放開 BOOT；不同開發板操作依其說明為準。USB、驅動與連接方式參考 [ESPHome 官方實體連線說明](https://esphome.io/guides/physical_device_connection/)。

ESPHome Web 寫入的是已編譯 BIN，不能直接上傳 ZIP、YAML 或 C++ 原始碼。

## 6. 已有資料的裝置與 OTA

先在管理頁下載完整 JSON 備份，並保留自己的 YAML 調整及 `secrets.yaml`。**裝置分割表與 `attendance_partitions_s3.csv` 一致，且 ESPHome 可連線進行 OTA 時**，複製完整本版程式檔、編譯成功後選 `Install → Wirelessly`。

OTA 不會更新 Flash 分割表。分割配置不同或無法確認時，先備份，再以 USB 安裝本版分割表與韌體。Factory 完整安裝或清除整顆 Flash 可能重設資料、Wi-Fi 與初始密碼；完成後核對資料，必要時從管理頁還原 JSON。

- `.ota.bin` 用於符合條件的 OTA。
- `.factory.bin` 用於 USB 完整安裝，不能當作 OTA 映像。
- JSON 保存指紋模板 ID 對應，不包含 R307-S 內的指紋模板。更換指紋模組需重新登記。

## 7. 開機後檢查

1. 手機或電腦與裝置連上同一區域網路，開啟 `http://nfc-attendance-clock.local/attendance/`，或 `http://裝置IP/attendance/`。
2. 使用 `admin` 與自己的管理員密碼登入。
3. 檢查時間、OLED、PN532、R307-S 狀態；按 GPIO4，確認四種模式依序切換。
4. 新增一位員工，測試感應登記、手動輸入卡號，以及實際打卡紀錄。
5. 需要指紋與門禁時，再確認指紋登記、辨識、員工開門權限與繼電器動作。
6. 測試 Excel 與 JSON 匯出，保存一份備份。

Wi-Fi 連線失敗可透過 `NFC-Clock-Fallback` 熱點與 `http://192.168.4.1/` 重新配網，熱點密碼為自己的 `fallback_ap_password`。

## 常見問題

| 問題 | 處理方式 |
| --- | --- |
| 找不到 `web_server_idf` | 將完整 `components/web_server_idf/` 放入設定目錄，確認 `__init__.py` 存在。 |
| 找不到 `attendance_web_s3` | 核對三個元件檔與 YAML 的相對位置，不要多包一層資料夾。 |
| 找不到分割表 | `attendance_partitions_s3.csv` 必須與 YAML 同層。 |
| 找不到 secret | 核對四個鍵名，檔名必須為 `secrets.yaml`，不能是 `.yaml.txt`。 |
| 字型下載失敗 | 確認建置主機能連到 Google Fonts，再重新編譯。 |
| 瀏覽器找不到序列埠 | 核對 USB 埠、資料線及驅動，關閉占用序列埠的工具。 |
| `.local` 網址無法開啟 | 從路由器或 ESPHome 日誌取得 IP，以 `http://裝置IP/attendance/` 開啟。 |

[返回專案首頁](../README.md)
