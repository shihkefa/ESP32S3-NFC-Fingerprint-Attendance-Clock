# v2.1.8 發布檔案與驗證範圍

本倉庫收錄單按鍵 ESP32-S3 NFC＋指紋打卡鐘 v2.1.8，包含手動輸入 NFC 卡號、感應登記語音提示及管理員補打卡功能。

## 已核對的內容

- 原始碼資料夾與所附 v2.1.8 程式 ZIP 逐檔一致。
- 發布的 YAML、Flash 分割表、兩個元件資料夾共 12 個檔案，與來源內容逐位元組一致。
- `secrets.example.yaml` 只含示例值，YAML 的四項 Wi-Fi／密碼設定均透過 `!secret` 引用。
- 公開檔案不包含私人 `secrets.yaml`、員工備份、出勤匯出或指紋模板。
- 單按鍵為 GPIO4，程式依序切換上班、下班、加班上班、加班下班。
- 16MB Flash 分割表、所需元件與檔案路徑已核對；ZIP 與倉庫程式內容一致，並提供 SHA-256 校驗碼。
- 文件只介紹 v2.1.8，接線圖及燒錄教學隨下載包提供。

## 編譯與實機範圍

來源文件記載使用 ESPHome 2026.8.2／ESP-IDF 5.5.5 的專案架構。本次整理沒有重新編譯或執行實機測試；檔案檢查不代表已在每種板型或後續 ESPHome 版本驗證。

此原始碼發行包不附預先編譯的 BIN。請填入自己的 `secrets.yaml` 後編譯，安裝前先備份既有資料。完成燒錄後，依[開機檢查](./ESPHOME_FLASHING.md#7-開機後檢查)逐項確認硬體及功能。

校驗碼見 [SHA256SUMS.txt](https://github.com/shihkefa/ESP32S3-NFC-Fingerprint-Attendance-Clock/blob/main/releases/v2.1.8/SHA256SUMS.txt)，其中路徑以倉庫根目錄為基準。
