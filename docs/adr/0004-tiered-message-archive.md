# ADR 0004: Lưu trữ phân tầng tin nhắn & media lên object storage (S3/R2/GCS/MinIO)

- **Trạng thái:** Đã chấp nhận (Accepted)
- **Ngày:** 2026-11-17
- **Liên quan:** ADR-0001 (đồng bộ lịch sử), INV-2 (`session.json`), INV-3 (UI thread), INV-4 (idempotent theo `msg_id`), `docs/standards/security-and-cryptography.md`

## Bối cảnh

- Zalo không giữ lịch sử chat lâu dài trên server; dữ liệu ở máy (`accounts/<UIN>_history.db`, `accounts/<UIN>/media_cache/`) gần như là bản duy nhất. Mất máy, cài lại hệ điều hành hay xoá thư mục dữ liệu là mất lịch sử.
- Lịch sử và media tăng không giới hạn trên đĩa. Người dùng muốn giữ ở máy một phần (theo số ngày hoặc dung lượng) và tải lại phần cũ khi cuộn tới, giống Telegram.
- App hỗ trợ nhiều tài khoản (mỗi UIN một DB và thư mục media riêng) và nhận tin đồng bộ từ thiết bị khác (Sync V2, ADR-0001), nên tin có thể đến muộn với `ts` cũ.
- Người dùng tự cung cấp bucket: AWS S3, Cloudflare R2, Google Cloud Storage (API tương thích S3 với HMAC key) hoặc MinIO tự host. Cả bốn đều nói giao thức S3 (SigV4).
- Chuẩn bảo mật: `session.json`, cookie, `zpw_*`, IMEI không bao giờ rời máy (INV-2); dữ liệu gửi ra dịch vụ ngoài cần người dùng đồng ý rõ ràng; thay đổi mã hoá cần ADR và known-answer test.

## Quyết định

Thêm module `archive` (worker-owned, không chạy trên UI thread) đẩy tin nhắn và media của từng tài khoản lên một bucket S3-compatible dưới dạng **object bất biến**, rồi cho phép dọn bản ở máy theo chính sách giữ lại và tải lại theo nhu cầu.

### 1. Bố cục object (bất biến, không bao giờ ghi đè)

```
<prefix>/v1/
  vault.json                                   # salt + tham số KDF + khối kiểm tra mật khẩu (không chứa khoá)
  accounts/<acct>/
    segments/<thread>/<ts_min>-<ts_max>-<device>-<seq>.seg   # một lô tin của một hội thoại
    media/<sha256>.blob                                      # một tệp media, đặt tên theo hash nội dung
    meta/<device>-<seq>.snap                                 # danh sách hội thoại, cài đặt không nhạy cảm
```

- `<acct>` và `<thread>` là HMAC-SHA256 (khoá con của tài khoản) của UIN/thread_id khi bật mã hoá, để tên object không lộ danh bạ; khi tắt mã hoá dùng nguyên giá trị.
- Không có file index dùng chung bị sửa: danh sách segment lấy bằng `ListObjectsV2` theo prefix, khoảng thời gian nằm trong tên object. Hai thiết bị cùng tài khoản ghi vào cùng bucket không bao giờ xung đột (tên có `<device>`).

### 2. Segment tin nhắn

- Một segment = các dòng `messages` (đủ cột, gồm `raw_json`) của **một hội thoại**, dạng JSON Lines → nén zstd → (mã hoá) → upload. Kích thước mục tiêu ≤ 2 MB hoặc ≤ 2 000 tin.
- Theo dõi ở máy bằng cột mới `messages.archive_seg TEXT NULL` (migration `user_version = 3`) và bảng `archive_segments(seg_key, thread_id, ts_min, ts_max, msg_count, etag, uploaded_at, origin)`.
- Dòng **chưa lưu trữ** = `archive_seg IS NULL`. Mỗi lần sao lưu gom các dòng này theo hội thoại thành segment mới. Vì đánh dấu theo từng dòng, tin đến muộn có `ts` cũ (đồng bộ từ thiết bị khác) vẫn được lưu trữ. Khi một dòng đã lưu trữ bị sửa (sửa tin, reaction, thu hồi), `archive_seg` được đặt lại `NULL` để vào segment sau; khi khôi phục, bản trong segment mới nhất thắng (INV-4: khoá theo `msg_id`, không nhân đôi).
- Chỉ ghi `archive_seg` sau khi upload trả về thành công và `HEAD` xác nhận đúng kích thước.
- Việc đặt lại `archive_seg = NULL` khi nội dung thay đổi do trigger SQLite `messages_archive_dirty` đảm nhận (chỉ khi `text`/`raw_json`/`msg_type`/`thread_id`/`sender_name` thực sự đổi), nên mọi chỗ ghi hiện có và sau này đều tự động đúng; nhận lại tin y hệt không tạo segment mới.
- `archive_segments.seq` (thứ tự upload, lấy từ tên object) quyết định bản nào mới hơn khi tải về: một dòng chỉ bị thay bởi bản trong segment có `seq` lớn hơn segment hiện tại của nó; dòng sửa ở máy chưa lưu trữ (`archive_seg IS NULL`) luôn được giữ.

### 3. Media

- Mỗi tệp trong `media_cache/` (ảnh, video, voice, file đã tải) upload một lần thành `media/<sha256>.blob`; bảng `archive_media(cache_name, sha256, size, uploaded_at)` ghi lại. Trùng nội dung giữa hội thoại hay thiết bị chỉ lưu một lần.

### 4. Giữ lại ở máy & tải lại theo nhu cầu (kiểu Telegram)

- Cài đặt mỗi tài khoản: `keep_days` (0 = giữ hết), `max_db_mb` (0 = không giới hạn), `max_media_mb` (0 = không giới hạn).
- Bộ dọn (chạy sau mỗi lần sao lưu thành công) chỉ xoá **dòng đã có `archive_seg`** và **media đã có trong `archive_media`**: tin cũ hơn `keep_days`, rồi tin cũ nhất cho tới khi DB dưới `max_db_mb`; media ít dùng nhất (LRU theo atime) tới khi dưới `max_media_mb`. Không bao giờ xoá tin của hội thoại đang mở, tin đã lưu (saved items), tin có nhắc hẹn, nháp. Khi chưa cấu hình lưu trữ, chính sách giữ lại **không** có hiệu lực (không xoá vĩnh viễn ngầm).
- Khi cuộn tới đầu danh sách tin và SQLite hết tin cũ hơn, worker tra `archive_segments` (và `ListObjectsV2` nếu cần) tìm segment có `ts_min` nhỏ hơn tin cũ nhất đang có, tải về, giải mã, `INSERT OR IGNORE` vào SQLite (giữ nguyên `archive_seg` để có thể dọn lại), rồi mới tới bước hỏi server Zalo (`LoadGroupHistory`) như hiện nay.
- Mở ảnh/file mà `media_cache` không còn (đã dọn) và link Zalo đã hết hạn: tải `media/<sha256>.blob` về cache.

### 5. Mã hoá (tuỳ chọn, mặc định BẬT)

- Mật khẩu → **Argon2id** (m = 64 MiB, t = 3, p = 1, salt 16 byte ngẫu nhiên lưu trong `vault.json`) → master key 32 byte. Khoá con mỗi tài khoản và mục đích bằng **HKDF-SHA256** (`info = "ctdozlite/v1/" + mục đích + UIN`): khoá dữ liệu, khoá đặt tên (HMAC).
- Mỗi object: **AES-256-GCM**, nonce 96 bit ngẫu nhiên từ `OsRng` cho mỗi object (không tái dùng), AAD = object key đầy đủ (gắn ciphertext với tên, chống tráo object).
- Định dạng: `"CTZA"` | `version:u8` | `flags:u8` (bit0 = mã hoá, bit1 = zstd) | `nonce[12]` (nếu mã hoá) | payload. Có cờ trong từng object nên đổi tuỳ chọn mã hoá về sau không làm hỏng bản cũ.
- `vault.json` chứa khối kiểm tra (`AES-GCM(master, "ctdozlite-vault-check")`) để báo sai mật khẩu trước khi khôi phục.
- Để sao lưu tự động, master key được lưu ở máy trong `archive.json` (quyền `0600`, ghi nguyên tử như `session.json`). Tuỳ chọn "Không lưu mật khẩu" → chỉ sao lưu thủ công, hỏi mật khẩu mỗi lần.
- Thông số kỹ thuật được khoá bằng known-answer test.

### 6. Cấu hình & bí mật

- `archive.json` trong thư mục dữ liệu (`0600`): provider, endpoint, region, bucket, prefix, path-style, access key, secret key, bật/tắt mã hoá, master key (nếu cho phép lưu), chính sách giữ lại theo tài khoản, `device_id` ngẫu nhiên.
- Không bao giờ upload: `session*.json`, `accounts/<UIN>.json`, `archive.json`, khoá API LLM, log. Không log access key, secret, master key, nội dung tin.
- Tất cả host Zalo vẫn ở `src/endpoints.rs`; endpoint object storage do người dùng nhập, không phải host Zalo.

### 7. Lịch chạy

- Nút "Sao lưu ngay"; tự động mỗi 6 giờ nếu có dòng `archive_seg IS NULL` hoặc media chưa lưu; khi thoát app (giới hạn thời gian, không chặn việc thoát quá 10 giây). Tất cả chạy trên worker với `spawn_blocking` cho SQLite/zstd/mã hoá (INV-3).

### 8. Khôi phục

- "Khôi phục" theo tài khoản: liệt kê segment, tải theo thứ tự `uploaded_at`, gộp vào SQLite (INV-4). Không xoá dữ liệu đang có. Media tải dần theo nhu cầu thay vì tải hết.

### 9. Thư viện

- `rusty-s3` (sans-IO, ký SigV4 + tạo URL; HTTP dùng `reqwest` sẵn có, không thêm runtime mạng mới).
- `argon2`, `hkdf` (RustCrypto, cùng hệ với `aes-gcm`, `sha2` đang dùng). `zstd` đã có.

### 10. Chia PR

1. **Lõi** (không UI): định dạng object + mã hoá + KAT, client S3, migration schema, sao lưu segment/media, tải segment theo nhu cầu, bộ dọn (logic thuần, test đầy đủ), test tích hợp với MinIO (chỉ chạy khi có biến môi trường `CTDOZLITE_TEST_S3_*`).
2. **Giao diện**: tab "Lưu trữ & Sao lưu" trong Cài đặt (preset provider, kiểm tra kết nối, mã hoá + mật khẩu, chính sách giữ lại, trạng thái, Sao lưu ngay, Khôi phục), nối tải-theo-nhu-cầu vào nút/cuộn "tin cũ hơn".

## Hệ quả

- **Tích cực:** Lịch sử và media không còn phụ thuộc một máy; giới hạn được dung lượng ở máy; nhiều tài khoản, nhiều thiết bị ghi chung bucket không xung đột; nhà cung cấp không đọc được dữ liệu khi bật mã hoá; object bất biến dễ kiểm tra và an toàn với sự cố mạng giữa chừng.
- **Tiêu cực:** Thêm 3 dependency; mỗi lần sao lưu tạo thêm object (cần dọn segment thừa về sau bằng gộp segment); quên mật khẩu là mất bản sao lưu; master key lưu ở máy cho chế độ tự động — ai đọc được thư mục dữ liệu thì đọc được backup (cùng mức rủi ro với `session.json` hiện nay).
- **Việc sau:** gộp segment nhỏ (compaction), xoá tin "chỉ phía tôi" lan sang bản lưu trữ (tombstone), đổi mật khẩu (mã hoá lại khoá), dọn object theo tuổi trên bucket.

## Phương án đã cân nhắc

| Phương án | Lý do không chọn |
| :--- | :--- |
| Chụp nguyên file SQLite mỗi lần sao lưu | Không tải lại từng phần khi cuộn; upload lại toàn bộ DB mỗi lần; hai thiết bị ghi đè nhau. |
| File index/manifest dùng chung có sửa đổi | Xung đột khi nhiều thiết bị cùng ghi; cần khoá phân tán mà S3 không có. |
| Đánh dấu đã lưu trữ theo mốc `ts` lớn nhất | Bỏ sót tin đồng bộ muộn có `ts` cũ và tin bị sửa sau khi đã lưu. |
| `aws-sdk-s3` | Nặng (nhiều crate, runtime riêng), dư thừa cho vài thao tác PUT/GET/HEAD/LIST. |
| Lưu khoá trong keyring hệ điều hành | Mỗi nền tảng một backend, không có trên mọi máy Linux headless; cân nhắc lại sau. |
| Không mã hoá mặc định | Lịch sử chat là dữ liệu riêng tư; chi phí AES-GCM không đáng kể so với mạng. |
