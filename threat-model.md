# Threat Model

(a) Actor và role: gồm ba vai trò
- admin: toàn quyền truy cập cấu hình thiết bị 
- operator: được xem các thông số vận hành
- viewer: được tra cứu các trạng thái sự cố
- 
(b) Asset nhạy cảm: 
- apiKey
- managementIpAddress
- issueSummary
- 
(c) Trust boundary: Ranh giới những người có khả năng gọi hàm (viewer, operator) và dữ liệu nội bộ trả về từ API giám sát hạ tầng mạng. Nếu hàm json_search() không kiểm tra role trước khi trả kết quả thì ai gọi hàm cũng đọc được toàn bộ dữ liệu, lúc đó, ranh giới này bị bỏ qua. 

(d) Threat theo STRIDE:
- Information Disclosure: viewer gọi json_search("apiKey", data) và nhận được apiKey, hoặc lấy được managementIpAddress của thiết bị.
- Elevation of Privilege: viewer dùng apiKey lấy được để thực hiện các thao tác chỉ dành cho admin.