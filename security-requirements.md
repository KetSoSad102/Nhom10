# Security Requirements 

SR-1: Hệ thống chỉ trả về giá trị của trường apiKey cho role admin. Các role khác nhận về danh sách rỗng.

SR-2: Hệ thống chỉ trả về giá trị của trường managementIpAddress cho các role admin và operator. Role viewer nhận về danh sách rỗng.

SR-3: Hệ thống trả về giá trị của trường issueSummary cho các role admin, operator và viewer.

SR-4: Khi role không được cung cấp hoặc không có trong policy, hệ thống không trả về dữ liệu nào (trả về danh sách rỗng).

SR-5: Việc kiểm tra quyền được áp dụng cho mọi kết quả tìm thấy, kể cả key nằm trong dict hoặc list lồng nhau.