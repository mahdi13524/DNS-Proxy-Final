# راهنمای DNS Decision X-Ray

در نسخه Advanced، کارت «DNS DECISION X-RAY» در صفحه داشبورد قرار گرفته است.

## نمایش مرحله‌به‌مرحله
- Validation: بررسی صحت و نرمال‌سازی دامنه
- Advertising: بررسی فهرست تبلیغات
- Sanctions: بررسی فهرست تحریم
- Cache: تشخیص Cache Hit / Miss یا خاموش بودن کش
- Upstream: ثبت درخواست واقعی به DNS بالادستی (یا رد شدن از آن)
- Result: نمایش نتیجه نهایی، IP و TTL

## روش استفاده
1. در VS Code وارد `Advanced/Network-Project-Final` شوید.
2. برای حالت شبیه‌ساز، ابتدا `python upstream.py` را اجرا کنید.
3. `python -m dns_control` را اجرا کنید و به `http://127.0.0.1:8080` بروید.
4. در «آزمایش DNS» یک دامنه وارد کنید یا دکمه «اجرای Demo زنده» را بزنید.
5. مسیر درخواست در بخش DNS Decision X-Ray نمایش داده می‌شود. دکمه «مسیر تصمیم» در جدول آخرین درخواست‌ها نیز مسیر همان رکورد را نشان می‌دهد.

### تست نمایشی
- `ads.example.com` → AD_BLOCK، توقف قبل از تحریم و کش و Upstream
- `service.example.org` → SANCTION، توقف قبل از کش و Upstream
- `normal.example.net` → UPSTREAM در بار اول، CACHE در بار دوم پیش از پایان TTL (اگر کش فعال باشد)
- با خاموش کردن کش، مسیر Cache به‌صورت Disabled و مسیر Upstream به‌صورت درخواست واقعی ثبت می‌شود.

X-Ray تنها مسیر *موتور مستقل داشبورد* را مشاهده می‌کند؛ شمارنده‌ها و کش کنسول `dns_proxy.py` جدا هستند. این قابلیت هیچ نتیجه‌ای را جعل یا به‌صورت شبیه‌سازی‌شده جایگزین نمی‌کند.

برای تست خودکار: `python -m unittest discover -s tests -p "test_*.py" -v`.
