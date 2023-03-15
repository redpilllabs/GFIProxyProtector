<!-- markdownlint-disable MD034 -->
# GFWProxyProtector

به کمک این اسکریپت میتوانید ماژول xt_geoip را برای هسته ی لینوکس نصب و فعال کنید. این ماژول سیستم عامل را قادر به کنترل اتصالات شبکه بر اساس خصوصیات جغرافیایی می‌کند. با این روش دیگر اهمیتی ندارد از چه نرم افزار پروکسی یا وی پی ان بر روی سرور استفاده می‌کنید چون نهایتا تمام اتصالات توسط هسته ی سیستم عامل لینوکس و iptables بررسی خواهند شد.

در صورت مسدودسازی آی‌پی های چینی، هرگونه تلاش اتصال به سرور از  جانب این آی‌پی ها در فایل  `/var/log/kern.log`  با پیشوند GFW ثبت خواهد شد.

## نحوه اجرا

```
git clone https://github.com/0xNeu/GFIProxyProtector.git
cd GFIProxyProtector
chmod +x run.sh
sudo ./run.sh
```

## منابع

- [صفحه ی اصلی ماژول](https://inai.de/projects/xtables-addons/geoip.php)
