# PESS Central MySQL — Backend Foundation

هذه حزمة تأسيسية لخادم مركزي MySQL 8 لنظام PESS. تتضمن جداول العملاء والعقود والاستحقاقات والدفعات والتوزيعات وكشوف الحساب وسجل التدقيق والأحداث الأمنية ومحاولات PIN والتنبيهات.

## تشغيل محلي

1. أنشئ قاعدة بيانات MySQL 8 جديدة بترميز `utf8mb4`.
2. نفّذ `database/schema.sql`.
3. انسخ `.env.example` إلى `.env` واملأ بيانات اتصال قاعدة البيانات وسر الجلسة.
4. ثبّت Node.js 20+ ثم نفّذ `npm install`.
5. أنشئ مستخدمًا أوليًا بعد توليد Argon2id hash للـ PIN (راجع قسم bootstrap).
6. نفّذ `npm run dev`.

## إنشاء أول مستخدم

أنشئ hash محليًا باستخدام:
`node --input-type=module -e "import argon2 from 'argon2'; console.log(await argon2.hash(process.env.PESS_INITIAL_PIN, {type: argon2.argon2id}))"`

ثم أدخل الـ hash في جدول `app_users` باستخدام SQL آمن. لا تضع PIN أو hash في المستودع.

## حدود هذه النسخة

- هذه ليست نسخة منشورة ولا تم ربطها تلقائيًا بواجهة V28.
- لا توجد بيانات مستخدمين أو مفاتيح أو أسرار مضمنة.
- يجب إضافة CSRF protection عند فصل الواجهة عن نطاق API، واختبار سياسة CORS وsecure cookies على نطاق الإنتاج.
- يجب إكمال التحقق من ملكية customer/contract عند إنشاء الدفعات، وربط payment_allocations عند دعم دفعات متعددة العقود.
- يجب إضافة ترقيم صفحات، صلاحيات تفصيلية، إدارة مستخدمين، ترحيل بيانات legacy، اختبارات آلية ومراقبة.
- الـ webhook يرسل بيانات وصفية محدودة فقط ويوقع الجسم بـ HMAC-SHA256. لا يرسل أسماء العملاء أو أرقامهم أو تفاصيل مالية.
- لا تنفذ `schema.sql` على قاعدة بيانات الإنتاج الحالية قبل نسخة احتياطية ومراجعة migration plan.

راجع `docs/FRONTEND-INTEGRATION.md` قبل ربط واجهة V28.
