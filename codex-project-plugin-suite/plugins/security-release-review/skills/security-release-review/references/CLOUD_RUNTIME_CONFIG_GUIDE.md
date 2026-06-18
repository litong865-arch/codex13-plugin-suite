# Cloud Runtime Config Guide

V4 只能检查仓库可见配置；生产云配置仍需导出或人工确认。

必须检查：

- S3/R2/OSS bucket public access。
- Supabase/Postgres RLS。
- Firebase/Firestore rules。
- Vercel/Netlify/Cloudflare env 变量名和公开前缀。
- Nginx/CDN CORS 和安全响应头。
- 生产 source map 是否公开。
- 生产 debug 是否开启。

建议把导出的配置放进 staging 审计目录后再跑 V4。
