# QR-toolbox: Workers + Static Assets 密码登录版本

目录：
- worker.js：服务端登录页、密码验证、HttpOnly Cookie、图片代理及资源入口
- wrangler.jsonc：Workers 构建配置
- public/index.html：保留原始 QR 工具，新增退出按钮、使用本站图片代理

## 部署
1. 解压后，将本目录内容放到 GitHub 仓库根目录，不要套一层 QR-toolbox 目录。
2. 移除旧的 functions/、其他 wrangler.toml/wrangler.json、旧的根目录 index.html，避免混用。
3. Cloudflare 配置：Build command 留空；Deploy command 为 npx wrangler deploy；Root directory 为 /。
4. 保留现有自定义域名 qr.allez.cc.cd。项目名必须与配置 name 一致（本例 qr-toolbox）。
5. 在此 Worker 设置两个 Secret：ACCESS_PASSWORD 和 TOKEN_SECRET（至少 32 随机字节，例如 openssl rand -hex 32）。无默认密码。
6. 提交到 main，确认新的部署成功，然后刷新页面。

也可在此目录执行：npx wrangler deploy
不要使用 wrangler pages deploy；本项目是 Workers，不是 Pages。

## 行为
未登录：主页只返回登录窗口，不返回工具 HTML。接口和图片代理也会校验 Cookie。
登录：记住设备为 7 天；不勾选为会话 Cookie，服务端最长 8 小时。
不使用 localStorage 或 sessionStorage 保存认证，不需要配置 AUTH_API。
Cookie 为 HttpOnly/Secure/SameSite=Strict；必须 HTTPS 访问线上站点。
退出会删除本浏览器 Cookie，但不是服务端撤销已复制令牌。修改密码或 TOKEN_SECRET 会使旧令牌失效。
令牌到期后刷新页面重新登录；当前已打开的页面不会自动关闭。
原有字体/CDN及第三方图片代理回退仍保留，因此并非完全离线或完全无第三方请求。
未加入登录限速；公网使用建议为 /api/login 配置 Cloudflare 限速规则。
此版本未部署到你的账号，需实际验证浏览器及部署结果。

## 验证
curl -i https://qr.allez.cc.cd/api/verify
未登录应返回 401 和 {"ok":false}。
打开主页，输入 ACCESS_PASSWORD 的实际值登录，检查 QR 功能与退出。
