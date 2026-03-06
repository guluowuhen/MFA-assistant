# MFA助手

## 目录结构

- `manifest.json`：Chrome 扩展清单
- `content/`：内容脚本与样式
- `popup/`：点击插件图标展示的 MFA 快捷面板
- `manage/`：批量配置页面（由 popup 打开新页签）

## 安装方式

1. 打开 Chrome，访问 `chrome://extensions/`
2. 开启“开发者模式”
3. 点击“加载已解压的扩展程序”
4. 选择当前项目根目录（本仓库目录）

## 当前交互

1. 点击插件图标：显示已绑定 MFA 列表，可直接复制验证码
2. 点击 popup 右上角“配置”：打开新页签进入批量配置
3. 批量配置页支持上传多个二维码自动解析，默认提取系统名，可手改后批量保存

## 本地存储

- 域名绑定：`chrome.storage.local` 的 `mfaSystems`
- MFA 密钥覆盖：`chrome.storage.local` 的 `mfaSecretOverrides`
